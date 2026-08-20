# tests/usecases/test_apply.py
"""Execution depth tests that no EXEC-* frame row pins; the breadth
lives in the frame catalogue (tests/specs/frames.py)."""
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.actions import (Action, ActionList, AttachNic,
                                      CreateRule, CreateSg)
from hcs_sg_iac.model.cloud import CloudNic
from hcs_sg_iac.model.entities import (DesiredState, Group, Member, Rule,
                                       RulesFile)
from hcs_sg_iac.model.errors import CloudError
from hcs_sg_iac.model.remote import RemoteCidr
from hcs_sg_iac.usecases.apply import execute
from tests.helpers import plan_state


def test_audit_receives_one_record_per_apply():
    """EXEC-02's expect_audit pins the record content (created names +
    per-action keys); unique here: exactly ONE record per execute call —
    a per-action audit bug would still satisfy the frame row."""
    gw = FakeGateway()
    seen = []
    al = ActionList(actions=(Action("+", "group", "a", "", None, CreateSg("d")),),
                    unmanaged=(), overlap=())
    execute(al, sg_writer=gw, rule_writer=None, binder=None,
            audit=seen.append)
    assert len(seen) == 1 and "actions" in seen[0]


def test_throttled_then_resume_completes_only_the_remainder():
    """§3 resume depth. EXEC-06 pins the per-phase statuses and final
    convergence; unique here: the mid-state cloud layout after the
    throttled phase and the exact remainder the fresh plan contains."""
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    state = DesiredState(
        groups={"alpha": Group("alpha", "a", (Member("10.0.1.10"),)),
                "beta": Group("beta", "b", ())},
        rules={"alpha": RulesFile("alpha",
                                  (Rule("ingress", "tcp", "22",
                                        RemoteCidr("203.0.113.0/24")),),
                                  (), True, False),
               "beta": RulesFile("beta",
                                 (Rule("ingress", "tcp", "443",
                                       RemoteCidr("203.0.113.0/24")),),
                                 (), True, False)})

    gw.budget = 3
    results = execute(plan_state(gw, state), sg_writer=gw, rule_writer=gw,
                      binder=gw)
    assert [r.status for r in results] == \
        ["ok", "ok", "ok", "throttled", "throttled"]
    # partial cloud state: both SGs landed, only alpha's rule, no members
    by_name = {sg.name: sg for sg in gw.list_security_groups()}
    assert sorted(by_name) == ["alpha", "beta"]
    assert len(gw.list_rules(by_name["alpha"].id)) == 1
    assert gw.list_rules(by_name["beta"].id) == []
    assert gw.list_attached_nics(by_name["alpha"].id) == []

    gw.budget = None                              # new window: resume
    al2 = plan_state(gw, state)
    assert sorted((a.group, a.type) for a in al2.actions) == \
        [("alpha", "member"), ("beta", "rule")]
    results2 = execute(al2, sg_writer=gw, rule_writer=gw, binder=gw)
    assert all(r.status == "ok" for r in results2), [r.error for r in results2]
    assert plan_state(gw, state).actions == ()


def test_dependents_of_failed_group_create_are_skipped_not_orphaned():
    """EXEC-05 pins the three failed statuses and sg_missing; unique
    here: the dependents' skip literals and the zero-orphan write log."""
    class ExplodingCreate(FakeGateway):
        def create_security_group(self, name, description):
            if name == "boom":
                raise CloudError("provision failed")
            return super().create_security_group(name, description)

    gw = ExplodingCreate()
    al = ActionList(actions=(
        Action("+", "group", "boom", "", None, CreateSg("d")),
        Action("+", "rule", "boom", "ingress tcp 22 from cidr:203.0.113.0/24",
               None, CreateRule(sg_id="",
                                rule=Rule("ingress", "tcp", "22",
                                          RemoteCidr("203.0.113.0/24")))),
        Action("+", "member", "boom", "ip 10.0.1.10", "p1",
               AttachNic(sg_id="", port_id="p1")),
    ), unmanaged=(), overlap=())
    results = execute(al, sg_writer=gw, rule_writer=gw, binder=gw)
    assert [r.status for r in results] == ["failed", "failed", "failed"]
    assert "provision failed" in results[0].error
    assert results[1].error == "group creation failed — skipping dependent"
    assert results[2].error == "group creation failed — skipping dependent"
    # nothing was written for the missing group: no orphan rules/attachments
    assert gw.list_security_groups() == []
    assert gw.call_log == []
