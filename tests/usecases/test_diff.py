# tests/usecases/test_diff.py
"""Plan-engine depth tests that no PLAN-*/DSTR-* frame row pins; the
breadth lives in the frame catalogue (tests/specs/frames.py)."""

import pytest
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.cloud import CloudRule, CloudSg
from hcs_sg_iac.model.entities import DesiredState, Group, Rule, RulesFile
from hcs_sg_iac.model.remote import RemoteCidr, RemoteGroup
from hcs_sg_iac.usecases.plan import plan_destroy, read_snapshot

from tests.helpers import plan_state


def _gw_one_sg(name, rules=()):
    gw = FakeGateway()
    gw.add_sg(CloudSg(id=f"sg-{name}", name=name, description="d"))
    for r in rules:
        gw.add_rule(r)
    return gw


def _state_one(name, rules_file):
    return DesiredState(
        groups={name: Group(name, "d", ())},
        rules={name: rules_file} if rules_file else {},
    )


def test_detach_detail_falls_back_to_port_id_when_ip_empty():
    gw = FakeGateway()
    gw.add_sg(CloudSg(id="sg-x", name="x", description=""))
    gw.attach_nic("sg-x", "p9")  # fake gateway auto-adds CloudNic(ip="")
    state = DesiredState(groups={"x": Group("x", "", ())}, rules={})
    al = plan_state(gw, state)
    assert [(a.sign, a.type, a.detail, a.cloud_id) for a in al.actions] == [
        ("-", "member", "ip p9", "p9")
    ]


def test_duplicate_cloud_names_report_every_instance():
    """CLI-20/PLAN depth pin the single-pair error; unique here: a name
    held by THREE SGs plus a second duplicated name — every name and
    EVERY sg id is enumerated, not just the first pair found."""
    gw = FakeGateway()
    for sg_id, name in (
        ("sg-w1", "web"),
        ("sg-w2", "web"),
        ("sg-w3", "web"),
        ("sg-d1", "db"),
        ("sg-d2", "db"),
        ("sg-ok", "fine"),
    ):
        gw.add_sg(CloudSg(id=sg_id, name=name, description="d"))
    state = DesiredState(groups={"fine": Group("fine", "d", ())}, rules={})
    with pytest.raises(ValueError) as ei:
        plan_state(gw, state)
    msg = str(ei.value)
    for token in (
        "'web'",
        "sg-w1",
        "sg-w2",
        "sg-w3",
        "'db'",
        "sg-d1",
        "sg-d2",
    ):
        assert token in msg, token
    assert "fine" not in msg  # the un-duplicated name stays out


def test_cloud_self_rules_are_preserved_across_convergence():
    """HCS auto-adds self-referential rules on SG create (remote_group_id
    = the SG itself). Unique here: they survive a managed non-empty
    direction (only true stale goes), a managed [] direction (nothing
    stripped, no false clear), and a CODED self-reference converges
    against the existing self rule instead of duplicating it."""
    gw = _gw_one_sg(
        "web",
        [
            CloudRule(
                id="self-i",
                sg_id="sg-web",
                direction="ingress",
                protocol=None,
                ports=None,
                remote_group_id="sg-web",
                remote_ip_prefix=None,
            ),
            CloudRule(
                id="stale-i",
                sg_id="sg-web",
                direction="ingress",
                protocol="tcp",
                ports="22",
                remote_group_id=None,
                remote_ip_prefix="0.0.0.0/0",
            ),
            CloudRule(
                id="self-e",
                sg_id="sg-web",
                direction="egress",
                protocol=None,
                ports=None,
                remote_group_id="sg-web",
                remote_ip_prefix=None,
            ),
        ],
    )
    # ingress managed with one wanted rule; egress managed + [] — the
    # self rules in BOTH directions must survive, stale tcp/22 must go
    state = _state_one(
        "web",
        RulesFile(
            "web",
            (Rule("ingress", "tcp", "80", RemoteCidr("0.0.0.0/0")),),
            (),
            True,
            True,
        ),
    )
    al = plan_state(gw, state)
    assert [
        a.detail for a in al.actions if a.sign == "-" and a.type == "rule"
    ] == ["ingress tcp 22 from cidr:0.0.0.0/0"]
    assert al.clears == ()  # egress [] strips nothing: only self rules

    # a coded self-reference matches the cloud's auto self rule
    state2 = _state_one(
        "web",
        RulesFile(
            "web",
            (Rule("ingress", "all", None, RemoteGroup("web")),),
            (),
            True,
            False,
        ),
    )
    al2 = plan_state(gw, state2)
    assert [(a.sign, a.type) for a in al2.actions] == [("-", "rule")]


# ---- clear-all set (ActionList.clears): data, not display parsing ----


def test_clears_names_each_managed_empty_direction_with_cloud_rules():
    """PLAN-13 pins the positive side (managed+empty with a cloud rule is
    named); unique here: the managed NON-empty direction stays out of
    clears even though it also has cloud rules."""
    gw = _gw_one_sg(
        "web",
        [
            CloudRule(
                id="i1",
                sg_id="sg-web",
                direction="ingress",
                protocol="tcp",
                ports="22",
                remote_group_id=None,
                remote_ip_prefix="0.0.0.0/0",
            ),
            CloudRule(
                id="e1",
                sg_id="sg-web",
                direction="egress",
                protocol="tcp",
                ports="80",
                remote_group_id=None,
                remote_ip_prefix="0.0.0.0/0",
            ),
            CloudRule(
                id="e2",
                sg_id="sg-web",
                direction="egress",
                protocol=None,
                ports=None,
                remote_group_id=None,
                remote_ip_prefix="10.0.0.0/8",
            ),
        ],
    )
    state = _state_one(
        "web",
        RulesFile(
            "web",
            (Rule("ingress", "tcp", "22", RemoteCidr("0.0.0.0/0")),),
            (),
            True,
            True,
        ),
    )  # egress managed + code-empty
    al = plan_state(gw, state)
    assert al.clears == ("egress rules of web",)


def test_clears_empty_for_drift_on_non_empty_direction():
    # deletes that are convergence against a NON-empty code list are not
    # a clear-all: only managed+code-empty directions qualify
    gw = _gw_one_sg(
        "web",
        [
            CloudRule(
                id="e1",
                sg_id="sg-web",
                direction="egress",
                protocol="tcp",
                ports="80",
                remote_group_id=None,
                remote_ip_prefix="0.0.0.0/0",
            )
        ],
    )
    state = _state_one(
        "web",
        RulesFile(
            "web",
            (),
            (Rule("egress", "tcp", "443", RemoteCidr("0.0.0.0/0")),),
            True,
            True,
        ),
    )
    al = plan_state(gw, state)
    assert any(a.sign == "-" and a.type == "rule" for a in al.actions)
    assert al.clears == ()


def test_clears_empty_without_rules_file():
    # no rules file: both directions unmanaged -> never a clear-all
    # (PLAN-04 checks unmanaged for this shape but leaves clears unchecked)
    gw = _gw_one_sg(
        "web",
        [
            CloudRule(
                id="e1",
                sg_id="sg-web",
                direction="egress",
                protocol="tcp",
                ports="80",
                remote_group_id=None,
                remote_ip_prefix="0.0.0.0/0",
            )
        ],
    )
    al = plan_state(gw, _state_one("web", None))
    assert al.clears == ()


# ---- plan_destroy ----


def test_plan_destroy_detail_falls_back_to_port_id_when_ip_empty():
    # DSTR-01 pins the detach-then-delete order and the call log; unique
    # here: a NIC with an empty ip falls back to the port id in the detail.
    gw = FakeGateway()
    gw.add_sg(CloudSg(id="sg-y", name="y", description="d"))
    gw.attach_nic("sg-y", "p1")  # fake gateway auto-adds CloudNic(ip="")
    al = plan_destroy("y", read_snapshot(gw, gw))
    assert al.actions[0].detail == "ip p1"
