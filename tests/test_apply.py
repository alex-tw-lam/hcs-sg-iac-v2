# tests/test_apply.py
"""The executor: throttle semantics, wait-and-continue (write AND read
side), mid-failure isolation, dependent skipping, ordering."""

import time

from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.common import CloudError, CloudThrottled, QuotaExhausted
from hcs_sg_iac.usecases import pipeline
from hcs_sg_iac.usecases.apply import execute

from tests.conftest import (
    GROUP_YAML,
    INGRESS_YAML,
    ExhaustOnce,
    make_project,
    plan_state,
    seed,
)


def _project(tmp_path, files=None):
    files = {
        "security-groups/web/group.yaml": GROUP_YAML,
        "security-groups/web/ingress.yaml": INGRESS_YAML,
        "security-groups/web/egress.yaml": "[]\n",
        **(files or {}),
    }
    return make_project(tmp_path, files)


def _state(root):
    from hcs_sg_iac.adapters import yaml_config

    state, report = yaml_config.load_project(root)
    assert state is not None, report.errors
    return state


def test_wait_and_continue_write_side(tmp_path):
    """Exhaustion with a retry deadline: the executor sleeps once, then
    finishes — the whole point of wait-and-continue."""
    gw = seed(ExhaustOnce(delay=30.0))
    slept = []
    al = plan_state(gw, _state(_project(tmp_path)))
    results = execute(
        al, gateway=gw, sleep=slept.append, notify=lambda m: None
    )
    assert all(r.status == "ok" for r in results)
    assert len(slept) == 1 and 0 < slept[0] <= 30.0


class ExhaustReadsOnce(FakeGateway):
    """inventory() raises QuotaExhausted (with deadline) on the first
    call, then behaves — the READ side's wait-and-continue shape."""

    def __init__(self, delay=60.0):
        super().__init__()
        self._deadline = time.time() + delay
        self.raised = False

    def inventory(self):
        if not self.raised:
            self.raised = True
            raise QuotaExhausted(
                "budget exhausted for this window", retry_at=self._deadline
            )
        return super().inventory()


def test_wait_and_continue_read_side(tmp_path):
    root = _project(tmp_path)
    gw = seed(ExhaustReadsOnce(delay=30.0))
    slept = []
    from hcs_sg_iac.adapters import yaml_config

    al, errors = pipeline.plan_project(
        yaml_config.load_project,
        gw,
        root,
        sleep=slept.append,
        notify=lambda m: None,
    )
    assert al is not None, errors
    assert len(slept) == 1


def test_throttle_then_resume_completes_remainder(tmp_path):
    root = _project(tmp_path)
    gw = seed(FakeGateway())
    gw.budget = 1
    al = plan_state(gw, _state(root))
    first = execute(al, gateway=gw)
    assert any(r.status == "throttled" for r in first)
    gw.budget = 25  # a new window
    al2 = plan_state(gw, _state(root))
    second = execute(al2, gateway=gw)
    assert all(r.status == "ok" for r in second)
    assert plan_state(gw, _state(root)).actions == ()  # converged


def test_mid_failure_isolates_and_skips_dependents(tmp_path):
    root = _project(tmp_path)

    class HalfBroken(FakeGateway):
        def create_security_group(self, name, description):
            raise CloudError("create failed")

    gw = seed(HalfBroken())
    al = plan_state(gw, _state(root))
    results = execute(al, gateway=gw)
    statuses = [r.status for r in results]
    assert statuses[0] == "failed"  # the create
    assert all(s == "failed" for s in statuses[1:])  # dependents skipped


def test_throttle_is_not_a_hard_error(tmp_path):
    """CloudThrottled on one action must not abort the loop."""

    class ThrottleFirst(FakeGateway):
        def __init__(self):
            super().__init__()
            self.raised = False

        def create_security_group(self, name, description):
            if not self.raised:
                self.raised = True
                raise CloudThrottled("cloud throttled", retry_at=time.time())
            return super().create_security_group(name, description)

    gw = seed(ThrottleFirst())
    al = plan_state(gw, _state(_project(tmp_path)))
    results = execute(
        al, gateway=gw, sleep=lambda s: None, notify=lambda m: None
    )
    assert all(r.status == "ok" for r in results)


def test_remote_group_created_before_its_rule(tmp_path):
    """A rule referencing another group by name: apply's ordering must
    create the referenced SG before the rule."""
    files = {
        "security-groups/web/group.yaml": GROUP_YAML,
        "security-groups/web/ingress.yaml": "- {source: db, protocol: tcp, ports: '5432'}\n",
        "security-groups/db/group.yaml": "name: db\nmembers: []\n",
    }
    root = make_project(tmp_path, files)
    gw = seed(FakeGateway())
    results = execute(plan_state(gw, _state(root)), gateway=gw)
    assert all(r.status == "ok" for r in results)
    # web's rule (id-0002) references db by NAME; db (id-0001) must be
    # created before the rule that resolves it
    assert gw.call_log.index("create_sg:db") < gw.call_log.index(
        "create_rule:id-0002"
    )


def test_execute_updates_description_and_deletes_extra_rule(tmp_path):
    """The write-side branches no scenario reached: UpdateSg (description
    drift) and DeleteRule (cloud has extra) execute and converge."""
    root = _project(tmp_path)  # code: desc 'web', ingress 22/203.0.113.0/24
    from hcs_sg_iac.adapters.fake_gateway import FakeGateway

    from tests.conftest import cloud_rule
    from tests.conftest import seed as _s

    sg = ("sg-web", "web", "OLD-DESC")
    extra = cloud_rule(id="r-extra", sg_id="sg-web", ports="8080")
    keep = cloud_rule(id="r-keep")
    gw = _s(
        FakeGateway(),
        sgs=(sg,),
        rules=(keep, extra),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-web", "p1"),),
    )
    al = plan_state(gw, _state(root))
    signs = {(a.sign, a.type) for a in al.actions}
    assert ("~", "group") in signs and ("-", "rule") in signs
    results = execute(al, gateway=gw)
    assert all(r.status == "ok" for r in results)
    cloud_sg = next(s for s in gw.list_security_groups() if s.name == "web")
    assert cloud_sg.description == "web"  # UpdateSg executed
    remaining = gw.list_rules(cloud_sg.id)
    assert [r.id for r in remaining] == ["r-keep"]  # DeleteRule executed
