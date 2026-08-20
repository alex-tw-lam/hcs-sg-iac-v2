# tests/usecases/test_pipeline.py
"""The orchestration seam, directly: an injected loader + FakeGateway,
confirmation hook and audit sink. The CLI is one consumer; these tests
pin the pipeline's contract for future presentation layers."""

import time

from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.actions import Action, ActionList, CreateSg
from hcs_sg_iac.model.cloud import CloudNic, CloudSg
from hcs_sg_iac.model.entities import DesiredState, Group, Member
from hcs_sg_iac.model.errors import CloudError, QuotaExhausted
from hcs_sg_iac.model.report import Report
from hcs_sg_iac.usecases import pipeline

from tests.helpers import ExhaustOnce


class ExhaustReadsOnce(FakeGateway):
    """inventory() (the read fast path every gateway with it takes)
    raises QuotaExhausted carrying a retry deadline on the FIRST call,
    then behaves normally — the read path's wait-and-continue shape."""

    def __init__(self, delay: float = 60.0):
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


def _state():
    return DesiredState(
        groups={"web": Group("web", "d", (Member("10.0.1.10"),))}, rules={}
    )


def _loader(state=None, errors=()):
    def load(project):
        return state, Report(errors=list(errors))

    return load


def _planned(gw):
    al, errors = pipeline.plan_project(_loader(_state()), gw, "unused")
    assert al is not None, errors
    return al


def test_plan_project_loads_validates_resolves_and_plans():
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    al, errors = pipeline.plan_project(_loader(_state()), gw, "unused")
    assert errors == []
    assert [(a.sign, a.type) for a in al.actions] == [
        ("+", "group"),
        ("+", "member"),
    ]


def test_plan_project_collects_failures_from_every_stage():
    # load failure
    al, errors = pipeline.plan_project(
        _loader(None, ["bad yaml"]), FakeGateway(), "unused"
    )
    assert al is None and errors == ["bad yaml"]
    # resolve failure: member ip matches no NIC
    al, errors = pipeline.plan_project(
        _loader(_state()), FakeGateway(), "unused"
    )
    assert al is None and any("no NIC found" in e for e in errors)
    # plan-engine failure: duplicate cloud SG names surface as error lines
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    gw.add_sg(CloudSg(id="sg-a", name="web"))
    gw.add_sg(CloudSg(id="sg-b", name="web"))
    al, errors = pipeline.plan_project(_loader(_state()), gw, "unused")
    assert al is None and errors[0].startswith("error: duplicate")


def test_execute_confirmed_declined_by_hook_writes_nothing():
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    al = _planned(gw)
    audits = []
    results = pipeline.execute_confirmed(
        gw,
        al,
        prompt="Apply the changes above",
        expect="yes",
        confirm=lambda prompt, expect: False,
        audit=lambda: audits.append(1),
    )
    assert results is None
    assert gw.call_log == []  # declined before any write
    assert audits == []  # sink factory never invoked


def test_execute_confirmed_prompts_then_runs_and_audits():
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    al = _planned(gw)
    seen = {}

    def confirm(prompt, expect):
        seen["prompt"], seen["expect"] = prompt, expect
        return True

    records = []
    results = pipeline.execute_confirmed(
        gw,
        al,
        prompt="Apply the changes above",
        expect="yes",
        confirm=confirm,
        audit=lambda: records.append,
    )
    assert seen == {"prompt": "Apply the changes above", "expect": "yes"}
    assert [r.status for r in results] == ["ok", "ok"]
    assert len(records) == 1  # one audit record after the run


def test_plan_project_waits_out_the_window_on_reads():
    """The READ side (snapshot/resolution) shares apply's
    wait-and-continue: one exhaustion mid-snapshot waits via the sleep
    hook and the whole read re-runs to a successful plan. Without the
    hook it degrades to a clean error line, not an exception."""
    gw = ExhaustReadsOnce()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    slept, notes = [], []
    al, errors = pipeline.plan_project(
        _loader(_state()),
        gw,
        "unused",
        sleep=slept.append,
        notify=notes.append,
    )
    assert al is not None, errors
    assert [(a.sign, a.type) for a in al.actions] == [
        ("+", "group"),
        ("+", "member"),
    ]
    assert len(slept) == 1 and 55 <= slept[0] <= 65
    assert notes and "planning reads" in notes[0]
    gw2 = ExhaustReadsOnce()
    gw2.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    al2, errors2 = pipeline.plan_project(_loader(_state()), gw2, "unused")
    assert al2 is None
    assert errors2 == ["error: budget exhausted for this window"]


def test_plan_project_cloud_error_is_a_clean_error_line():
    class Broken(FakeGateway):
        def inventory(self):  # the read path the CLI takes
            raise CloudError("VPC.0404 not found")

    empty_members = DesiredState(
        groups={"web": Group("web", "d", ())}, rules={}
    )
    al, errors = pipeline.plan_project(
        _loader(empty_members), Broken(), "unused"
    )
    assert al is None and errors == ["error: VPC.0404 not found"]


def test_execute_confirmed_forwards_the_wait_hooks():
    """apply's wait-and-continue only engages when the presentation
    forwards sleep/notify; unique here: the plumbing (exhaustion is
    retried to ok through execute_confirmed, audit still fires)."""
    slept, notes, audits = [], [], []
    al = ActionList(
        actions=(Action("+", "group", "a", "", None, CreateSg("d")),),
        unmanaged=(),
        overlap=(),
    )
    results = pipeline.execute_confirmed(
        ExhaustOnce(delay=60),
        al,
        prompt="Apply the changes above",
        expect="yes",
        confirm=lambda p, e: True,
        audit=lambda: audits.append,
        sleep=slept.append,
        notify=notes.append,
    )
    assert [r.status for r in results] == ["ok"]
    assert len(slept) == 1 and 55 <= slept[0] <= 65
    assert notes and len(audits) == 1
