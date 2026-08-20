# tests/test_frames_model.py
"""Tier-1 consumer: interprets tier-1 Frame rows (tests/specs/frames.py)
against the model constructors. One dispatch table, no per-frame code."""

import pytest
from hcs_sg_iac.model import entities
from hcs_sg_iac.model.actions import (
    Action,
    ActionList,
    AttachNic,
    CreateRule,
    CreateSg,
    DeleteRule,
    DeleteSg,
    DetachNic,
    UpdateSg,
)
from hcs_sg_iac.model.portset import PortError, parse_ports
from hcs_sg_iac.model.remote import parse_remote
from hcs_sg_iac.model.report import Report

from tests.specs.builders import remote_from_tag
from tests.specs.frames import TIER1

_PAYLOADS = {
    "AttachNic": AttachNic,
    "CreateRule": CreateRule,
    "CreateSg": CreateSg,
    "DeleteRule": DeleteRule,
    "DeleteSg": DeleteSg,
    "DetachNic": DetachNic,
    "UpdateSg": UpdateSg,
}


def _check_group(g: entities.Group, want: tuple):
    name, desc, ips = want
    assert g == entities.Group(
        name, desc, tuple(entities.Member(ip=i) for i in ips)
    )


def _check_rules_file(rf: entities.RulesFile, want: dict):
    rule0 = want.get("rule0")
    if rule0 is not None:
        r0 = (rf.ingress + rf.egress)[0]
        assert (r0.direction, r0.protocol, r0.ports) == rule0[:3]
        assert r0.remote == remote_from_tag(rule0[3])
    assert rf.security_group == want["sg"]
    assert rf.ingress_managed is want["ingress_managed"]
    assert rf.egress_managed is want["egress_managed"]
    assert len(rf.ingress) == want["ingress"]
    assert len(rf.egress) == want["egress"]


@pytest.mark.parametrize("frame", TIER1, ids=lambda f: f.id)
def test_frame(frame):
    call, raw = frame.model_call, frame.model_input
    if call in ("parse_group", "parse_rules_file"):
        # "parse_rules_file" rows keep their OLD document shape
        # ({ingress?, egress?}) — the flat layout died in v0.6.0, so the
        # consumer translates each section to the REAL per-direction
        # parser (parse_rule_list). Same semantics, live code path.
        report = Report()
        if call == "parse_group":
            obj = entities.parse_group(raw, "where", report)
        else:
            ingress = egress = ()
            ing_managed = eg_managed = False
            if "ingress" in raw:
                ingress = entities.parse_rule_list(
                    raw["ingress"], "where", report, "ingress", "source"
                )
                ing_managed = True
            if "egress" in raw:
                egress = entities.parse_rule_list(
                    raw["egress"], "where", report, "egress", "destination"
                )
                eg_managed = True
            obj = (
                entities.RulesFile(
                    security_group=str(raw.get("security_group", "")),
                    ingress=ingress,
                    egress=egress,
                    ingress_managed=ing_managed,
                    egress_managed=eg_managed,
                )
                if report.ok
                else None
            )
        if frame.expect_ok:
            assert report.ok, report.errors
            assert obj is not None
            if frame.expect_value is not None:
                (_check_group if call == "parse_group" else _check_rules_file)(
                    obj, frame.expect_value
                )
        else:
            assert not report.ok, report.errors
            assert obj is None
        for sub in frame.expect_error_contains:
            assert any(sub in e for e in report.errors), (
                frame.id,
                sub,
                report.errors,
            )
    elif call == "parse_ports":
        if frame.expect_ok:
            assert parse_ports(raw) == frame.expect_value, frame.id
        else:
            with pytest.raises(PortError) as ei:
                parse_ports(raw)
            for sub in frame.expect_error_contains:
                assert sub in str(ei.value), frame.id
    elif call == "parse_remote":
        if frame.expect_ok:
            assert parse_remote(raw) == remote_from_tag(
                frame.expect_value
            ), frame.id
        else:
            with pytest.raises(ValueError) as ei:
                parse_remote(raw)
            for sub in frame.expect_error_contains:
                assert sub in str(ei.value), frame.id
    elif call == "actionlist_summary":
        actions = tuple(
            Action(
                sign,
                type_,
                group,
                detail,
                cloud_id,
                _PAYLOADS[op[0]](*op[1:]) if op else None,
            )
            for sign, type_, group, detail, cloud_id, op in raw["actions"]
        )
        al = ActionList(
            actions=actions,
            unmanaged=tuple(raw.get("unmanaged", ())),
            overlap=tuple(raw.get("overlap", ())),
        )
        assert al.summary() == frame.expect_value, frame.id
    elif call == "desired_state":
        state = entities.DesiredState(
            groups={n: entities.Group(n, "", ()) for n in raw["groups"]},
            rules={
                n: entities.RulesFile(n, (), (), True, True)
                for n in raw.get("rules", [])
            },
        )
        assert set(state.groups) == set(raw["groups"])
        assert set(state.rules) == set(raw.get("rules", []))
    else:
        pytest.fail(f"{frame.id}: unknown model_call {call!r}")
