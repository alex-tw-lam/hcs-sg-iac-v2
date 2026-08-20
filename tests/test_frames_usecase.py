# tests/test_frames_usecase.py
"""Tier-2 consumer: interprets tier-2 Frame rows (tests/specs/frames.py)
against load/validate/resolve/plan/execute/render (FakeGateway) plus the
pure adapter helpers (rate limiter, SDK rule translation)."""

import json
from types import SimpleNamespace

import pytest
from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.adapters.huawei_gateway import HuaweiGateway
from hcs_sg_iac.adapters.ratelimit import FixedWindowLimiter
from hcs_sg_iac.cli import render
from hcs_sg_iac.model.entities import Rule
from hcs_sg_iac.model.quota import QuotaPlan
from hcs_sg_iac.model.remote import RemoteGroup
from hcs_sg_iac.usecases import apply as apply_uc
from hcs_sg_iac.usecases import importer as import_uc
from hcs_sg_iac.usecases import pipeline
from hcs_sg_iac.usecases import resolve as resolve_uc
from hcs_sg_iac.usecases import validate as validate_uc

from tests.specs.builders import (
    check_cloud,
    make_project,
    remote_from_tag,
    seed_gateway,
)
from tests.specs.frames import TIER2


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _plan(gw, root):
    al, errors = pipeline.plan_project(yaml_config.load_project, gw, root)
    assert al is not None, errors
    return al


def _execute(gw, al, audit=None):
    return apply_uc.execute(
        al, sg_writer=gw, rule_writer=gw, binder=gw, audit=audit
    )


def _check_plan(frame, al):
    if frame.expect_actions is not None:
        assert len(al.actions) == len(frame.expect_actions), (
            frame.id,
            [(a.sign, a.type, a.group, a.detail) for a in al.actions],
        )
        for action, want in zip(al.actions, frame.expect_actions, strict=True):
            assert (action.sign, action.type, action.group) == want[:3], (
                frame.id,
                want,
                action.detail,
            )
            if len(want) == 4:
                assert want[3] in action.detail, (
                    frame.id,
                    want,
                    action.detail,
                )
    if frame.expect_unmanaged is not None:
        assert al.unmanaged == frame.expect_unmanaged, frame.id
    if frame.expect_clears is not None:
        assert al.clears == frame.expect_clears, frame.id


@pytest.mark.parametrize("frame", TIER2, ids=lambda f: f.id)
def test_frame(frame, tmp_path):
    root = make_project(tmp_path, frame.files)
    gw = seed_gateway(frame.cloud)
    usecase = frame.usecase

    if usecase == "load":
        state, report = yaml_config.load_project(root)
        if frame.expect_ok:
            assert report.ok, report.errors
            if frame.expect_value is not None:
                assert sorted(state.groups) == frame.expect_value["groups"]
                assert sorted(state.rules) == frame.expect_value["rules"]
        else:
            assert state is None, frame.id
            for sub in frame.expect_error_contains:
                assert any(sub in e for e in report.errors), (frame.id, sub)
        for sub in frame.expect_warn:
            assert any(sub in w for w in report.warnings), (frame.id, sub)

    elif usecase == "validate":
        state, report = yaml_config.load_project(root)
        errors = list(report.errors)
        if state is not None:
            errors += validate_uc.validate_state(state).errors
        if frame.expect_ok:
            assert not errors, (frame.id, errors)
        else:
            for sub in frame.expect_error_contains:
                assert any(sub in e for e in errors), (frame.id, sub, errors)

    elif usecase == "resolve":
        state, _ = yaml_config.load_project(root)
        res = resolve_uc.resolve_memberships(gw, state)
        if frame.expect_ok:
            assert res.report.ok, (frame.id, res.report.errors)
        else:
            assert not res.report.ok, frame.id
            for sub in frame.expect_error_contains:
                assert any(sub in e for e in res.report.errors), (
                    frame.id,
                    sub,
                )
        for ip, port_id in frame.expect_nics or ():
            assert res.nics[ip].port_id == port_id, (frame.id, ip)
        if frame.expect_overlaps is not None:
            assert res.overlaps == frame.expect_overlaps, frame.id

    elif usecase == "plan":
        al, errors = pipeline.plan_project(yaml_config.load_project, gw, root)
        if frame.expect_ok is False:
            assert al is None, frame.id
            for sub in frame.expect_error_contains:
                assert any(sub in e for e in errors), (frame.id, sub, errors)
            return
        assert al is not None, (frame.id, errors)
        _check_plan(frame, al)

    elif usecase == "destroy":
        al = pipeline.plan_destroy_project(gw, frame.model_input)
        results = _execute(gw, al)
        assert all(r.status == "ok" for r in results), frame.id
        _check_plan(frame, al)
        if frame.expect_call_log is not None:
            assert gw.call_log == frame.expect_call_log, (
                frame.id,
                gw.call_log,
            )

    elif usecase in ("execute", "execute_resume"):
        if usecase == "execute":
            phases = [{"budget": (frame.cloud or {}).get("budget")}]
        else:
            phases = frame.model_input["phases"]
        statuses = []
        records = []  # audit sink, when the row wants it
        for i, phase in enumerate(phases):
            gw.budget = phase.get("budget")
            results = _execute(
                gw,
                _plan(gw, root),
                audit=(
                    records.append
                    if (i == 0 and frame.expect_audit is not None)
                    else None
                ),
            )
            statuses.append(tuple(r.status for r in results))
        if frame.expect_phases is not None:
            assert tuple(statuses) == frame.expect_phases, (frame.id, statuses)
        elif frame.expect_results is not None:
            assert statuses[-1] == frame.expect_results, (frame.id, statuses)
        if frame.expect_audit is not None:
            assert records, frame.id
            assert set(records[-1]["created"]) == set(
                frame.expect_audit
            ), frame.id
            for r in records[-1]["actions"]:
                assert {
                    "group",
                    "type",
                    "cloud_id",
                    "detail",
                    "status",
                } <= set(r), frame.id
        if usecase == "execute_resume":
            assert _plan(gw, root).actions == (), frame.id  # converged
        if frame.expect_call_log is not None:
            assert gw.call_log == frame.expect_call_log, (
                frame.id,
                gw.call_log,
            )

    elif usecase == "import":
        imp = import_uc.import_snapshot(gw.inventory().snapshot)
        want = frame.expect_value or {}
        assert sorted(imp.groups) == want["groups"], frame.id
        for gname, ips in want.get("members", {}).items():
            assert tuple(m.ip for m in imp.groups[gname].members) == ips, (
                frame.id,
                gname,
            )
        for gname, rows in want.get("rules", {}).items():
            rf = imp.rules[gname]

            def sig(r):
                remote = (
                    ("group", r.remote.name)
                    if isinstance(r.remote, RemoteGroup)
                    else ("cidr", r.remote.cidr)
                )
                return (r.direction, r.protocol, r.ports, remote)

            got = [sig(r) for r in rf.ingress] + [sig(r) for r in rf.egress]
            assert got == [tuple(x) for x in rows], (frame.id, gname, got)
            assert rf.ingress_managed and rf.egress_managed, frame.id
        notes = list(imp.notes)
        for sub in want.get("notes", ()):
            assert any(sub in n for n in notes), (frame.id, sub, notes)

    elif usecase in ("render_plan", "render_exec", "render_json"):
        al = _plan(gw, root)
        q = (frame.model_input or {}).get("quota")
        quota = QuotaPlan(**q) if q else None
        if usecase == "render_plan":
            out = render.render_plan(al, quota=quota, dry_run=True)
        elif usecase == "render_exec":
            out = render.render_plan(
                al, quota=quota, executed=_execute(gw, al), dry_run=False
            )
        else:
            out = render.render_json(al, quota=quota)
            data = json.loads(out)
            for key, want in (frame.expect_json or {}).items():
                assert data[key] == want, (frame.id, key)
            return
        for sub in frame.expect_out:
            assert sub in out, (frame.id, sub)
        for sub in frame.expect_out_absent:
            assert sub not in out, (frame.id, sub)

    elif usecase == "fake":
        for op in frame.model_input:
            if op[0] == "create_sg":
                gw.create_security_group(op[1], op[2])
            elif op[0] == "update_sg":
                gw.update_security_group_description(op[1], op[2])
            elif op[0] == "delete_sg":
                gw.delete_security_group(op[1])
            elif op[0] == "create_rule":
                gw.create_rule(
                    op[1], Rule(op[2], op[3], op[4], remote_from_tag(op[5]))
                )
            else:
                pytest.fail(f"{frame.id}: unknown fake op {op!r}")
        if frame.expect_call_log is not None:
            assert gw.call_log == frame.expect_call_log, (
                frame.id,
                gw.call_log,
            )

    elif usecase == "ratelimit":
        spec = frame.model_input
        clock = _Clock()
        lim = FixedWindowLimiter(
            budget=spec["budget"], window_seconds=spec["window"], clock=clock
        )
        got = []
        for op in spec["ops"]:
            if op[0] == "acquire":
                got.append(lim.try_acquire())
            elif op[0] == "advance":
                clock.now += op[1]
            elif op[0] == "throttle":
                lim.report_external_throttle()
            else:
                pytest.fail(f"{frame.id}: unknown ratelimit op {op!r}")
        assert got == frame.expect_value, frame.id

    elif usecase == "translate_rule":
        spec = frame.model_input
        wire = SimpleNamespace(
            id=spec["id"],
            security_group_id=spec["sg"],
            direction=spec["direction"],
            protocol=spec.get("protocol"),
            port_range_min=spec.get("min"),
            port_range_max=spec.get("max"),
            remote_group_id=spec.get("rgid"),
            remote_ip_prefix=spec.get("prefix"),
        )
        cr = HuaweiGateway.__new__(HuaweiGateway)._to_cloud_rule(wire)
        for key, want in frame.expect_value.items():
            assert getattr(cr, key) == want, (frame.id, key)

    else:
        pytest.fail(f"{frame.id}: unknown usecase {usecase!r}")

    check_cloud(gw, frame.expect_cloud)
