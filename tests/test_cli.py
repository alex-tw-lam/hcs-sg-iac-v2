# tests/test_cli.py
"""The 17 end-to-end scenarios that are the refactor safety net: argv ->
rc/stdout/stderr against main() with a seeded FakeGateway."""

import json

import pytest
from hcs_sg_iac.cli.main import main
from hcs_sg_iac.model.errors import CloudError

from tests.conftest import INGRESS_YAML, ExhaustOnce, run, seed


def test_validate_ok(project, gw, capsys, monkeypatch):
    rc, out, _ = run(
        ["validate", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "OK: 1 groups" in out and gw.call_log == []


def test_validate_errors_on_stderr(project, gw, capsys, monkeypatch):
    (project / "security-groups" / "web" / "group.yaml").write_text(
        "name: Web\nmembers: []\n"
    )
    rc, out, err = run(
        ["validate", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 1 and out == "" and "must match" in err


def test_plan_is_readonly(project, gw, capsys, monkeypatch):
    rc, out, _ = run(
        ["plan", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "member" in out and "Dry run" in out
    assert gw.call_log == []  # reads are not writes


def test_plan_offline_snapshot(project, capsys, monkeypatch):
    """Offline planning core: no gateway, no credentials, snapshot only."""
    import json as _json

    from tests.conftest import make_project

    snap = {
        "sgs": [{"id": "sg-web", "name": "web", "description": "web"}],
        "rules": {},
        "attached": {},
        "nics_by_ip": {
            "10.0.1.10": [
                {"port_id": "p1", "ip": "10.0.1.10", "vm_name": None}
            ]
        },
    }
    make_project(project, {"snapshot.json": _json.dumps(snap)})
    for var in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    rc, out, _ = run(
        ["plan", "--project", str(project)], None, capsys, monkeypatch
    )
    assert rc == 0 and "Dry run" in out


def test_apply_defaults_to_dry_run(project, gw, capsys, monkeypatch):
    rc, out, _ = run(
        ["apply", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "member" in out and gw.call_log == []


def test_apply_yes_previews_before_writing(project, gw, capsys, monkeypatch):
    rc, out, _ = run(
        ["apply", "--yes", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0
    assert out.index("Plan: 2 to add") < out.index("Apply complete")
    assert any(s.name == "web" for s in gw.list_security_groups())
    assert gw.call_log  # writes happened after the preview


def test_apply_throttled_rc1_resume_hint(project, gw, capsys, monkeypatch):
    gw.budget = 1
    rc, out, _ = run(
        ["apply", "--yes", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 1 and "re-run to resume" in out


def test_apply_json_pure_stdout(project, gw, capsys, monkeypatch):
    rc, out, err = run(
        ["apply", "--yes", "--json", "--project", str(project)],
        gw,
        capsys,
        monkeypatch,
    )
    data = json.loads(out)  # stdout is ONE pure JSON document
    assert rc == 0 and {"summary", "results"} <= set(data)
    assert "Plan:" in err  # the preview went to stderr


def test_apply_partial_failure_rc1(project, capsys, monkeypatch):
    from hcs_sg_iac.adapters.fake_gateway import FakeGateway

    from tests.conftest import seed as _seed

    class Exploding(FakeGateway):
        def create_security_group(self, name, description):
            raise CloudError("boom")

    gw = _seed(Exploding())
    rc, out, _ = run(
        ["apply", "--yes", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 1 and "failed" in out


def test_apply_waits_out_rate_window(project, capsys, monkeypatch):
    """Wait-and-continue: budget exhaustion with a retry deadline sleeps
    once, then completes — one command, unattended."""
    sleeps = []
    gw = seed(ExhaustOnce(delay=30.0))
    rc, out, err = _run_with_sleep(
        ["apply", "--yes", "--project", str(project)],
        gw,
        capsys,
        monkeypatch,
        sleeps,
    )
    assert rc == 0 and "Apply complete" in out
    assert len(sleeps) == 1 and "waiting" in err


def _run_with_sleep(argv, gw, capsys, monkeypatch, sleeps):
    from hcs_sg_iac.cli import main as cli_main

    monkeypatch.setattr(
        "builtins.input", lambda *_: (_ for _ in ()).throw(AssertionError)
    )
    import hcs_sg_iac.cli.main as m

    real_sleep = m.time.sleep

    def fake_sleep(s):
        sleeps.append(s)

    m.time.sleep = fake_sleep
    try:
        rc = cli_main.main(list(argv), gateway=gw)
    finally:
        m.time.sleep = real_sleep
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_destroy_dry_run(project, gw, capsys, monkeypatch):
    from hcs_sg_iac.adapters.fake_gateway import FakeGateway

    from tests.conftest import seed as _seed

    gw = _seed(FakeGateway(), sgs=(("sg-1", "web", "web"),))
    rc, out, _ = run(
        ["destroy", "web", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "delete security group" in out
    assert gw.call_log == []


def test_destroy_yes_detaches_then_deletes(project, gw, capsys, monkeypatch):
    from hcs_sg_iac.adapters.fake_gateway import FakeGateway

    from tests.conftest import seed as _seed

    gw = _seed(
        FakeGateway(),
        sgs=(("sg-1", "web", "web"),),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-1", "p1"),),
    )
    rc, _, _ = run(
        ["destroy", "web", "--yes", "--project", str(project)],
        gw,
        capsys,
        monkeypatch,
    )
    assert rc == 0
    assert gw.call_log.index("detach:p1->sg-1") < gw.call_log.index(
        "delete_sg:sg-1"
    )
    assert not any(s.name == "web" for s in gw.list_security_groups())


def test_snapshot_writes_file(project, gw, capsys, monkeypatch):
    rc, out, _ = run(
        ["snapshot", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "snapshot: " in out
    assert (project / "snapshot.json").exists()


def test_drift_rc1_on_change(project, capsys, monkeypatch):
    import json as _json

    from hcs_sg_iac.adapters.fake_gateway import FakeGateway

    from tests.conftest import seed as _seed

    snap = {
        "sgs": [{"id": "sg-web", "name": "web", "description": ""}],
        "rules": {},
        "attached": {},
        "nics_by_ip": {},
    }
    (project / "snapshot.json").write_text(_json.dumps(snap))
    gw = _seed(FakeGateway())  # cloud now empty -> group deleted
    rc, out, _ = run(
        ["drift", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 1 and "- group web" in out


def test_import_writes_files_with_notes(tmp_path, capsys, monkeypatch):
    from tests.conftest import make_project

    project = make_project(tmp_path, {})
    import json as _json

    snap = {
        "sgs": [{"id": "sg-web", "name": "web", "description": ""}],
        "rules": {
            "sg-web": [
                {
                    "id": "r1",
                    "sg_id": "sg-web",
                    "direction": "ingress",
                    "protocol": "tcp",
                    "ports": "22",
                    "remote_group_id": "sg-web",
                    "remote_ip_prefix": None,
                }
            ]
        },
        "attached": {},
        "nics_by_ip": {},
    }
    (project / "snapshot.json").write_text(_json.dumps(snap))
    rc, out, _ = run(
        ["import", "--project", str(project)], None, capsys, monkeypatch
    )
    assert rc == 0
    assert (project / "security-groups" / "web" / "group.yaml").exists()
    assert (project / "security-groups" / "web" / "ingress.yaml").exists()
    assert "self-referential" in out and "now managed" in out


def test_import_refuses_overwrite(project, capsys, monkeypatch):
    import json as _json

    # the project fixture already manages `web`; importing it again
    # must refuse without --force
    (project / "snapshot.json").write_text(
        _json.dumps(
            {
                "sgs": [{"id": "sg-web", "name": "web", "description": ""}],
                "rules": {},
                "attached": {},
                "nics_by_ip": {},
            }
        )
    )
    rc, _, err = run(
        ["import", "--project", str(project)], None, capsys, monkeypatch
    )
    assert rc == 1 and "refusing to overwrite" in err


def test_plan_yes_rejected(project, gw, capsys, monkeypatch):
    monkeypatch.setattr(
        "builtins.input", lambda *_: pytest.fail("unexpected prompt")
    )
    with pytest.raises(SystemExit) as ei:
        main(["plan", "--yes", "--project", str(project)], gateway=gw)
    err = capsys.readouterr().err
    assert ei.value.code == 2
    assert "read-only" in err and "apply --yes" in err


def test_missing_credentials_names_all_four(project, capsys, monkeypatch):
    from tests.conftest import make_project

    make_project(project, {})  # empty dir: no security-groups/
    for var in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    rc, _, err = run(
        ["plan", "--project", str(project)], None, capsys, monkeypatch
    )
    assert rc == 1
    for name in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        assert name in err


def test_plan_verbose_logs_phases(project, gw, capsys, monkeypatch):
    rc, out, err = run(
        ["plan", "--verbose", "--project", str(project)],
        gw,
        capsys,
        monkeypatch,
    )
    assert rc == 0 and "Dry run" in out
    assert "hcs-sg: phase: reading cloud snapshot" in err
    assert "hcs-sg: gateway call" in err


def test_duplicate_cloud_names_clean_error(project, capsys, monkeypatch):
    from hcs_sg_iac.adapters.fake_gateway import FakeGateway

    from tests.conftest import seed as _seed

    gw = _seed(FakeGateway(), sgs=(("sg-a", "web", ""), ("sg-b", "web", "")))
    rc, _, err = run(
        ["plan", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 1
    assert "duplicate cloud security group name" in err
    assert "sg-a" in err and "sg-b" in err


def test_apply_with_rules_full_flow(project, gw, capsys, monkeypatch):
    from tests.conftest import make_project

    make_project(
        project,
        {
            "security-groups/web/ingress.yaml": INGRESS_YAML,
            "security-groups/web/egress.yaml": "[]\n",
        },
    )
    rc, out, _ = run(
        ["apply", "--yes", "--project", str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "3 ok" in out  # group + rule + member
    rules = gw.list_rules(
        next(s.id for s in gw.list_security_groups() if s.name == "web")
    )
    assert len(rules) == 1 and rules[0].ports == "22"
