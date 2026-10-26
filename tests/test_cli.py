# tests/test_cli.py
"""The end-to-end scenarios that are the refactor safety net: argv ->
rc/stdout/stderr against main() with a seeded FakeGateway."""

import json
import shutil

import pytest
from hcs_sg_iac.cli.main import main
from hcs_sg_iac.contracts import CloudError

from tests.conftest import (
    INGRESS_YAML,
    cloud_rule,
    make_project,
    run,
    seed,
    write_snapshot,
)
from tests.fake_gateway import FakeGateway

P = "--project"


def test_plan_is_readonly(project, gw, capsys, monkeypatch):
    rc, out, _ = run(["plan", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 0 and "member" in out and "Dry run" in out
    assert gw.call_log == []  # reads are not writes


def test_plan_offline_snapshot(project, capsys, monkeypatch):
    """Offline planning core: no gateway, no credentials, snapshot only."""
    write_snapshot(
        project,
        sgs=(("sg-web", "web", "web"),),
        nics_by_ip={
            "10.0.1.10": [
                {"port_id": "p1", "ip": "10.0.1.10", "vm_name": None}
            ]
        },
    )
    for var in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    rc, out, _ = run(["plan", P, str(project)], None, capsys, monkeypatch)
    assert rc == 0 and "Dry run" in out


def test_apply_defaults_to_dry_run(project, gw, capsys, monkeypatch):
    rc, out, _ = run(["apply", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 0 and "member" in out and gw.call_log == []


def test_apply_yes_previews_before_writing(project, gw, capsys, monkeypatch):
    rc, out, _ = run(
        ["apply", "--yes", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0
    assert out.index("Plan: 2 to add") < out.index("Apply complete")
    assert any(s.name == "web" for s in gw.list_security_groups())
    assert gw.call_log  # writes happened after the preview


def test_apply_json_pure_stdout(project, gw, capsys, monkeypatch):
    rc, out, err = run(
        ["apply", "--yes", "--json", P, str(project)], gw, capsys, monkeypatch
    )
    data = json.loads(out)  # stdout is ONE pure JSON document
    assert rc == 0 and {"summary", "results"} <= set(data)
    assert "Plan:" in err  # the preview went to stderr


def test_apply_partial_failure_rc1(project, capsys, monkeypatch):
    class Exploding(FakeGateway):
        def create_security_group(self, name, description):
            raise CloudError("boom")

    gw = seed(Exploding())
    rc, out, _ = run(
        ["apply", "--yes", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 1 and "failed" in out


def _remove_web_group(project):
    """Deleting a group = removing its security-groups/<name>/
    directory. A second group (db) keeps security-groups/ non-empty so
    the whole-estate guard stays quiet — these tests are about ONE
    deletion."""
    make_project(
        project, {"security-groups/db/group.yaml": "name: db\nmembers: []\n"}
    )
    shutil.rmtree(project / "security-groups" / "web")


def test_removed_directory_plans_deletion(project, capsys, monkeypatch):
    _remove_web_group(project)
    gw = seed(FakeGateway(), sgs=(("sg-1", "web", "web"),))
    rc, out, _ = run(["plan", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 0 and "delete security group" in out
    assert "1 to destroy" in out
    assert gw.call_log == []  # a plan never writes


def test_apply_yes_on_removed_directory_detaches_then_deletes(
    project, capsys, monkeypatch
):
    _remove_web_group(project)
    gw = seed(
        FakeGateway(),
        sgs=(("sg-1", "web", "web"),),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-1", "p1"),),
    )
    rc, _, _ = run(
        ["apply", "--yes", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0
    assert gw.call_log.index("detach:p1->sg-1") < gw.call_log.index(
        "delete_sg:sg-1"
    )
    assert not any(s.name == "web" for s in gw.list_security_groups())


def test_snapshot_writes_file(project, gw, capsys, monkeypatch):
    rc, out, _ = run(["snapshot", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 0 and "snapshot: " in out
    assert (project / "snapshot.json").exists()


def test_drift_rc1_on_change(project, capsys, monkeypatch):
    write_snapshot(project, sgs=(("sg-web", "web", ""),))
    gw = seed(FakeGateway())  # cloud now empty -> group deleted
    rc, out, _ = run(["drift", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 1 and "- group web" in out


def test_import_writes_files_with_notes(tmp_path, capsys, monkeypatch):
    project = make_project(tmp_path, {})  # fresh: nothing to clash with
    write_snapshot(
        project,
        sgs=(("sg-web", "web", ""),),
        rules={
            "sg-web": [
                cloud_rule(
                    id="r1", remote_group_id="sg-web", remote_ip_prefix=None
                )
            ]
        },
    )
    rc, out, _ = run(["import", P, str(project)], None, capsys, monkeypatch)
    assert rc == 0
    assert (project / "security-groups" / "web" / "group.yaml").exists()
    assert (project / "security-groups" / "web" / "ingress.yaml").exists()
    assert "self-referential" in out and "now managed" in out


def test_import_refuses_overwrite(project, capsys, monkeypatch):
    # the project fixture already manages `web`; importing it again
    # must refuse without --force
    write_snapshot(project, sgs=(("sg-web", "web", ""),))
    rc, _, err = run(["import", P, str(project)], None, capsys, monkeypatch)
    assert rc == 1 and "refusing to overwrite" in err


def test_plan_yes_rejected(project, gw, capsys, monkeypatch):
    monkeypatch.setattr(
        "builtins.input", lambda *_: pytest.fail("unexpected prompt")
    )
    with pytest.raises(SystemExit) as ei:
        main(["plan", "--yes", P, str(project)], gateway=gw)
    err = capsys.readouterr().err
    assert ei.value.code == 2
    assert "read-only" in err and "apply --yes" in err


def test_missing_credentials_names_all_four(project, capsys, monkeypatch):
    make_project(project, {})  # empty dir: no security-groups/
    for var in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    rc, _, err = run(["plan", P, str(project)], None, capsys, monkeypatch)
    assert rc == 1
    for name in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        assert name in err


def test_plan_verbose_logs_phases(project, gw, capsys, monkeypatch):
    rc, out, err = run(
        ["plan", "--verbose", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "Dry run" in out
    assert "hcs-sg: phase: reading the observed state" in err
    # resolve is pure now (fed by the inventory's IP→NIC index), so a
    # plan emits no per-call gateway trail — only writes do


def test_duplicate_cloud_names_clean_error(project, capsys, monkeypatch):
    gw = seed(FakeGateway(), sgs=(("sg-a", "web", ""), ("sg-b", "web", "")))
    rc, _, err = run(["plan", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 1
    assert "duplicate cloud security group name" in err
    assert "sg-a" in err and "sg-b" in err


def test_apply_with_rules_full_flow(project, gw, capsys, monkeypatch):
    make_project(
        project,
        {
            "security-groups/web/ingress.yaml": INGRESS_YAML,
            "security-groups/web/egress.yaml": "[]\n",
        },
    )
    rc, out, _ = run(
        ["apply", "--yes", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "3 ok" in out  # group + rule + member
    rules = gw.list_rules(
        next(s.id for s in gw.list_security_groups() if s.name == "web")
    )
    assert len(rules) == 1 and rules[0].ports == "22"


def test_apply_snapshot_pair_writes_and_notes_stale(
    tmp_path, capsys, monkeypatch
):
    """Offline pre-work + live write pairing: snapshot.json present ->
    plan reads the FILE (cloud lacks web), --yes writes to the gateway,
    and the snapshot is honestly noted stale."""
    from tests.conftest import GROUP_YAML, make_project

    project = make_project(
        tmp_path, {"security-groups/web/group.yaml": GROUP_YAML}
    )
    write_snapshot(
        project,
        nics_by_ip={
            "10.0.1.10": [
                {"port_id": "p1", "ip": "10.0.1.10", "vm_name": None}
            ]
        },
    )
    gw = seed(FakeGateway())
    rc, out, err = run(
        ["apply", "--yes", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0 and "Apply complete" in out
    assert any(s.name == "web" for s in gw.list_security_groups())  # live
    assert "planning from snapshot.json" in err  # pre-work was offline
    assert "snapshot.json is now stale" in err


def test_deletion_preview_precedes_writes(project, capsys, monkeypatch):
    _remove_web_group(project)
    gw = seed(
        FakeGateway(),
        sgs=(("sg-1", "web", "web"),),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-1", "p1"),),
    )
    rc, out, _ = run(
        ["apply", "--yes", P, str(project)], gw, capsys, monkeypatch
    )
    assert rc == 0
    assert out.index("2 to destroy") < out.index("Apply complete")
    # 2 to destroy = member detach + group delete, previewed FIRST


def test_drift_clean_rc0_and_json_envelope(project, capsys, monkeypatch):
    write_snapshot(project, sgs=(("sg-web", "web", "web"),))
    gw = seed(FakeGateway(), sgs=(("sg-web", "web", "web"),))
    rc, out, _ = run(["drift", P, str(project)], gw, capsys, monkeypatch)
    assert rc == 0 and "no drift" in out
    rc, out, _ = run(
        ["drift", "--json", P, str(project)], gw, capsys, monkeypatch
    )
    data = json.loads(out)  # one pure JSON doc
    assert rc == 0
    assert {
        "created",
        "reference",
        "target",
        "missingObjects",
        "unexpectedObjects",
        "changedObjects",
    } == set(data["diff"])


def test_import_force_overwrites_and_json_lists(tmp_path, capsys, monkeypatch):
    from tests.conftest import GROUP_YAML, make_project

    project = make_project(
        tmp_path, {"security-groups/web/group.yaml": GROUP_YAML}
    )
    write_snapshot(project, sgs=(("sg-web", "web", "new-desc"),))
    rc, _, _ = run(
        ["import", "--force", P, str(project)], None, capsys, monkeypatch
    )
    assert rc == 0
    assert (
        "new-desc"
        in (project / "security-groups" / "web" / "group.yaml").read_text()
    )
    rc, out, _ = run(
        ["import", "--json", "--force", P, str(project)],
        None,
        capsys,
        monkeypatch,
    )
    data = json.loads(out)
    assert rc == 0
    assert {"imported", "rules", "files", "notes"} == set(data)


def test_plan_uses_snapshot_flag_not_just_autodetect(
    tmp_path, capsys, monkeypatch
):
    """The --snapshot FILE path (vs auto-detected snapshot.json)."""
    from tests.conftest import make_project

    project = make_project(
        tmp_path,
        {"security-groups/web/group.yaml": "name: web\nmembers: []\n"},
    )
    other = project / "elsewhere"
    other.mkdir()
    write_snapshot(other, sgs=(("sg-x", "ghost", ""),))
    for var in ("HCS_AK", "HCS_SK", "HCS_PROJECT_ID", "HCS_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    rc, out, _ = run(
        ["plan", "--snapshot", str(other / "snapshot.json"), P, str(project)],
        None,
        capsys,
        monkeypatch,
    )
    assert rc == 0 and "Dry run" in out  # planned from the flag's file
