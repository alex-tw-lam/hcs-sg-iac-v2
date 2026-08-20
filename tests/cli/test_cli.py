# tests/cli/test_cli.py
"""CLI depth tests that no CLI-* frame row pins; the breadth lives in
the frame catalogue (tests/specs/frames.py)."""
import pytest

from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.cli.main import main
from hcs_sg_iac.model.cloud import CloudNic
from hcs_sg_iac.model.errors import CloudError


@pytest.fixture
def project(tmp_path):
    g = tmp_path / "groups"
    g.mkdir()
    (g / "web.yaml").write_text(
        "name: web\ndescription: web\nmembers:\n  - ip: 10.0.1.10\n")
    return tmp_path


@pytest.fixture
def gw():
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    return gw


def test_apply_partial_failure_rc(project, capsys, monkeypatch):
    """No CLI row exercises a hard gateway failure (CLI-15 is throttle):
    rc 1 with the failure visible on stdout."""
    class ExplodingGateway(FakeGateway):
        def create_security_group(self, name, description):
            raise CloudError("boom")

    gw = ExplodingGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    rc = main(["apply", "--project", str(project), "--execute", "--yes"],
              gateway=gw)
    out = capsys.readouterr().out
    assert rc == 1
    assert "failed" in out


def test_apply_execute_writes_audit_jsonl(project, gw, capsys, monkeypatch):
    """CLI-17 pins the file's existence; unique here: the record content —
    resolved project path, quota context, per-action entries."""
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    rc = main(["apply", "--project", str(project), "--execute"], gateway=gw)
    assert rc == 0
    audit_path = project / "audit.jsonl"
    assert audit_path.exists()
    import json as _json
    rec = _json.loads(audit_path.read_text().splitlines()[-1])
    assert rec["project"] == str(project.resolve())
    assert rec["quota"] is not None
    assert any(a["type"] == "group" for a in rec["actions"])


def test_json_execute_stdout_is_pure_json(project, gw, capsys, monkeypatch):
    """--json --execute: the confirmation prompt goes to stderr so stdout
    parses as JSON from the very first character."""
    import json as _json
    monkeypatch.setattr("builtins.input", lambda *_: "yes")
    rc = main(["apply", "--project", str(project), "--execute", "--json"],
              gateway=gw)
    captured = capsys.readouterr()
    assert rc == 0
    data = _json.loads(captured.out)          # must not need prompt-skipping
    assert data["summary"]["add"] >= 1
    assert "type 'yes'" in captured.err


def test_schema_command_outputs_json_no_gateway(capsys):
    import json as _json
    for which, keys in (("group", None), ("rules", None),
                        ("all", ["group_file", "rules_file"])):
        rc = main(["schema", which], gateway=None)
        assert rc == 0
        data = _json.loads(capsys.readouterr().out)
        if keys:
            assert set(data) == set(keys)
        else:
            assert data["$schema"].startswith("https://json-schema.org/")
