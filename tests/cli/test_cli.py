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


def test_apply_partial_failure_rc(project, capsys):
    """No CLI row exercises a hard gateway failure (CLI-15 is throttle):
    rc 1 with the failure visible on stdout."""
    class ExplodingGateway(FakeGateway):
        def create_security_group(self, name, description):
            raise CloudError("boom")

    gw = ExplodingGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    rc = main(["apply", "--project", str(project), "--yes"], gateway=gw)
    out = capsys.readouterr().out
    assert rc == 1
    assert "failed" in out


def test_apply_yes_writes_audit_jsonl(project, gw, capsys):
    """CLI-17 pins the file's existence; unique here: the record content —
    resolved project path, quota context, per-action entries."""
    rc = main(["apply", "--project", str(project), "--yes"], gateway=gw)
    assert rc == 0
    audit_path = project / "audit.jsonl"
    assert audit_path.exists()
    import json as _json
    rec = _json.loads(audit_path.read_text().splitlines()[-1])
    assert rec["project"] == str(project.resolve())
    assert rec["quota"] is not None
    assert any(a["type"] == "group" for a in rec["actions"])


def test_json_yes_stdout_is_pure_json(project, gw, capsys):
    """--json --yes: the preview table goes to stderr so stdout parses
    as JSON from the very first character."""
    import json as _json
    rc = main(["apply", "--project", str(project), "--yes", "--json"],
              gateway=gw)
    captured = capsys.readouterr()
    assert rc == 0
    data = _json.loads(captured.out)          # one JSON doc, first char
    assert data["summary"]["add"] >= 1
    assert "Plan: 2 to add" in captured.err   # preview on stderr


def test_apply_yes_previews_before_writing(project, gw, capsys):
    """The write path must show the preview BEFORE writing it out:
    pre-write quota line strictly before the RESULT table; --json keeps
    the preview on stderr (stdout stays one JSON document)."""
    rc = main(["apply", "--project", str(project), "--yes"], gateway=gw)
    out = capsys.readouterr().out
    assert rc == 0
    assert out.index("25 left in this window") < out.index("RESULT")
    assert gw.call_log                      # the preview came first, then writes


def test_plan_cloud_failure_is_one_clean_line(project, capsys):
    """A gateway read failure mid-plan must surface as a single error
    line with rc 1 — never a traceback (the raw-QuotaExhausted crash
    class of bugs)."""
    class BrokenGateway(FakeGateway):
        def inventory(self):              # the read path the CLI takes
            raise CloudError("VPC.0404 boom")

    gw = BrokenGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    rc = main(["plan", "--project", str(project)], gateway=gw)
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.strip() == "error: VPC.0404 boom"


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
