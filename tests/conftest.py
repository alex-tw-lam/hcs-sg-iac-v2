# tests/conftest.py
"""The lean suite's shared fixtures: a per-SG-directory project on disk,
a seeded FakeGateway, and the run() harness every CLI scenario uses."""

import time

import pytest
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.cli.main import main
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg
from hcs_sg_iac.model.common import QuotaExhausted
from hcs_sg_iac.usecases.plan import plan, read_snapshot
from hcs_sg_iac.usecases.resolve import resolve_memberships

GROUP_YAML = "name: web\ndescription: web\nmembers:\n  - ip: 10.0.1.10\n"
INGRESS_YAML = "- {source: 203.0.113.0/24, protocol: tcp, ports: '22'}\n"


def make_project(root, files: dict):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def seed(gw, sgs=(), rules=(), nics=(("10.0.1.10", "p1"),), attached=()):
    for s in sgs:
        gw.add_sg(
            CloudSg(id=s[0], name=s[1], description=s[2] if len(s) > 2 else "")
        )
    for r in rules:
        gw.add_rule(CloudRule(**r))
    for ip, port in nics:
        gw.add_nic(CloudNic(port_id=port, ip=ip))
    for sg_id, port in attached:
        gw._attached.add((sg_id, port))
    return gw


def run(argv, gw, capsys, monkeypatch, sleeps=None):
    """argv -> (rc, stdout, stderr); any stray prompt fails loudly.
    `sleeps` (a list) captures time.sleep calls instead of sleeping."""
    monkeypatch.setattr(
        "builtins.input", lambda *_: pytest.fail("unexpected prompt")
    )
    if sleeps is not None:
        monkeypatch.setattr("time.sleep", sleeps.append)
    rc = main(list(argv), gateway=gw)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def cloud_rule(**kw):
    base = {
        "id": "r1",
        "sg_id": "sg-web",
        "direction": "ingress",
        "protocol": "tcp",
        "ports": "22",
        "remote_group_id": None,
        "remote_ip_prefix": "203.0.113.0/24",
    }
    base.update(kw)
    return base


def write_snapshot(
    project, sgs=(), rules=None, attached=None, nics_by_ip=None
):
    import json as _json

    snap = {
        "sgs": [
            {
                "id": s[0],
                "name": s[1],
                "description": s[2] if len(s) > 2 else "",
            }
            for s in sgs
        ],
        "rules": rules or {},
        "attached": attached or {},
        "nics_by_ip": nics_by_ip or {},
    }
    (project / "snapshot.json").write_text(_json.dumps(snap))
    return snap


def plan_state(gw, state):
    res = resolve_memberships(gw, state)
    assert res.report.ok, res.report.errors
    return plan(state, res, read_snapshot(gw))


@pytest.fixture
def project(tmp_path):
    return make_project(
        tmp_path, {"security-groups/web/group.yaml": GROUP_YAML}
    )


@pytest.fixture
def gw():
    return seed(FakeGateway())


class ExhaustOnce(FakeGateway):
    """QuotaExhausted carrying a retry deadline on the FIRST
    create_security_group, then normal — the wait-and-continue shape."""

    def __init__(self, delay: float = 60.0):
        super().__init__()
        self._deadline = time.time() + delay
        self.raised = False

    def create_security_group(self, name, description):
        if not self.raised:
            self.raised = True
            raise QuotaExhausted(
                "budget exhausted for this window", retry_at=self._deadline
            )
        return super().create_security_group(name, description)
