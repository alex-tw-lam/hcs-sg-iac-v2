# tests/adapters/test_fake_gateway.py
"""Row coverage for the writer surface lives in tests/specs/frames.py
(FAKE-01/01.a: create/update/delete round-trip, FAKE-02: remote-group
name→id, FAKE-03: per-SG delete cascade). What stays is row-inexpressible:
unseeded-port attachment, the unknown-remote error, and the audit sinks."""

import json

import pytest
from hcs_sg_iac.adapters.audit import enrich, jsonl_sink
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.entities import Rule
from hcs_sg_iac.model.errors import CloudError
from hcs_sg_iac.model.remote import RemoteGroup


def test_attach_unseeded_port_becomes_visible():
    gw = FakeGateway()
    sg = gw.create_security_group("web", "")
    gw.attach_nic(sg.id, "port-999")
    attached = gw.list_attached_nics(sg.id)
    assert [n.port_id for n in attached] == ["port-999"]
    assert attached[0].ip == ""  # auto-registered placeholder


def test_create_rule_unknown_remote_group_raises():
    gw = FakeGateway()
    sg = gw.create_security_group("web", "")
    with pytest.raises(CloudError, match="unknown remote group 'ghost'"):
        gw.create_rule(
            sg.id, Rule("ingress", "tcp", "443", RemoteGroup("ghost"))
        )


def test_jsonl_sink_appends(tmp_path):
    p = tmp_path / "audit.jsonl"
    sink = jsonl_sink(p)
    sink({"a": 1})
    sink({"b": 2})
    lines = [json.loads(line) for line in p.read_text().splitlines()]
    assert lines == [{"a": 1}, {"b": 2}]


def test_enrich_adds_context_without_clobbering():
    seen = []
    sink = enrich(seen.append, project="demo", quota={"left": 3})
    sink({"timestamp": "t", "actions": []})
    assert seen == [
        {
            "timestamp": "t",
            "actions": [],
            "project": "demo",
            "quota": {"left": 3},
        }
    ]
