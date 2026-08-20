# tests/test_model.py
"""The vocabulary's load-bearing corners: name boundaries, port grammar,
remote normalisation, icmp/ports consistency, snapshot roundtrip."""

import pytest
from hcs_sg_iac.model.cloud import (
    CloudNic,
    CloudRule,
    CloudSg,
    Snapshot,
    snapshot_from_json,
    snapshot_to_json,
)
from hcs_sg_iac.model.entities import parse_group, parse_rule_list
from hcs_sg_iac.model.portset import PortError, parse_ports
from hcs_sg_iac.model.remote import parse_remote
from hcs_sg_iac.model.report import Report


def _group(d):
    return parse_group(d, "where", Report())


def test_name_boundaries():
    assert _group({"name": "a" * 64, "members": []}) is not None
    assert _group({"name": "a" * 65, "members": []}) is None
    assert _group({"name": "Web", "members": []}) is None
    assert _group({"name": "10.0.1.10", "members": []}) is None  # IP-like
    assert _group({"name": "web_tier", "members": []}) is not None


def test_ports_canonical_merge():
    assert parse_ports("443,22,80") == "22,80,443"  # sorted
    assert parse_ports("22,23") == "22-23"  # adjacent merged
    assert parse_ports("80,80") == "80"  # duplicates collapse
    assert parse_ports([8080, 9090]) == "8080,9090"
    assert parse_ports("1-65535") is None  # full range == all ports
    assert parse_ports("") is None


@pytest.mark.parametrize(
    "bad",
    [
        "0",
        "65536",
        "70000",
        "80-22",
        "abc",
        "22,,443",
        "8-0",
        1.5,
        True,
        "22.5",
    ],
)
def test_ports_junk_raises(bad):
    with pytest.raises(PortError):
        parse_ports(bad)


def test_remote_normalisation():
    assert parse_remote("10.0.0.7") == parse_remote("10.0.0.7/32")
    assert parse_remote("ghost") is not None  # group name is fine
    with pytest.raises(ValueError):
        parse_remote("::/0")  # v6 is out of model scope
    with pytest.raises(ValueError):
        parse_remote("10.0.0.0/33")


def test_icmp_rules_reject_ports():
    report = Report()
    rules = parse_rule_list(
        [{"source": "0.0.0.0/0", "protocol": "icmp", "ports": "80"}],
        "where",
        report,
        "ingress",
        "source",
    )
    assert not report.ok and rules == ()
    assert any("must not have ports" in e for e in report.errors)


def test_null_direction_document_guidance():
    report = Report()
    parse_rule_list(None, "where", report, "ingress", "source")
    assert any("use [] for remove-all" in e for e in report.errors)


def test_snapshot_json_roundtrip():
    snap = Snapshot(
        sgs=(CloudSg(id="s1", name="web", description="d"),),
        rules={
            "s1": [
                CloudRule(
                    id="r1",
                    sg_id="s1",
                    direction="ingress",
                    protocol=None,
                    ports=None,
                    remote_group_id="s1",
                    remote_ip_prefix=None,
                )
            ]
        },
        attached={
            "s1": [CloudNic(port_id="p1", ip="10.0.1.1", vm_name="vm-a")]
        },
    )
    nics = {
        "10.0.1.1": [CloudNic(port_id="p1", ip="10.0.1.1", vm_name="vm-a")]
    }
    inv = snapshot_from_json(
        snapshot_to_json(snap.sgs, snap.rules, snap.attached, nics)
    )
    assert inv.snapshot == snap and inv.nics_by_ip == nics
