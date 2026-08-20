# tests/contract/test_gateway_contract.py
"""One behavioural suite, two gateways: the in-memory fake (always) and
the real Huawei adapter (only with credentials). LSP, executable."""
import os

import pytest

from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.entities import Rule
from hcs_sg_iac.model.remote import RemoteCidr, RemoteGroup


def _real_gateway():
    from hcs_sg_iac.adapters.huawei_gateway import build_gateway
    from hcs_sg_iac.cli.main import load_config
    return build_gateway(load_config())


GATEWAYS = [
    pytest.param(FakeGateway, id="fake"),
    pytest.param(_real_gateway, id="real",
                 marks=[pytest.mark.cloud_contract,
                        pytest.mark.skipif(not os.environ.get("HCS_AK"),
                                           reason="no HCS credentials")]),
]


def _best_effort_cleanup(gw):
    """Failure-safe teardown: a mid-run assertion failure must not leak
    the contract SGs on a live cloud (the fake just ignores it)."""
    try:
        sgs = {s.name: s.id for s in gw.list_security_groups()}
    except Exception:
        return
    for name in ("contract", "contract-peer", "contract-2"):
        sg_id = sgs.get(name)
        if not sg_id:
            continue
        try:
            for nic in gw.list_attached_nics(sg_id):
                gw.detach_nic(sg_id, nic.port_id)
        except Exception:
            pass
        try:
            gw.delete_security_group(sg_id)
        except Exception:
            pass


def _exercise(gw):
    try:
        sg = gw.create_security_group("contract", "d")
        assert any(s.name == "contract" for s in gw.list_security_groups())
        gw.attach_nic(sg.id, "port-1")
        assert [n.port_id for n in gw.list_attached_nics(sg.id)] == ["port-1"]
        rule = gw.create_rule(sg.id, Rule("ingress", "tcp", "22",
                                          RemoteCidr("203.0.113.0/24")))
        rules = gw.list_rules(sg.id)
        assert len(rules) == 1 and rules[0].id == rule.id
        assert rules[0].remote_ip_prefix == "203.0.113.0/24"
        other = gw.create_security_group("contract-peer", "d")
        rr = gw.create_rule(sg.id, Rule("ingress", "tcp", "8080",
                                        RemoteGroup("contract-peer")))
        assert rr.remote_group_id == other.id      # id, not the name
        gw.delete_rule(rule.id)
        assert len(gw.list_rules(sg.id)) == 1
        gw.detach_nic(sg.id, "port-1")
        assert gw.list_attached_nics(sg.id) == []
        gw.delete_security_group(sg.id)
        assert not any(s.name == "contract" for s in gw.list_security_groups())
    finally:
        _best_effort_cleanup(gw)


def _exercise_extended(gw):
    """The protocol corners CTRCT-01's tcp exercise does not touch:
    a udp rule keeps its port; an icmp rule reads back PORTLESS even
    though the wire carries type/code in port_range_min/max; an
    all-protocol rule reads back protocol None. Create, list, verify
    identity, delete — same cleanup discipline as CTRCT-01."""
    try:
        sg = gw.create_security_group("contract-2", "d")
        udp = gw.create_rule(sg.id, Rule("ingress", "udp", "53",
                                         RemoteCidr("203.0.113.0/24")))
        icmp = gw.create_rule(sg.id, Rule("ingress", "icmp", None,
                                          RemoteCidr("203.0.113.0/24")))
        everything = gw.create_rule(sg.id, Rule("egress", "all", None,
                                                RemoteCidr("0.0.0.0/0")))
        rules = {r.id: r for r in gw.list_rules(sg.id)}
        assert set(rules) == {udp.id, icmp.id, everything.id}
        assert rules[udp.id].protocol == "udp"
        assert rules[udp.id].ports == "53"
        assert rules[icmp.id].protocol == "icmp"
        assert rules[icmp.id].ports is None          # type/code are not ports
        assert rules[everything.id].protocol is None  # all == protocol unset
        assert rules[everything.id].ports is None
        for r in (udp, icmp, everything):
            gw.delete_rule(r.id)
        assert gw.list_rules(sg.id) == []
        gw.delete_security_group(sg.id)
        assert not any(s.name == "contract-2" for s in gw.list_security_groups())
    finally:
        _best_effort_cleanup(gw)


def _exercise_inventory(gw):
    """The 2-call fast path must agree with the per-SG protocol reads on
    the SAME cloud — the strongest real-cloud validation of the snapshot
    optimisation (SG set, per-SG rules, per-SG membership, and the NIC
    index). Slow path sampled to 5 SGs to bound the call cost."""
    snap, nics_by_ip = gw.inventory()
    slow_sgs = {s.id for s in gw.list_security_groups()}
    assert {s.id for s in snap.sgs} == slow_sgs, \
        "inventory SG set disagrees with per-SG read"
    for sg in list(snap.sgs)[:5]:
        assert set(snap.rules.get(sg.id, ())) == set(gw.list_rules(sg.id)), \
            f"rules disagree for {sg.name}"
        assert ({n.port_id for n in snap.attached.get(sg.id, ())}
                == {n.port_id
                    for n in gw.list_attached_nics(sg.id)}), \
            f"membership disagrees for {sg.name}"
    for sg in snap.sgs:            # every attached v4 NIC is indexed
        for n in snap.attached.get(sg.id, ()):
            if n.ip and "." in n.ip:
                assert any(x.port_id == n.port_id
                           for x in nics_by_ip.get(n.ip, ())), \
                    f"nic {n.port_id} ({n.ip}) missing from the index"


@pytest.mark.parametrize("make_gw", GATEWAYS)
def test_contract_round_trip(make_gw):                  # CTRCT-01
    _exercise(make_gw())


@pytest.mark.parametrize("make_gw", GATEWAYS)
def test_contract_extended_protocols(make_gw):          # CTRCT-02
    _exercise_extended(make_gw())


@pytest.mark.parametrize("make_gw", GATEWAYS)
def test_contract_inventory_matches_per_sg_reads(make_gw):   # CTRCT-03
    _exercise_inventory(make_gw())
