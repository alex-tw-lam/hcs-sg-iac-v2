# tests/test_gateway_contract.py
"""One behavioural exercise, two gateways: the fake (always) and the
real adapter (credentials-gated). LSP, executable — the fake cannot
silently diverge from the real cloud."""

import contextlib
import os

import pytest
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.common import RemoteCidr, RemoteGroup
from hcs_sg_iac.model.entities import Rule


def _real_gateway():
    from hcs_sg_iac.adapters.huawei_gateway import build_gateway
    from hcs_sg_iac.cli.main import load_config

    return build_gateway(load_config())


GATEWAYS = [
    pytest.param(FakeGateway, id="fake"),
    pytest.param(
        _real_gateway,
        id="real",
        marks=[
            pytest.mark.cloud_contract,
            pytest.mark.skipif(
                not os.environ.get("HCS_AK"), reason="no HCS credentials"
            ),
        ],
    ),
]

_NAMES = ("contract", "contract-peer", "contract-2", "contract-m")


def _cleanup(gw):
    """Failure-safe teardown: never leak contract SGs on a live cloud."""
    try:
        sgs = {s.name: s.id for s in gw.list_security_groups()}
    except Exception:
        return
    for name in _NAMES:
        sg_id = sgs.get(name)
        if not sg_id:
            continue
        with contextlib.suppress(Exception):
            for nic in gw.list_attached_nics(sg_id):
                gw.detach_nic(sg_id, nic.port_id)
        with contextlib.suppress(Exception):
            gw.delete_security_group(sg_id)


def _ours(gw, sg_id, *created):
    """list_rules filtered to the ids this run created — the real cloud
    coexists them with auto-added self rules, so identity is by OUR ids."""
    ids = {c.id for c in created}
    return {r.id: r for r in gw.list_rules(sg_id) if r.id in ids}


def test_round_trip(make_gw):  # CTRCT-01
    gw = make_gw
    try:
        sg = gw.create_security_group("contract", "d")
        assert any(s.name == "contract" for s in gw.list_security_groups())
        rule = gw.create_rule(
            sg.id, Rule("ingress", "tcp", "22", RemoteCidr("203.0.113.0/24"))
        )
        rules = _ours(gw, sg.id, rule)
        assert set(rules) == {rule.id}
        assert rules[rule.id].remote_ip_prefix == "203.0.113.0/24"
        other = gw.create_security_group("contract-peer", "d")
        rr = gw.create_rule(
            sg.id, Rule("ingress", "tcp", "8080", RemoteGroup("contract-peer"))
        )
        assert rr.remote_group_id == other.id  # id, not the name
        gw.delete_rule(rule.id)
        assert set(_ours(gw, sg.id, rule, rr)) == {rr.id}
        gw.delete_security_group(sg.id)
        assert not any(s.name == "contract" for s in gw.list_security_groups())
    finally:
        _cleanup(gw)


def test_extended_protocols(make_gw):  # CTRCT-02
    gw = make_gw
    try:
        sg = gw.create_security_group("contract-2", "d")
        udp = gw.create_rule(
            sg.id, Rule("ingress", "udp", "53", RemoteCidr("203.0.113.0/24"))
        )
        icmp = gw.create_rule(
            sg.id, Rule("ingress", "icmp", None, RemoteCidr("203.0.113.0/24"))
        )
        everything = gw.create_rule(
            sg.id, Rule("egress", "all", None, RemoteCidr("0.0.0.0/0"))
        )
        rules = _ours(gw, sg.id, udp, icmp, everything)
        assert set(rules) == {udp.id, icmp.id, everything.id}
        assert rules[udp.id].ports == "53"
        assert rules[icmp.id].ports is None  # type/code are not ports
        assert rules[everything.id].protocol is None
        for r in (udp, icmp, everything):
            gw.delete_rule(r.id)
        assert _ours(gw, sg.id, udp, icmp, everything) == {}
        gw.delete_security_group(sg.id)
    finally:
        _cleanup(gw)


def test_inventory_agrees_with_per_sg_reads(make_gw):  # CTRCT-03
    gw = make_gw
    snap = gw.inventory().snapshot
    assert {s.id for s in snap.sgs} == {
        s.id for s in gw.list_security_groups()
    }
    for sg in list(snap.sgs)[:5]:  # slow path sampled to bound call cost
        assert set(snap.rules.get(sg.id, ())) == set(gw.list_rules(sg.id))
        assert {n.port_id for n in snap.attached.get(sg.id, ())} == {
            n.port_id for n in gw.list_attached_nics(sg.id)
        }


def test_member_bind_unbind(make_gw):  # CTRCT-04
    gw = make_gw
    port = os.environ.get("HCS_CONTRACT_PORT")
    if not isinstance(gw, FakeGateway) and not port:
        pytest.skip(
            "set HCS_CONTRACT_PORT=<spare test port id> to "
            "exercise member bind/unbind on the real cloud"
        )
    if isinstance(gw, FakeGateway):
        port = "port-1"  # the fake seeds it
    sg = gw.create_security_group("contract-m", "d")
    try:
        gw.attach_nic(sg.id, port)
        assert port in {n.port_id for n in gw.list_attached_nics(sg.id)}
        gw.detach_nic(sg.id, port)  # append/remove-one: other SGs intact
        assert port not in {n.port_id for n in gw.list_attached_nics(sg.id)}
    finally:
        _cleanup(gw)


@pytest.fixture(params=GATEWAYS, ids=lambda p: p.id)
def make_gw(request):
    return request.param()
