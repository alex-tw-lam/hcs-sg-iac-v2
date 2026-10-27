# tests/test_huawei_translate.py
"""The SDK adapter's wire essentials against a stub SDK (never a real
network): dispatch pairing, rule translation, throttle wait-and-retry,
pagination on one endpoint, the fixed_ips filter, 2-call inventory."""

import re
from types import SimpleNamespace

import pytest
from hcs_sg_iac.adapters.huawei_gateway import (
    _METHODS,
    HuaweiGateway,
    _bounds,
)
from hcs_sg_iac.contracts import CloudError
from hcs_sg_iac.entities import PortSet
from huaweicloudsdkcore.exceptions.exceptions import (
    ClientRequestException,
    ServiceResponseException,
)


def test_dispatch_table_pairs_request_classes_with_methods():
    """The credential-free guard: every mapping must be the request type
    its VpcClient method actually takes (a table typo fails HERE)."""
    from huaweicloudsdkvpc.v2 import VpcClient

    for req_name, method_name in _METHODS.items():
        assert callable(getattr(VpcClient, method_name, None)), method_name
        doc = getattr(VpcClient, method_name).__doc__ or ""
        m = re.search(r":type request:\s*:class:`[\w.]+\.(\w+)`", doc)
        assert m and m.group(1) == req_name, f"{req_name}->{method_name}"


def _wire_rule(**kw):
    base: dict = {
        "id": "r1",
        "security_group_id": "sg1",
        "direction": "ingress",
        "protocol": "tcp",
        "port_range_min": 80,
        "port_range_max": 81,
        "remote_group_id": None,
        "remote_ip_prefix": "10.0.0.0/8",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_cloud_rule_translation():
    tr = HuaweiGateway.__new__(HuaweiGateway)._to_cloud_rule
    cr = tr(_wire_rule())  # range
    assert cr.ports == "80-81" and cr.protocol == "tcp"
    cr = tr(
        _wire_rule(
            protocol=None,
            port_range_min=None,
            port_range_max=None,
            remote_group_id="sg9",
            remote_ip_prefix=None,
        )
    )  # all-ports, group remote
    assert cr.ports is None and cr.protocol is None
    assert cr.remote_group_id == "sg9"
    cr = tr(
        _wire_rule(protocol="icmp", port_range_min=8, port_range_max=0)
    )  # type/code are NOT ports
    assert cr.ports is None and cr.protocol == "icmp"


def test_bounds_envelope():
    assert _bounds(None) == (None, None)
    assert _bounds(PortSet("80")) == (80, 80)
    assert _bounds(PortSet("8000-9000")) == (8000, 9000)


def test_name_to_uuid_resolution_caches():
    gw = HuaweiGateway.__new__(HuaweiGateway)
    gw._sg_name_to_id = {}
    listed = []

    def fake_list():
        listed.append(1)
        gw._sg_name_to_id["web"] = "uuid-web"
        return []

    gw.list_security_groups = fake_list
    assert gw._resolve_remote_id("web") == "uuid-web"
    assert gw._resolve_remote_id("web") == "uuid-web"  # cached
    assert len(listed) == 1


# -- the chokepoint: every SDK call retries throttles in place --


def _sdk_error(code, msg):
    return SimpleNamespace(
        error_code=code, error_msg=msg, request_id="r", encoded_auth_msg=None
    )


def _gateway(handler, **kw):
    return HuaweiGateway(
        SimpleNamespace(list_security_groups=handler), **kw
    )


def test_throttle_waits_and_retries_in_place():
    """429 twice then success: the gateway retries inside, the caller
    never sees the throttle."""
    calls = []

    def flaky(req):
        calls.append(1)
        if len(calls) < 3:
            raise ServiceResponseException(
                429, _sdk_error("APIGW.0301", "too many")
            )
        return SimpleNamespace(security_groups=[])

    gw = _gateway(flaky, throttle_wait=0.0)
    assert gw.list_security_groups() == []
    assert len(calls) == 3


def test_persistent_throttle_becomes_clean_cloud_error():
    def raise_429(req):
        raise ServiceResponseException(429, _sdk_error("APIGW.0301", "slow"))

    gw = _gateway(raise_429, throttle_wait=0.0, throttle_tries=2)
    with pytest.raises(CloudError) as ei:
        gw.list_security_groups()
    msg = str(ei.value)
    assert "throttled" in msg and "APIGW.0301" in msg
    assert "list_security_groups" in msg  # the call trail travels

    # the SDK's own internal-retry-exhaustion shape counts too:
    def raise_client_429(req):
        raise ClientRequestException(429, _sdk_error("429", "max retries"))

    gw2 = _gateway(raise_client_429, throttle_wait=0.0, throttle_tries=2)
    with pytest.raises(CloudError):
        gw2.list_security_groups()


def test_other_errors_become_cloud_error():
    def raise_404(req):
        raise ServiceResponseException(
            404, _sdk_error("VPC.0404", "not found")
        )

    gw = _gateway(raise_404)
    with pytest.raises(CloudError) as ei:
        gw.list_security_groups()
    assert "VPC.0404" in str(ei.value)


def test_pagination_follows_marker_one_endpoint():
    pages = [
        [
            SimpleNamespace(id=f"g{i}", name=f"n{i}", description="")
            for i in range(0, 3)
        ],  # full page (limit 3) -> continue
        [SimpleNamespace(id="g9", name="n9", description="")],
    ]
    calls = []

    def handler(req):
        calls.append(type(req).__name__)
        return SimpleNamespace(
            security_groups=pages[1] if req.marker else pages[0]
        )

    gw = HuaweiGateway(SimpleNamespace(list_security_groups=handler))
    # shrink the page size for the test via the module constant
    import hcs_sg_iac.adapters.huawei_gateway as hg

    real = hg._SG_PAGE
    hg._SG_PAGE = 3
    try:
        sgs = gw.list_security_groups()
    finally:
        hg._SG_PAGE = real
    assert [s.name for s in sgs] == ["n0", "n1", "n2", "n9"]
    assert len(calls) == 2  # full page advanced the marker


def test_inventory_whole_cloud_in_two_calls():
    embedded = _wire_rule(
        id="r-1",
        direction="ingress",
        protocol="tcp",
        port_range_min=80,
        port_range_max=80,
        remote_ip_prefix="10.0.0.0/8",
        security_group_id=None,
    )
    sg = SimpleNamespace(
        id="sg-1", name="web", description="d", security_group_rules=[embedded]
    )
    port = SimpleNamespace(
        id="p-1",
        fixed_ips=[SimpleNamespace(ip_address="10.0.1.10")],
        security_groups=["sg-1"],
        dns_assignment=[{"hostname": "vm-a", "ip_address": "10.0.1.10"}],
    )
    calls = []

    def handler(req):
        calls.append(type(req).__name__)
        if type(req).__name__ == "NeutronListSecurityGroupsRequest":
            return SimpleNamespace(security_groups=[sg])
        return SimpleNamespace(ports=[port])

    gw = HuaweiGateway(
        SimpleNamespace(
            neutron_list_security_groups=handler, list_ports=handler
        )
    )
    inv = gw.inventory()
    assert [s.name for s in inv.snapshot.sgs] == ["web"]
    assert inv.snapshot.rules["sg-1"][0].ports == "80"
    assert [n.port_id for n in inv.snapshot.attached["sg-1"]] == ["p-1"]
    assert inv.nics_by_ip["10.0.1.10"][0].vm_name == "vm-a"
    assert calls.count("NeutronListSecurityGroupsRequest") == 1
    assert calls.count("ListPortsRequest") == 1  # the whole estate
