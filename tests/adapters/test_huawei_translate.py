# tests/adapters/test_huawei_translate.py
"""Pure translation helpers + the limiter chokepoint, tested against a
stub SDK (never a real network)."""
import warnings
from types import SimpleNamespace

import pytest
from huaweicloudsdkcore.exceptions.exceptions import (ClientRequestException,
                                                      ServiceResponseException)

from hcs_sg_iac.adapters.huawei_gateway import (HuaweiGateway, _METHODS,
                                                _bounds, build_gateway)
from hcs_sg_iac.adapters.ratelimit import FixedWindowLimiter
from hcs_sg_iac.model.errors import CloudError, CloudThrottled, QuotaExhausted


def test_dispatch_table_targets_exist_on_vpcclient():
    """Every _METHODS value must be a real VpcClient method — this is
    the credential-free guard that would have caught a table typo."""
    from huaweicloudsdkvpc.v2 import VpcClient
    missing = [name for name in sorted(set(_METHODS.values()))
               if not callable(getattr(VpcClient, name, None))]
    assert not missing, f"VpcClient is missing dispatch targets: {missing}"


def test_dispatch_table_pairs_request_classes_with_methods():
    """Existence is not enough: each request class must be the type its
    client method actually expects. The generated SDK methods document
    the parameter as ':type request: :class:`...XxxRequest`' — parse
    that and compare against the table key, so mapping e.g.
    ListSecurityGroupRulesRequest (native v1) to neutron_list_...
    FAILS here instead of erroring (or worse, silently succeeding)
    against the real cloud."""
    import re
    from huaweicloudsdkvpc.v2 import VpcClient
    for req_name, method_name in _METHODS.items():
        doc = getattr(VpcClient, method_name).__doc__ or ""
        m = re.search(r":type request:\s*:class:`[\w.]+\.(\w+)`", doc)
        assert m, f"no :type request: in {method_name} docstring"
        assert m.group(1) == req_name, \
            f"{req_name} -> {method_name} expects {m.group(1)}"


def test_cloud_rule_translation_range():
    r = SimpleNamespace(id="r1", security_group_id="sg1",
                        direction="ingress", protocol="tcp",
                        port_range_min=80, port_range_max=81,
                        remote_group_id=None, remote_ip_prefix="10.0.0.0/8")
    cr = HuaweiGateway.__new__(HuaweiGateway)._to_cloud_rule(r)
    assert cr.ports == "80-81"
    assert cr.remote_ip_prefix == "10.0.0.0/8"
    assert cr.protocol == "tcp"


def test_cloud_rule_translation_all_ports():
    r = SimpleNamespace(id="r2", security_group_id="sg1",
                        direction="egress", protocol=None,
                        port_range_min=None, port_range_max=None,
                        remote_group_id="sg9", remote_ip_prefix=None)
    cr = HuaweiGateway.__new__(HuaweiGateway)._to_cloud_rule(r)
    assert cr.ports is None and cr.protocol is None
    assert cr.remote_group_id == "sg9"


def test_bounds_envelope():
    assert _bounds(None) == (None, None)
    assert _bounds("80") == (80, 80)
    assert _bounds("8000-9000") == (8000, 9000)


def test_cloud_rule_translation_icmp_type_code_not_ports():
    # console-created ping rule: min=8 (type), max=0 (code) — a naive
    # parse_ports("8-0") would raise PortError on the reversed range
    r = SimpleNamespace(id="r3", security_group_id="sg1",
                        direction="ingress", protocol="icmp",
                        port_range_min=8, port_range_max=0,
                        remote_group_id=None, remote_ip_prefix="10.0.113.0/24")
    cr = HuaweiGateway.__new__(HuaweiGateway)._to_cloud_rule(r)
    assert cr.ports is None            # icmp rules are all-ports by identity
    assert cr.protocol == "icmp"


def test_name_to_uuid_resolution_uses_listing():
    gw = HuaweiGateway.__new__(HuaweiGateway)
    gw._sg_name_to_id = {}
    listed = []

    def fake_list():
        listed.append(1)
        gw._sg_name_to_id["web"] = "uuid-web"
        return []

    gw.list_security_groups = fake_list
    assert gw._resolve_remote_id("web") == "uuid-web"
    assert len(listed) == 1
    assert gw._resolve_remote_id("web") == "uuid-web"   # cached, no re-list
    assert len(listed) == 1


# -- chokepoint: every SDK call passes the limiter; exceptions translate --

def _sdk_error(code, msg):
    return SimpleNamespace(error_code=code, error_msg=msg,
                           request_id="req-1", encoded_auth_msg=None)


def _svc_error(status_code, code, msg):
    # real SDK exception type, so the gateway's except-clause matches it
    return ServiceResponseException(status_code, _sdk_error(code, msg))


def _gateway(handler, budget=4):
    limiter = FixedWindowLimiter(budget=budget, window_seconds=300,
                                 clock=lambda: 1000.0)   # frozen window
    return HuaweiGateway(SimpleNamespace(list_security_groups=handler), limiter)


def test_huawei_chokepoint_429_becomes_throttled_and_halves_limit():
    def raise_429(req):
        raise _svc_error(429, "APIGW.0301", "too many requests")

    gw = _gateway(raise_429, budget=4)
    with pytest.raises(CloudThrottled) as ei:
        gw.list_security_groups()
    assert "APIGW.0301" in str(ei.value)
    assert ei.value.retry_at == 1300.0   # frozen clock 1000 + 300s window
    assert gw.quota_snapshot()["effective_limit"] == 2   # 4 // 2: halved


def test_huawei_chokepoint_budget_exhaustion_short_circuits_sdk():
    calls = []

    def ok(req):
        calls.append(req)
        return SimpleNamespace(security_groups=[])

    gw = _gateway(ok, budget=1)
    gw.list_security_groups()
    assert len(calls) == 1
    with pytest.raises(QuotaExhausted) as ei:
        gw.list_security_groups()
    assert ei.value.retry_at == 1300.0   # wait-and-continue deadline
    assert len(calls) == 1          # budget guard fired BEFORE any SDK call


def test_huawei_chokepoint_other_service_error_becomes_cloud_error():
    def raise_404(req):
        raise _svc_error(404, "VPC.0404", "not found")

    gw = _gateway(raise_404, budget=4)
    with pytest.raises(CloudError) as ei:
        gw.list_security_groups()
    assert "404" in str(ei.value)
    assert "VPC.0404" in str(ei.value) and "not found" in str(ei.value)
    assert gw.quota_snapshot()["effective_limit"] == 4   # no shrink on plain errors


def test_huawei_chokepoint_client_request_429_also_throttles_with_deadline():
    """Real-shape regression (HCS HK environment): the SDK surfaces its
    internal retry exhaustion as ClientRequestException(status_code=429,
    error_code='429') — a ServiceResponseException subclass — not the
    documented APIGW.* shape. The chokepoint must still translate it to
    CloudThrottled carrying the window deadline, so the executor waits
    and continues instead of crashing."""
    def raise_429(req):
        raise ClientRequestException(429, _sdk_error(
            "429", "Max retries exceeded with url: /v2.0/"
                   "security-group-rules?limit=500"))

    gw = _gateway(raise_429, budget=4)
    with pytest.raises(CloudThrottled) as ei:
        gw.list_security_groups()
    assert "429" in str(ei.value)
    assert ei.value.retry_at == 1300.0
    assert gw.quota_snapshot()["effective_limit"] == 2


def test_ssl_verify_false_mutes_the_insecure_request_warning():
    """SSL_VERIFY=false opts out of TLS verification; the SDK's requests
    layer would then spam urllib3 InsecureRequestWarning on every call.
    build_gateway mutes exactly that message via stdlib warnings (no
    urllib3 import — the adapter keeps its designated-lib purity); with
    verification on, the warning stays loud."""
    cfg = SimpleNamespace(hcs_ak="a", hcs_sk="s", hcs_project_id="p",
                          hcs_endpoint="https://x", ca_bundle="",
                          ssl_verify=False, budget=1)

    def _caught_build_and_warn():
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            build_gateway(cfg)
            warnings.warn("Unverified HTTPS request is being made to host 'x'")
            return [str(w.message) for w in caught
                    if "Unverified HTTPS request" in str(w.message)]

    assert _caught_build_and_warn() == []          # muted when opted out
    cfg.ssl_verify = True
    assert _caught_build_and_warn()                # control: stays visible


# -- find_nics_by_ip: filter by fixed_ips, never by port UUID --

def _port(pid, ip, hostname="vm-a"):
    return SimpleNamespace(id=pid,
                           fixed_ips=[SimpleNamespace(ip_address=ip)],
                           dns_assignment=[{"hostname": hostname,
                                            "ip_address": ip}])


def _ports_gateway(handler, budget=10):
    limiter = FixedWindowLimiter(budget=budget, window_seconds=300,
                                 clock=lambda: 1000.0)
    return HuaweiGateway(SimpleNamespace(list_ports=handler), limiter)


def test_find_nics_by_ip_filters_on_fixed_ips_not_port_id():
    requests = []

    def fake_list_ports(req):
        requests.append(req)
        return SimpleNamespace(ports=[_port("port-1", "10.0.0.1")])

    gw = _ports_gateway(fake_list_ports)
    found = gw.find_nics_by_ip(["10.0.0.1", "10.0.0.2"])
    assert len(requests) == 1
    req = requests[0]
    assert req.fixed_ips == ["ip_address=10.0.0.1", "ip_address=10.0.0.2"]
    assert req.id is None                  # `id` filters port UUIDs — unused
    assert found["10.0.0.1"][0].port_id == "port-1"
    assert found["10.0.0.1"][0].vm_name == "vm-a"   # via dns_assignment
    assert found["10.0.0.2"] == []


def test_find_nics_by_ip_chunks_ip_filters_at_100():
    requests = []

    def fake_list_ports(req):
        requests.append(req)
        return SimpleNamespace(ports=[])

    gw = _ports_gateway(fake_list_ports)
    gw.find_nics_by_ip([f"10.0.{i // 250}.{i % 250}" for i in range(250)])
    assert [len(r.fixed_ips) for r in requests] == [100, 100, 50]
    assert all(r.id is None for r in requests)


# -- pagination: full pages advance the marker, a short page ends the loop --

def test_list_security_groups_follows_marker_through_pages():
    sg = lambda i: SimpleNamespace(id=f"sg-{i}", name=f"g{i}", description="")
    pages = [[sg(i) for i in range(200)],          # full
             [sg(i) for i in range(200, 400)],     # full
             [sg(400)]]                            # short -> stop
    requests = []

    def handler(req):
        requests.append(req)
        return SimpleNamespace(security_groups=pages[len(requests) - 1])

    gw = _gateway(handler, budget=5)
    sgs = gw.list_security_groups()
    assert len(sgs) == 401
    assert sgs[0].id == "sg-0" and sgs[-1].id == "sg-400"
    assert [r.marker for r in requests] == [None, "sg-199", "sg-399"]
    assert all(r.limit == 200 for r in requests)


def test_list_rules_follows_marker_through_pages():
    def rule(i):
        return SimpleNamespace(id=f"r-{i}", security_group_id="sg-1",
                               direction="ingress", protocol="tcp",
                               port_range_min=80, port_range_max=80,
                               remote_group_id=None,
                               remote_ip_prefix="10.0.0.0/8")

    pages = [[rule(i) for i in range(500)],
             [rule(i) for i in range(500, 1000)],
             [rule(1000)]]
    requests = []

    def handler(req):
        requests.append(req)
        return SimpleNamespace(security_group_rules=pages[len(requests) - 1])

    limiter = FixedWindowLimiter(budget=5, window_seconds=300,
                                 clock=lambda: 1000.0)
    gw = HuaweiGateway(
        SimpleNamespace(neutron_list_security_group_rules=handler), limiter)
    rules = gw.list_rules("sg-1")
    assert len(rules) == 1001
    assert [r.marker for r in requests] == [None, "r-499", "r-999"]
    assert all(r.limit == 500 for r in requests)
    assert all(r.security_group_id == "sg-1" for r in requests)


def test_list_attached_nics_follows_marker_through_pages():
    def port(i):
        return SimpleNamespace(
            id=f"p-{i}",
            fixed_ips=[SimpleNamespace(ip_address="10.0.0.1")],
            dns_assignment=[{"hostname": "vm-a", "ip_address": "10.0.0.1"}])

    pages = [[port(i) for i in range(200)],
             [port(i) for i in range(200, 400)],
             [port(400)]]
    requests = []

    def handler(req):
        requests.append(req)
        return SimpleNamespace(ports=pages[len(requests) - 1])

    gw = _ports_gateway(handler, budget=5)
    nics = gw.list_attached_nics("sg-1")
    assert len(nics) == 401
    assert all(n.vm_name == "vm-a" for n in nics)
    assert [r.marker for r in requests] == [None, "p-199", "p-399"]
    assert all(r.limit == 200 for r in requests)
    assert all(r.security_groups == ["sg-1"] for r in requests)
