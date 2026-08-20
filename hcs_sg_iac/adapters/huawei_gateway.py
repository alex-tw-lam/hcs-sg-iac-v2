# hcs_sg_iac/adapters/huawei_gateway.py
"""The ONLY module importing the Huawei SDK. Implements every protocol;
every call goes through the fixed-window limiter (single chokepoint).
Attach/detach uses the update-port pattern proven in the sibling
service (v3 insert/remove not assumed published on HCS 8.5.1).

Discovered against huaweicloudsdkvpc 3.1.210 (v2 API): SG description
updates ride the Neutron API (the native v2 create option has no
description field), so create passes name only and a non-empty
description is set right after via NeutronUpdateSecurityGroup. Port
lookup by member IP uses the fixed_ips query filter ("ip_address=...")—
the `id` filter matches port UUIDs, not addresses. ICMP rules carry
type/code in port_range_min/max, which are NOT ports."""
import logging
import time
import warnings

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions.exceptions import (SdkException,
                                                      ServiceResponseException)
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkvpc.v2 import (CreateSecurityGroupOption,
                                  CreateSecurityGroupRequest,
                                  CreateSecurityGroupRequestBody,
                                  DeleteSecurityGroupRequest,
                                  ListPortsRequest, ListSecurityGroupsRequest,
                                  NeutronCreateSecurityGroupRuleOption,
                                  NeutronCreateSecurityGroupRuleRequest,
                                  NeutronCreateSecurityGroupRuleRequestBody,
                                  NeutronDeleteSecurityGroupRuleRequest,
                                  NeutronListSecurityGroupRulesRequest,
                                  NeutronListSecurityGroupsRequest,
                                  NeutronSecurityGroupRule,
                                  NeutronUpdateSecurityGroupOption,
                                  NeutronUpdateSecurityGroupRequest,
                                  NeutronUpdateSecurityGroupRequestBody,
                                  UpdatePortOption, UpdatePortRequestBody,
                                  UpdatePortRequest, VpcClient)

from hcs_sg_iac.adapters.ratelimit import FixedWindowLimiter
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg, Inventory, Snapshot
from hcs_sg_iac.model.entities import Rule
from hcs_sg_iac.model.errors import CloudError, CloudThrottled, QuotaExhausted
from hcs_sg_iac.model.portset import parse_ports  # PortSet via _bounds

_log = logging.getLogger(__name__)   # --verbose: wired by the CLI

# Marker pagination page sizes (introspected: ListSecurityGroupsRequest,
# NeutronListSecurityGroupRulesRequest and ListPortsRequest all expose
# both limit and marker on this SDK). Smaller pages cost more budget
# slots on large estates; these are the sane defaults for an HCS
# private-cloud scale.
_SG_PAGE = 200
_RULE_PAGE = 500
_PORT_PAGE = 200

# Client-method dispatch: request class name → VpcClient method name.
# Verified against the installed SDK: Neutron request classes pair with
# the neutron_* client methods (the /v2.0 endpoints); the native methods
# hit /v1 endpoints and take different request types. Every URI below
# cross-checked against the HCS 8.5.1 VPC API Reference (Issue 04 PDF,
# 585pp): all ten are documented for the private cloud — the v1 paths
# appear there with {tenant_id} placeholders, which BasicCredentials
# fills with the project id. tests/adapters/test_huawei_translate.py
# asserts every target exists on VpcClient.
_METHODS = {
    "ListSecurityGroupsRequest": "list_security_groups",
    "CreateSecurityGroupRequest": "create_security_group",
    "NeutronListSecurityGroupsRequest": "neutron_list_security_groups",
    "NeutronUpdateSecurityGroupRequest": "neutron_update_security_group",
    "DeleteSecurityGroupRequest": "delete_security_group",
    "NeutronListSecurityGroupRulesRequest": "neutron_list_security_group_rules",
    "NeutronCreateSecurityGroupRuleRequest": "neutron_create_security_group_rule",
    "NeutronDeleteSecurityGroupRuleRequest": "neutron_delete_security_group_rule",
    "ListPortsRequest": "list_ports",
    "UpdatePortRequest": "update_port",
}


def build_gateway(config) -> "HuaweiGateway":
    http = HttpConfig.get_default_config()
    if config.ca_bundle:
        http.ssl_ca_cert = config.ca_bundle
    else:
        http.ignore_ssl_verification = not config.ssl_verify
        if not config.ssl_verify:
            # Opted out of verification: the SDK's requests layer would
            # spam urllib3 InsecureRequestWarning on EVERY call. Muted by
            # message via stdlib warnings — importing urllib3 here would
            # break the adapter's designated-third-party purity.
            warnings.filterwarnings("ignore",
                                    message="Unverified HTTPS request")
    sdk = (VpcClient.new_builder()
           .with_http_config(http)
           .with_credentials(BasicCredentials(config.hcs_ak, config.hcs_sk,
                                              config.hcs_project_id))
           .with_endpoint(config.hcs_endpoint)
           .build())
    limiter = FixedWindowLimiter(budget=config.budget, window_seconds=300)
    return HuaweiGateway(sdk, limiter)


class HuaweiGateway:
    def __init__(self, sdk, limiter):
        self._sdk = sdk
        self._limiter = limiter
        self._sg_name_to_id = {}      # cache for remote-group resolution
        self._recent_calls: list = []  # capped method-name trail; travels
        # on rate errors so the exact call sequence that hit the 429 is
        # visible in the one-line error (and the audit record)
        self._warned_low_budget = False   # one warning per run, not per call

    def quota_snapshot(self):
        return self._limiter.snapshot()

    def _run(self, request):
        if not self._limiter.try_acquire():
            raise QuotaExhausted(
                "service call budget exhausted for this window; last "
                f"calls: {', '.join(self._recent_calls[-20:])}",
                retry_at=self._limiter.snapshot().window_resets_at)
        method_name = _METHODS[type(request).__name__]
        self._recent_calls.append(method_name)
        del self._recent_calls[:-50]              # cap the trail
        method = getattr(self._sdk, method_name)
        started = time.perf_counter()
        try:
            resp = method(request)
            snap = self._limiter.snapshot()
            _log.info("gateway call %s (%s/%s this window, %.0f ms)",
                      method_name, snap.used_calls,
                      snap.effective_limit,
                      (time.perf_counter() - started) * 1000)
            left = snap.left
            if left <= 5 and not self._warned_low_budget:
                self._warned_low_budget = True
                _log.warning(
                    "call budget nearly exhausted (%s left this window) — "
                    "this is OUR limiter, not the cloud's: raise "
                    "SERVICE_CALL_BUDGET (cloud cap ~90 per 5 min) for "
                    "large batches, or let the run wait the window out", left)
            return resp
        except ServiceResponseException as e:
            if e.status_code == 429 or str(e.error_code or "").startswith("APIGW"):
                self._limiter.report_external_throttle()
                _log.warning("cloud throttle %s — our limit now %s",
                             e.error_code,
                             self._limiter.snapshot().effective_limit)
                raise CloudThrottled(
                    f"cloud throttled: {e.error_code} {e.error_msg}; "
                    f"calls before throttle: "
                    f"{', '.join(self._recent_calls[-20:])}",
                    retry_at=self._limiter.snapshot().window_resets_at) from e
            raise CloudError(f"{e.status_code}: {e.error_code} {e.error_msg}") from e
        except SdkException as e:
            raise CloudError(str(e)) from e

    def _paged(self, make_request, attr, limit, convert):
        """Marker pagination shared by the list endpoints: request full
        pages of `limit`, follow `marker` (the id of the last item of the
        last page) while pages come back full, stop at the first short
        page — so small estates still spend exactly one call."""
        out = []
        marker = None
        while True:
            resp = self._run(make_request(marker))
            page = getattr(resp, attr) or []
            out.extend(convert(item) for item in page)
            if len(page) < limit:
                return out
            marker = page[-1].id

    # -- SgReader --
    def list_security_groups(self) -> list:
        def to_sg(sg):
            self._sg_name_to_id[sg.name] = sg.id
            return CloudSg(id=sg.id, name=sg.name,
                           description=sg.description or "")
        return self._paged(
            lambda marker: ListSecurityGroupsRequest(limit=_SG_PAGE,
                                                     marker=marker),
            "security_groups", _SG_PAGE, to_sg)

    def list_rules(self, sg_id: str) -> list:
        return self._paged(
            lambda marker: NeutronListSecurityGroupRulesRequest(
                security_group_id=sg_id, limit=_RULE_PAGE, marker=marker),
            "security_group_rules", _RULE_PAGE, self._to_cloud_rule)

    def inventory(self) -> Inventory:
        """The WHOLE account in two paged call families (the big rate
        saver): neutron_list_security_groups embeds each SG's rules, and
        one unfiltered list_ports yields membership (port.security_
        groups) plus the IP→NIC index (fixed_ips/dns_assignment) —
        replacing the 1 + 2N (+ per-100-IP) reads of the fallback."""
        sgs, rules = [], {}
        attached: dict = {}
        nics_by_ip: dict = {}

        def to_sg_with_rules(sg):
            sgs.append(CloudSg(id=sg.id, name=sg.name,
                               description=sg.description or ""))
            self._sg_name_to_id[sg.name] = sg.id
            rules[sg.id] = [self._to_cloud_rule(r, sg_id=sg.id)
                            for r in (sg.security_group_rules or [])]

        def to_port(p):
            ips = [f.ip_address for f in (p.fixed_ips or [])]
            nic = CloudNic(port_id=p.id, ip=ips[0] if ips else "",
                           vm_name=_vm_name(p))
            for sg_id in (p.security_groups or []):
                attached.setdefault(sg_id, []).append(nic)
            for ip in ips:
                if "." in ip:              # IPv4 only — model is v4-only
                    nics_by_ip.setdefault(ip, []).append(nic)

        self._paged(
            lambda marker: NeutronListSecurityGroupsRequest(
                limit=_SG_PAGE, marker=marker),
            "security_groups", _SG_PAGE, to_sg_with_rules)
        self._paged(
            lambda marker: ListPortsRequest(limit=_PORT_PAGE, marker=marker),
            "ports", _PORT_PAGE, to_port)
        # every sg id keyed in rules/attached: Snapshot's own invariant now
        return Inventory(snapshot=Snapshot(sgs=tuple(sgs), rules=rules,
                                           attached=attached),
                         nics_by_ip=nics_by_ip)

    # -- MembershipReader --
    def find_nics_by_ip(self, ips: list) -> dict:
        # No marker loop here on purpose: each chunk's result set is
        # bounded by construction — the response can only contain ports
        # whose IP is one of the (at most 100) queried addresses — so a
        # single request per chunk is complete in practice.
        found = {ip: [] for ip in ips}
        for i in range(0, len(ips), 100):        # URL-length safety chunks
            chunk = ips[i:i + 100]               # fixed_ips is 'multi': one
            resp = self._run(ListPortsRequest(   # repeated param per ip
                fixed_ips=[f"ip_address={ip}" for ip in chunk]))
            for p in resp.ports or []:
                for fip in p.fixed_ips or []:
                    if fip.ip_address in found:
                        found[fip.ip_address].append(
                            CloudNic(port_id=p.id, ip=fip.ip_address,
                                     vm_name=_vm_name(p)))
        return found

    def list_attached_nics(self, sg_id: str) -> list:
        def to_nic(p):
            return CloudNic(port_id=p.id,
                            ip=p.fixed_ips[0].ip_address if p.fixed_ips else "",
                            vm_name=_vm_name(p))
        return self._paged(
            lambda marker: ListPortsRequest(security_groups=[sg_id],
                                            limit=_PORT_PAGE, marker=marker),
            "ports", _PORT_PAGE, to_nic)

    # -- SgWriter --
    def create_security_group(self, name: str, description: str) -> CloudSg:
        resp = self._run(CreateSecurityGroupRequest(body=CreateSecurityGroupRequestBody(
            security_group=CreateSecurityGroupOption(name=name))))
        sg = resp.security_group
        self._sg_name_to_id[sg.name] = sg.id
        if description:              # native create takes no description
            self.update_security_group_description(sg.id, description)
        return CloudSg(id=sg.id, name=sg.name, description=description)

    def update_security_group_description(self, sg_id: str,
                                          description: str) -> None:
        self._run(NeutronUpdateSecurityGroupRequest(
            security_group_id=sg_id,
            body=NeutronUpdateSecurityGroupRequestBody(security_group=
                NeutronUpdateSecurityGroupOption(description=description))))

    def delete_security_group(self, sg_id: str) -> None:
        self._run(DeleteSecurityGroupRequest(security_group_id=sg_id))

    # -- SgRuleWriter --
    def create_rule(self, sg_id: str, rule: Rule) -> CloudRule:
        lo, hi = _bounds(rule.ports)
        if hasattr(rule.remote, "name"):
            remote_group_id = self._resolve_remote_id(rule.remote.name)
            remote = {"remote_group_id": remote_group_id}
        else:
            remote = {"remote_ip_prefix": rule.remote.cidr}
        resp = self._run(NeutronCreateSecurityGroupRuleRequest(body=
            NeutronCreateSecurityGroupRuleRequestBody(security_group_rule=
                NeutronCreateSecurityGroupRuleOption(
                    security_group_id=sg_id,
                    direction=rule.direction,
                    protocol=None if rule.protocol == "all" else rule.protocol,
                    port_range_min=lo, port_range_max=hi,
                    ethertype="IPv4", **remote))))
        return self._to_cloud_rule(resp.security_group_rule)

    def delete_rule(self, rule_id: str) -> None:
        self._run(NeutronDeleteSecurityGroupRuleRequest(
            security_group_rule_id=rule_id))

    def _resolve_remote_id(self, name: str) -> str:
        """The API wants a remote SG UUID; our rules carry group NAMES.
        Resolve via cache, refreshed by listing when unknown (apply
        ordering guarantees the remote SG exists by create time)."""
        if name not in self._sg_name_to_id:
            self.list_security_groups()          # refresh cache
        if name not in self._sg_name_to_id:
            raise CloudError(f"unknown remote group {name!r}")
        return self._sg_name_to_id[name]

    # -- NicBinder (update-port pattern, proven in the sibling service) --
    def attach_nic(self, sg_id: str, port_id: str) -> None:
        port = self._get_port(port_id)
        sgs = list(port.security_groups or [])
        if sg_id in sgs:
            return
        self._set_port_sgs(port_id, sgs + [sg_id])

    def detach_nic(self, sg_id: str, port_id: str) -> None:
        port = self._get_port(port_id)
        sgs = list(port.security_groups or [])
        if sg_id not in sgs:                     # symmetric with attach:
            return                               # saves a budget slot
        self._set_port_sgs(port_id, [s for s in sgs if s != sg_id])

    def _get_port(self, port_id: str):
        resp = self._run(ListPortsRequest(id=[port_id]))
        ports = resp.ports or []
        if not ports:
            raise CloudError(f"port {port_id} not found")
        return ports[0]

    def _set_port_sgs(self, port_id: str, security_groups: list) -> None:
        self._run(UpdatePortRequest(port_id=port_id,
                                    body=UpdatePortRequestBody(port=
                                        UpdatePortOption(security_groups=
                                                         security_groups))))

    def _to_cloud_rule(self, r: NeutronSecurityGroupRule,
                       sg_id: "str | None" = None) -> CloudRule:
        # sg_id: the parent SG for embedded rules (their JSON form does
        # not carry security_group_id); None = standalone listing.
        protocol = getattr(r, "protocol", None) or None
        lo = getattr(r, "port_range_min", None)
        hi = getattr(r, "port_range_max", None)
        if protocol in ("icmp", "icmpv6"):
            # min/max carry ICMP type/code on the wire (e.g. 8/0 for
            # ping) — NOT ports; canonicalising them would crash on
            # reversed ranges and never match Rule.identity().
            ports = None
        elif lo is not None and hi is not None:
            ports = parse_ports(f"{lo}-{hi}")
        else:
            ports = str(lo) if lo is not None else None
        return CloudRule(id=r.id, sg_id=sg_id or r.security_group_id,
                         direction=r.direction, protocol=protocol,
                         ports=ports,
                         remote_group_id=getattr(r, "remote_group_id", None),
                         remote_ip_prefix=getattr(r, "remote_ip_prefix", None))


def _vm_name(p) -> "str | None":
    """Port has no direct hostname attribute; the neutron dns_assignment
    list carries it (dict entries with 'hostname' in this SDK version —
    checked defensively since models have spelled this differently)."""
    for entry in (getattr(p, "dns_assignment", None) or []):
        if isinstance(entry, dict):
            name = entry.get("hostname")
        else:
            name = getattr(entry, "hostname", None)
        if name:
            return name
    return None


def _bounds(ports: "str | None"):
    """Neutron rules carry port_range_min/max. Engine rules are
    single-range (the plan engine expands multi-entry specs), so this
    is the identity envelope."""
    if ports is None:
        return None, None
    return ports.bounds(ports.entries[0])
