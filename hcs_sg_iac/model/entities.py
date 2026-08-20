# hcs_sg_iac/model/entities.py
"""Domain entities. The model IS the schema: from-dict constructors
validate everything and report ALL violations into the Report."""

import ipaddress
import re
from dataclasses import dataclass
from typing import cast

from hcs_sg_iac.model.portset import PortError, PortSet, parse_ports
from hcs_sg_iac.model.remote import Remote, parse_remote
from hcs_sg_iac.model.report import Report

GROUP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6", "all")
_NO_PORTS_PROTOCOLS = ("icmp", "icmpv6", "all")


@dataclass(frozen=True)
class Member:
    ip: str


@dataclass(frozen=True)
class Group:
    name: str
    description: str
    members: tuple  # tuple[Member, ...]


@dataclass(frozen=True)
class Rule:
    direction: str  # "ingress" | "egress"
    protocol: str
    ports: "PortSet | None"  # canonical form; None = all ports
    remote: Remote

    def __post_init__(self):
        # hand-constructed rules (tests, importer) carry plain strings;
        # the grammar ops (.entries/.bounds) live on PortSet
        if isinstance(self.ports, str):
            object.__setattr__(self, "ports", PortSet(self.ports))

    def identity(self) -> tuple:
        return (self.direction, self.protocol, self.ports, self.remote)


@dataclass(frozen=True)
class RulesFile:
    security_group: str
    ingress: tuple  # tuple[Rule, ...]
    egress: tuple
    ingress_managed: bool  # section present (even if [])
    egress_managed: bool


@dataclass(frozen=True)
class DesiredState:
    groups: dict  # name -> Group
    rules: dict  # name -> RulesFile (only groups WITH a rules file)


def _looks_like_ip(name: str) -> bool:
    try:
        if "/" in name:
            ipaddress.ip_network(name, strict=False)
        else:
            ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def parse_group(d, where: str, report: Report) -> Group | None:
    """Parse one groups/<name>.yaml document (a plain dict)."""
    if not isinstance(d, dict):
        report.error(where, "group file must be a YAML mapping")
        return None
    name = d.get("name")
    if not isinstance(name, str):
        report.error(where, f"name must be a string, got {name!r}")
        name = None
    elif _looks_like_ip(name):
        report.error(where, f"name {name!r} must not look like an IP/CIDR")
        name = None
    elif not GROUP_NAME_RE.fullmatch(name):
        report.error(
            where, f"name {name!r} must match {GROUP_NAME_RE.pattern}"
        )
        name = None
    description = d.get("description", "")
    ok = True
    if not isinstance(description, str):
        report.error(where, "description must be a string")
        description = ""
        ok = False
    members, seen = [], set()
    raw_members = d.get("members", [])
    if not isinstance(raw_members, list):
        report.error(where, "members must be a list")
        raw_members = []
        ok = False
    for i, m in enumerate(raw_members):
        mwhere = f"{where}: members[{i}]"
        if not isinstance(m, dict) or "ip" not in m:
            report.error(mwhere, "member must be a mapping with an 'ip' key")
            ok = False
            continue
        ip = m["ip"]
        if not isinstance(ip, str):
            report.error(mwhere, "ip must be a string")
            ok = False
            continue
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            report.error(mwhere, f"ip {ip!r} is not a valid address")
            ok = False
            continue
        if ip_obj.version != 4:
            report.error(mwhere, f"ip {ip!r}: IPv6 is not supported")
            ok = False
            continue
        ip = str(
            ip_obj
        )  # canonical spelling: duplicate check is address-based
        if ip in seen:
            report.error(mwhere, f"duplicate ip {ip} in group")
            ok = False
            continue
        seen.add(ip)
        members.append(Member(ip=ip))
    if name is None:
        ok = False
    return (
        Group(
            name=cast(str, name),
            description=description,
            members=tuple(members),
        )
        if ok
        else None
    )


def _parse_rule_items(
    raw,
    where: str,
    report: Report,
    label: str,
    direction: str,
    remote_key: str,
):
    """Parse ONE list of rule mappings (shared by the flat rules file
    and the per-direction files). Returns (rules, ok)."""
    rules, seen, ok = [], set(), True
    for i, rd in enumerate(raw):
        rwhere = f"{where}: {label}[{i}]"
        if not isinstance(rd, dict):
            report.error(rwhere, "rule must be a mapping")
            ok = False
            continue
        remote_raw = rd.get(remote_key)
        if not isinstance(remote_raw, str) or not remote_raw:
            report.error(
                rwhere, f"{remote_key} is required (group name or CIDR)"
            )
            ok = False
            continue
        try:
            remote = parse_remote(remote_raw)
        except ValueError:
            report.error(
                rwhere, f"{remote_key} {remote_raw!r} is not a valid CIDR"
            )
            ok = False
            continue
        protocol = rd.get("protocol")
        if protocol not in PROTOCOLS:
            report.error(
                rwhere,
                f"protocol must be one of {PROTOCOLS}, got {protocol!r}",
            )
            ok = False
            continue
        ports_raw = rd.get("ports")
        if protocol in _NO_PORTS_PROTOCOLS and ports_raw not in (None, "", []):
            report.error(rwhere, f"{protocol} rules must not have ports")
            ok = False
            continue
        try:
            ports = parse_ports(ports_raw, field="ports")
        except PortError as e:
            report.error(rwhere, str(e))
            ok = False
            continue
        rule = Rule(
            direction=direction, protocol=protocol, ports=ports, remote=remote
        )
        if rule.identity() in seen:
            report.error(
                rwhere,
                f"duplicate {direction} rule "
                f"(protocol={protocol}, ports={ports}, "
                f"{remote_key}={remote_raw})",
            )
            ok = False
            continue
        seen.add(rule.identity())
        rules.append(rule)
    return tuple(rules), ok


def parse_rule_list(
    raw, where: str, report: Report, direction: str, remote_key: str
) -> tuple:
    """Parse a bare list of rules — the per-direction file layout
    (security-groups/<name>/ingress|egress.yaml). An empty/null document
    is the remove-all guidance error ([] is the explicit empty list)."""
    if raw is None:
        report.error(
            where,
            f"{direction} file is empty or contains no document "
            f"(use [] for remove-all, or delete the file to leave "
            f"the direction unmanaged)",
        )
        return ()
    if not isinstance(raw, list):
        report.error(where, f"{direction} file must be a list of rules")
        return ()
    return _parse_rule_items(
        raw, where, report, direction, direction, remote_key
    )[0]
