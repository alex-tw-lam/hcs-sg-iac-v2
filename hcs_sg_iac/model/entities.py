# hcs_sg_iac/model/entities.py
"""Domain entities. The model IS the schema: from-dict constructors
validate everything and report ALL violations into the Report."""

import ipaddress
import re
from dataclasses import dataclass
from typing import cast

from hcs_sg_iac.model.common import (
    Remote,
    Report,
    looks_like_ip,
    parse_remote,
)
from hcs_sg_iac.model.portset import PortError, PortSet, parse_ports

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


def parse_group(d, where: str, report: Report) -> Group | None:
    """Parse one groups/<name>.yaml document (a plain dict)."""
    if not isinstance(d, dict):
        report.error(where, "group file must be a YAML mapping")
        return None
    name = d.get("name")
    if not isinstance(name, str):
        report.error(where, f"name must be a string, got {name!r}")
        name = None
    elif looks_like_ip(name):
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


def parse_rule_list(
    raw, where: str, report: Report, direction: str, remote_key: str
) -> tuple:
    """Parse one direction file (security-groups/<name>/<direction>.yaml)
    — a bare list of rule mappings. An empty/null document is the
    remove-all guidance error ([] is the explicit empty list); every
    violation is collected, none fail fast."""
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
    rules, seen = [], set()
    for i, rd in enumerate(raw):
        rwhere = f"{where}: {direction}[{i}]"
        if not isinstance(rd, dict):
            report.error(rwhere, "rule must be a mapping")
            continue
        remote_raw = rd.get(remote_key)
        if not isinstance(remote_raw, str) or not remote_raw:
            report.error(
                rwhere, f"{remote_key} is required (group name or CIDR)"
            )
            continue
        try:
            remote = parse_remote(remote_raw)
        except ValueError:
            report.error(
                rwhere, f"{remote_key} {remote_raw!r} is not a valid CIDR"
            )
            continue
        protocol = rd.get("protocol")
        if protocol not in PROTOCOLS:
            report.error(
                rwhere,
                f"protocol must be one of {PROTOCOLS}, got {protocol!r}",
            )
            continue
        ports_raw = rd.get("ports")
        if protocol in _NO_PORTS_PROTOCOLS and ports_raw not in (None, "", []):
            report.error(rwhere, f"{protocol} rules must not have ports")
            continue
        try:
            ports = parse_ports(ports_raw, field="ports")
        except PortError as e:
            report.error(rwhere, str(e))
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
            continue
        seen.add(rule.identity())
        rules.append(rule)
    return tuple(rules)
