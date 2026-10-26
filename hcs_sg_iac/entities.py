# hcs_sg_iac/entities.py
"""The desired-state vocabulary: the ports grammar, the remote ends of
a rule, the collect-all Report, and the YAML entities themselves. The
types ARE the schema: from-dict constructors validate everything and
report ALL violations into the Report."""

import ipaddress
import re
from dataclasses import dataclass
from typing import cast

# ---- the collect-all report ----


class Report:
    """Collects EVERY violation (never fail-fast) with a `where`."""

    def __init__(self):
        self.errors: list = []

    def error(self, where: str, message: str) -> None:
        self.errors.append(f"{where}: {message}")

    @property
    def ok(self) -> bool:
        return not self.errors


# ---- the far end of a rule: another group, or a canonical v4 CIDR ----


@dataclass(frozen=True)
class RemoteGroup:
    name: str


@dataclass(frozen=True)
class RemoteCidr:
    cidr: str

    def __post_init__(self):
        net = ipaddress.ip_network(self.cidr, strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 is not supported: {self.cidr!r}")
        object.__setattr__(self, "cidr", str(net))


Remote = RemoteGroup | RemoteCidr


def parse_remote(value: str):
    """Group name or IPv4 CIDR -> Remote. Group names can never look
    like an IP/CIDR (charset rule below), so a plain string is
    unambiguous; a bare IP becomes its /32."""
    if not value.strip():
        raise ValueError(f"empty remote: {value!r}")
    if "/" in value or looks_like_ip(value):
        return RemoteCidr(cidr=value)
    return RemoteGroup(name=value)


def looks_like_ip(value: str):
    """IP or CIDR shaped (group names can never be, by the charset rule
    below — so a plain string is unambiguous)."""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---- the ports grammar — identical to Huawei multiport ----
# "80", "22,443", "8000-9000". Accepts str / int / list input,
# normalises to the canonical sorted+merged PortSet. None (or empty
# input) means ALL ports. This is the single parser: the entities parse
# user input at construction, and the huawei adapter translates wire
# port ranges back through it. PortSet owns the grammar OPERATIONS too
# (sub-rule expansion, wire bounds).

_MAX_ENTRIES = 20


class PortError(Exception):
    pass


class PortSet(str):
    """A canonical ports spec. Subclasses str so it serialises, compares
    and displays as the canonical string everywhere (snapshot JSON,
    identity tuples, frame expectations) while owning the grammar ops."""

    __slots__ = ()

    @property
    def entries(self) -> "tuple[str, ...]":
        """Comma-separated entries, ranges intact — the plan engine's
        sub-rule expansion ("22,443" -> "22", "443"; "80-90" stays)."""
        return tuple(self.split(",")) if self else ()

    def bounds(self, entry: str) -> "tuple[int, int]":
        """(lo, hi) of ONE entry — the wire translation."""
        lo_s, _, hi_s = entry.partition("-")
        return int(lo_s), int(hi_s or lo_s)


@dataclass(frozen=True)
class _Range:
    lo: int
    hi: int


def _parse_entry(raw: str, field: str) -> _Range:
    """One ports entry ("80" | "8000-9000") -> _Range; PortError with
    the caller's field context."""
    raw = raw.strip()
    if not raw:
        raise PortError(f"{field}: empty entry in ports list")
    if "-" in raw:
        lo_s, hi_s = raw.split("-", 1)
        if not (lo_s.strip().isascii() and lo_s.strip().isdigit()) or not (
            hi_s.strip().isascii() and hi_s.strip().isdigit()
        ):
            raise PortError(f"{field}: bad port range {raw!r}")
        lo, hi = int(lo_s), int(hi_s)
    else:
        if not (raw.isascii() and raw.isdigit()):
            raise PortError(f"{field}: bad port {raw!r}")
        lo = hi = int(raw)
    if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
        raise PortError(f"{field}: port out of range 1-65535: {raw!r}")
    if lo > hi:
        raise PortError(f"{field}: reversed range {raw!r}")
    return _Range(lo, hi)


def _merge(ranges: list) -> list:
    """Sort and merge adjacent/overlapping ranges (the union)."""
    ranges.sort(key=lambda r: (r.lo, r.hi))
    merged: list = []
    for r in ranges:
        if merged and r.lo <= merged[-1].hi + 1:
            merged[-1] = _Range(merged[-1].lo, max(merged[-1].hi, r.hi))
        else:
            merged.append(r)
    return merged


def parse_ports(value, *, field: str = "ports") -> "PortSet | None":
    if value is None:
        return None
    if isinstance(value, bool):
        raise PortError(f"{field}: expected string/int/list, got bool")
    if isinstance(value, int):
        items = [str(value)]
    elif isinstance(value, (list, tuple)):
        items = [str(v) for v in value]
    elif isinstance(value, str):
        s = value.strip()
        items = s.split(",") if s else []
    else:
        raise PortError(
            f"{field}: expected string/int/list, got {type(value).__name__}"
        )
    if not items:
        return None
    merged = _merge([_parse_entry(raw, field) for raw in items])
    if len(merged) == 1 and merged[0].lo == 1 and merged[0].hi == 65535:
        return None  # full range is semantically all ports
    if len(merged) > _MAX_ENTRIES:
        raise PortError(
            f"{field}: at most {_MAX_ENTRIES} port entries "
            f"(Huawei multiport cap), got {len(merged)}"
        )
    return PortSet(
        ",".join(
            str(r.lo) if r.lo == r.hi else f"{r.lo}-{r.hi}" for r in merged
        )
    )


# ---- the entities ----

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
