# hcs_sg_iac/entities.py
"""The desired-state vocabulary: the ports grammar, the remote ends of
a rule, the collect-all Report, and the YAML entities themselves.
Pydantic owns the types (frozen, coercing, equality); the loaders
collect EVERY violation into the Report with one line per problem —
validation never fails fast."""

import ipaddress
import re

from pydantic import (
    BaseModel,
    ConfigDict,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

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


class RemoteGroup(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str


class RemoteCidr(BaseModel):
    model_config = ConfigDict(frozen=True)

    cidr: str

    @field_validator("cidr", mode="before")
    @classmethod
    def _canonical_v4(cls, v):
        net = ipaddress.ip_network(v, strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 is not supported: {v!r}")
        return str(net)




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
    identity tuples) while owning the grammar ops."""

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


class _Range:
    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi


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
PROTOCOLS = ("tcp", "udp", "icmp", "all")
_NO_PORTS_PROTOCOLS = ("icmp", "all")


class Member(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip: str

    @field_validator("ip", mode="before")
    @classmethod
    def _valid_v4(cls, v):
        if not isinstance(v, str):
            raise ValueError("ip must be a string")
        try:
            addr = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"ip {v!r} is not a valid address") from None
        if addr.version != 4:
            raise ValueError(f"ip {v!r}: IPv6 is not supported")
        return str(addr)  # canonical spelling

    @model_validator(mode="before")
    @classmethod
    def _must_be_mapping_with_ip(cls, d):
        if not isinstance(d, dict) or "ip" not in d:
            raise ValueError("member must be a mapping with an 'ip' key")
        return d


class Group(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str = ""
    members: tuple[Member, ...] = ()

    @field_validator("name", mode="before")
    @classmethod
    def _name_shape(cls, v):
        if not isinstance(v, str):
            raise ValueError(f"name must be a string, got {v!r}")
        if looks_like_ip(v):
            raise ValueError(f"name {v!r} must not look like an IP/CIDR")
        if not GROUP_NAME_RE.fullmatch(v):
            raise ValueError(f"name {v!r} must match {GROUP_NAME_RE.pattern}")
        return v

    @field_validator("description", mode="before")
    @classmethod
    def _description_str(cls, v):
        if not isinstance(v, str):
            raise ValueError("description must be a string")
        return v

    @field_validator("members", mode="before")
    @classmethod
    def _members_list(cls, v):
        # the loader hands a YAML list, the importer a tuple — both are
        # fine; anything else is not
        if not isinstance(v, (list, tuple)):
            raise ValueError("members must be a list")
        return v

    @model_validator(mode="after")
    def _no_duplicate_ips(self):
        seen = set()
        for m in self.members:
            if m.ip in seen:
                raise ValueError(f"duplicate ip {m.ip} in group")
            seen.add(m.ip)
        return self


class Rule(BaseModel):
    # PortSet is a str subclass pydantic can't schema — the before
    # validator hands core an instance, and arbitrary_types_allowed
    # makes core accept it by isinstance
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    direction: str  # "ingress" | "egress"
    protocol: str
    ports: "PortSet | None" = None  # canonical form; None = all ports
    remote: "RemoteGroup | RemoteCidr"

    @field_validator("ports", mode="before")
    @classmethod
    def _coerce_portset(cls, v):
        # hand-constructed rules (tests, importer) carry plain strings;
        # the grammar ops (.entries/.bounds) live on PortSet — no
        # validation here, the rule loaders run parse_ports themselves
        if isinstance(v, str):
            return PortSet(v)
        return v

    def identity(self) -> tuple:
        return (self.direction, self.protocol, self.ports, self.remote)


class RulesFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    security_group: str
    ingress: "tuple[Rule, ...]" = ()
    egress: "tuple[Rule, ...]" = ()
    ingress_managed: bool  # section present (even if [])
    egress_managed: bool


class DesiredState(BaseModel):
    model_config = ConfigDict(frozen=True)

    groups: "dict[str, Group]" = {}  # name -> Group
    rules: "dict[str, RulesFile]" = {}  # only groups WITH a rules file


_GROUP_ADAPTER = TypeAdapter(Group)


def _msg(err) -> str:
    """One pydantic error -> the message line (custom ValueErrors carry
    the exact hand-written text)."""
    return err["msg"].removeprefix("Value error, ")


def _nested(err) -> str:
    """The nested part of a pydantic error location: list indices
    render as members[3] — exactly the loaders' where-format. A
    top-level field adds nothing (those report at file level)."""
    parts = list(err["loc"])
    for i, p in enumerate(parts):
        if isinstance(p, int):
            return parts[i - 1] + f"[{p}]" if i else f"[{p}]"
    return ""


def parse_group(d, where: str, report: Report) -> "Group | None":
    """Parse one groups/<name>.yaml document (a plain dict); every
    violation is collected, none fail fast."""
    if not isinstance(d, dict):
        report.error(where, "group file must be a YAML mapping")
        return None
    try:
        return _GROUP_ADAPTER.validate_python(d)
    except ValidationError as e:
        for err in e.errors():
            nested = _nested(err)
            report.error(f"{where}: {nested}" if nested else where, _msg(err))
        return None


class _RuleShape(BaseModel):
    """The protocol/ports half of one rule mapping (the remote half is
    resolved by the loader — its error text names the source/
    destination key, which is per-direction)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    protocol: str
    ports: object = None

    @field_validator("protocol", mode="before")
    @classmethod
    def _known_protocol(cls, v):
        if v not in PROTOCOLS:
            raise ValueError(
                f"protocol must be one of {PROTOCOLS}, got {v!r}"
            )
        return v


_RULE_SHAPE = TypeAdapter(_RuleShape)


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
        try:
            shape = _RULE_SHAPE.validate_python(rd)
        except ValidationError as e:
            for err in e.errors():
                report.error(rwhere, _msg(err))
            continue
        protocol, ports_raw = shape.protocol, shape.ports
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
