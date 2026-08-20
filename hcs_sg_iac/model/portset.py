# hcs_sg_iac/model/portset.py
"""Ports grammar — identical to Huawei multiport: "80", "22,443", "8000-9000".

Accepts str / int / list input, normalises to the canonical sorted+merged
PortSet. None (or empty input) means ALL ports. This module is the single
parser: model entities parse user input at construction, and the huawei
adapter translates wire port ranges back through it. PortSet owns the
grammar OPERATIONS too (sub-rule expansion, wire bounds) — previously
scattered as string surgery in plan.py and huawei_gateway.py.
"""

from dataclasses import dataclass

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

    ranges: list = []
    for raw in items:
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
        ranges.append(_Range(lo, hi))

    if not ranges:
        return None
    ranges.sort(key=lambda r: (r.lo, r.hi))
    merged: list = []
    for r in ranges:
        if merged and r.lo <= merged[-1].hi + 1:
            merged[-1] = _Range(merged[-1].lo, max(merged[-1].hi, r.hi))
        else:
            merged.append(r)
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
