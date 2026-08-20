# hcs_sg_iac/model/common.py
"""The model's leaf vocabulary in one file: the collect-all Report, the
domain errors (both rate errors carry a retry_at window deadline), and
the far end of a rule (another group, or a canonical v4 CIDR)."""

import ipaddress
from dataclasses import dataclass


class Report:
    """Collects EVERY violation (never fail-fast) with a `where`."""

    def __init__(self):
        self.errors: list = []
        self.warnings: list = []

    def error(self, where: str, message: str) -> None:
        self.errors.append(f"{where}: {message}")

    def warning(self, where: str, message: str) -> None:
        self.warnings.append(f"{where}: {message}")

    @property
    def ok(self) -> bool:
        return not self.errors


class CloudError(Exception):
    """Unretryable cloud/API failure (one clean line, no traceback)."""


class _RateLimited(Exception):
    """Shared shape: a retry deadline for wait-and-continue."""

    def __init__(self, message, retry_at=None):
        super().__init__(message)
        self.retry_at = retry_at


class QuotaExhausted(_RateLimited):
    """OUR limiter's window is spent (not the cloud's)."""


class CloudThrottled(_RateLimited):
    """The cloud itself throttled us (429): halve our slice."""


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
    like an IP/CIDR (charset rule in entities), so a plain string is
    unambiguous; a bare IP becomes its /32."""
    if not value.strip():
        raise ValueError(f"empty remote: {value!r}")
    if "/" in value or _looks_like_ip(value):
        return RemoteCidr(cidr=value)
    return RemoteGroup(name=value)


def _looks_like_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False
