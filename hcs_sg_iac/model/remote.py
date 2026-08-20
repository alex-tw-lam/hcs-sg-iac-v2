# hcs_sg_iac/model/remote.py
"""The far end of a rule: another group, or a CIDR.

Group names can never look like an IP/CIDR (charset rule in entities.py),
so a plain string is unambiguous.

IPv4 only, and RemoteCidr is canonical regardless of construction site:
the plan engine builds RemoteCidr directly from cloud-returned strings,
which must compare equal to the parsed-from-YAML equivalent.
"""

import ipaddress
from dataclasses import dataclass


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


def parse_remote(value: str) -> Remote:
    if not value.strip():
        raise ValueError(f"empty remote: {value!r}")
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 is not supported: {value!r}")
        return RemoteCidr(cidr=str(net))  # raises ValueError if malformed
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return RemoteGroup(name=value)
    if ip.version != 4:
        raise ValueError(f"IPv6 is not supported: {value!r}")
    return RemoteCidr(cidr=str(ipaddress.ip_network(f"{ip}/32")))
