# hcs_sg_iac/model/cloud.py
"""Value types describing a point-in-time cloud snapshot.

These are OUR nouns (nic, sg, rule) — adapters translate SDK objects
into these; nothing inner ever sees the SDK.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class CloudSg:
    id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class CloudRule:
    id: str
    sg_id: str
    direction: str                 # "ingress" | "egress"
    protocol: Optional[str]        # None = all protocols
    ports: Optional[str]           # canonical form; None = all ports
    remote_group_id: Optional[str]
    remote_ip_prefix: Optional[str]


@dataclass(frozen=True)
class CloudNic:
    port_id: str
    ip: str
    vm_name: Optional[str] = None


@dataclass(frozen=True)
class Snapshot:
    sgs: tuple = field(default_factory=tuple)          # tuple[CloudSg, ...]
    rules: dict = field(default_factory=dict)          # sg_id -> [CloudRule]
    attached: dict = field(default_factory=dict)       # sg_id -> [CloudNic]
