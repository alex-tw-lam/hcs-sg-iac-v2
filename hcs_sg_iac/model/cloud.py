# hcs_sg_iac/model/cloud.py
"""Value types describing a point-in-time cloud snapshot.

These are OUR nouns (nic, sg, rule) — adapters translate SDK objects
into these; nothing inner ever sees the SDK. snapshot_to_json /
snapshot_from_json (de)serialise a whole inventory — the file format of
`hcs-sg snapshot` and the input of offline planning (`--snapshot`)."""
import json
from dataclasses import asdict, dataclass, field
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


def snapshot_to_json(sgs, rules: dict, attached: dict, nics_by_ip: dict) -> str:
    """Serialise an inventory: the Snapshot triples plus the member-IP
    NIC index (what find_nics_by_ip returned) — offline resolution
    needs it."""
    return json.dumps({
        "sgs": [asdict(s) for s in sgs],
        "rules": {sid: [asdict(r) for r in rs]
                  for sid, rs in rules.items()},
        "attached": {sid: [asdict(n) for n in ns]
                     for sid, ns in attached.items()},
        "nics_by_ip": {ip: [asdict(n) for n in ns]
                       for ip, ns in nics_by_ip.items()},
    }, indent=2)


def snapshot_from_json(text: str) -> "tuple[Snapshot, dict]":
    """Parse a snapshot file -> (Snapshot, nics_by_ip)."""
    d = json.loads(text)
    sgs = tuple(CloudSg(**s) for s in d.get("sgs", []))
    rules = {sid: [CloudRule(**r) for r in rs]
             for sid, rs in d.get("rules", {}).items()}
    attached = {sid: [CloudNic(**n) for n in ns]
                for sid, ns in d.get("attached", {}).items()}
    nics = {ip: [CloudNic(**n) for n in ns]
            for ip, ns in d.get("nics_by_ip", {}).items()}
    return Snapshot(sgs=sgs, rules=rules, attached=attached), nics
