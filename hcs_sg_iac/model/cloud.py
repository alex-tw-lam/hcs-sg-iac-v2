# hcs_sg_iac/model/cloud.py
"""Value types describing a point-in-time cloud observation.

These are OUR nouns (nic, sg, rule) — adapters translate SDK objects
into these; nothing inner ever sees the SDK. Snapshot carries the
invariant every reader needs (each sg id keyed in rules/attached) in
__post_init__; Inventory bundles a Snapshot with the member-IP NIC
index into the single type behind every inventory()/snapshot-file
parse. snapshot_to_json/from_json (de)serialise the file format of
`hcs-sg snapshot` and the input of offline planning."""

import json
from dataclasses import asdict, dataclass, field
from typing import Literal

from hcs_sg_iac.model.common import RemoteCidr, RemoteGroup


@dataclass(frozen=True)
class CloudSg:
    id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class CloudRule:
    id: str
    sg_id: str
    direction: "Literal['ingress', 'egress']"
    protocol: str | None  # None = all protocols
    ports: "str | None"  # canonical PortSet form; None = all ports
    remote_group_id: str | None
    remote_ip_prefix: str | None

    def identity(self, id_to_name: "dict | None" = None) -> tuple:
        """The join key against code rules — the SAME tuple shape as
        Rule.identity(). An unset remote is 0.0.0.0/0 (the API default
        when unset); a remote our v4-only model cannot express (e.g.
        IPv6) becomes an identity no code rule can ever match — an
        honest delete."""
        remote: RemoteGroup | RemoteCidr
        if self.remote_group_id:
            remote = RemoteGroup(
                name=(id_to_name or {}).get(
                    self.remote_group_id, self.remote_group_id
                )
            )
        elif self.remote_ip_prefix:
            try:
                remote = RemoteCidr(cidr=self.remote_ip_prefix)
            except ValueError:
                remote = RemoteGroup(
                    name=f"unrepresentable-remote({self.remote_ip_prefix})"
                )
        else:
            remote = RemoteCidr(cidr="0.0.0.0/0")
        return (self.direction, self.protocol or "all", self.ports, remote)


@dataclass(frozen=True)
class CloudNic:
    port_id: str
    ip: str
    vm_name: str | None = None


@dataclass(frozen=True)
class Snapshot:
    sgs: tuple = field(default_factory=tuple)  # tuple[CloudSg, ...]
    rules: dict = field(default_factory=dict)  # sg_id -> [CloudRule]
    attached: dict = field(default_factory=dict)  # sg_id -> [CloudNic]

    def __post_init__(self):
        # The invariant the readers used to maintain with per-adapter
        # normalisation loops: EVERY sg id is keyed in rules/attached
        # (an empty list when there is nothing) — so .get(id, []) and
        # [id] are both safe downstream.
        rules = dict(self.rules)
        attached = dict(self.attached)
        for sg in self.sgs:
            rules.setdefault(sg.id, [])
            attached.setdefault(sg.id, [])
        object.__setattr__(self, "rules", rules)
        object.__setattr__(self, "attached", attached)


@dataclass(frozen=True)
class Inventory:
    """One observed cloud: the Snapshot triples plus the member-IP NIC
    index (what find_nics_by_ip returned) — the type every
    inventory()-capable gateway and every snapshot-file parse hands
    back, instead of a bare (Snapshot, dict) tuple."""

    snapshot: Snapshot = field(default_factory=Snapshot)
    nics_by_ip: dict = field(default_factory=dict)  # ip -> [CloudNic]


def snapshot_to_json(
    sgs, rules: dict, attached: dict, nics_by_ip: dict
) -> str:
    """Serialise an inventory: the Snapshot triples plus the member-IP
    NIC index (what find_nics_by_ip returned) — offline resolution
    needs it."""
    return json.dumps(
        {
            "sgs": [asdict(s) for s in sgs],
            "rules": {
                sid: [asdict(r) for r in rs] for sid, rs in rules.items()
            },
            "attached": {
                sid: [asdict(n) for n in ns] for sid, ns in attached.items()
            },
            "nics_by_ip": {
                ip: [asdict(n) for n in ns] for ip, ns in nics_by_ip.items()
            },
        },
        indent=2,
    )


def snapshot_from_json(text: str) -> Inventory:
    """Parse a snapshot file -> Inventory."""
    d = json.loads(text)
    sgs = tuple(CloudSg(**s) for s in d.get("sgs", []))
    rules = {
        sid: [CloudRule(**r) for r in rs]
        for sid, rs in d.get("rules", {}).items()
    }
    attached = {
        sid: [CloudNic(**n) for n in ns]
        for sid, ns in d.get("attached", {}).items()
    }
    nics = {
        ip: [CloudNic(**n) for n in ns]
        for ip, ns in d.get("nics_by_ip", {}).items()
    }
    return Inventory(
        snapshot=Snapshot(sgs=sgs, rules=rules, attached=attached),
        nics_by_ip=nics,
    )
