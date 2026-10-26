# hcs_sg_iac/snapshot.py
"""Value types describing a point-in-time cloud observation.

These are OUR nouns (nic, sg, rule) — adapters translate SDK objects
into these; nothing inner ever sees the SDK. Snapshot carries the
invariant every reader needs (each sg id keyed in rules/attached); the
Inventory bundle adds the member-IP NIC index behind every
inventory()/snapshot-file parse. snapshot_to_json/from_json
(de)serialise the file format of `hcs-sg snapshot` and the input of
offline planning."""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from hcs_sg_iac.entities import RemoteCidr, RemoteGroup


class CloudSg(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    description: str = ""


class CloudRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    sg_id: str
    direction: "Literal['ingress', 'egress']"
    protocol: "str | None"  # None = all protocols
    ports: "str | None"  # canonical PortSet form; None = all ports
    remote_group_id: "str | None"
    remote_ip_prefix: "str | None"

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


class CloudNic(BaseModel):
    model_config = ConfigDict(frozen=True)

    port_id: str
    ip: str
    vm_name: "str | None" = None


class Snapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    sgs: "tuple[CloudSg, ...]" = ()
    rules: dict = {}  # sg_id -> [CloudRule]
    attached: dict = {}  # sg_id -> [CloudNic]

    @model_validator(mode="before")
    @classmethod
    def _key_every_sg(cls, d):
        """The invariant the readers used to maintain with per-adapter
        normalisation loops: EVERY sg id is keyed in rules/attached (an
        empty list when there is nothing) — so .get(id, []) and [id]
        are both safe downstream."""
        if not isinstance(d, dict):
            return d
        d = dict(d)
        rules = dict(d.get("rules") or {})
        attached = dict(d.get("attached") or {})
        for sg in d.get("sgs") or ():
            rules.setdefault(sg.id, [])
            attached.setdefault(sg.id, [])
        d["rules"], d["attached"] = rules, attached
        return d


class Inventory(BaseModel):
    """One observed cloud: the Snapshot triples plus the member-IP NIC
    index (what find_nics_by_ip returned) — the type every
    inventory()-capable gateway and every snapshot-file parse hands
    back, instead of a bare (Snapshot, dict) tuple."""

    model_config = ConfigDict(frozen=True)

    snapshot: Snapshot = Snapshot()
    nics_by_ip: dict = {}  # ip -> [CloudNic]


def snapshot_to_json(
    sgs, rules: dict, attached: dict, nics_by_ip: dict
) -> str:
    """Serialise an inventory: the Snapshot triples plus the member-IP
    NIC index (what the live read returned) — offline resolution
    needs it."""
    return json.dumps(
        {
            "sgs": [s.model_dump() for s in sgs],
            "rules": {
                sid: [r.model_dump() for r in rs] for sid, rs in rules.items()
            },
            "attached": {
                sid: [n.model_dump() for n in ns] for sid, ns in attached.items()
            },
            "nics_by_ip": {
                ip: [n.model_dump() for n in ns] for ip, ns in nics_by_ip.items()
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
