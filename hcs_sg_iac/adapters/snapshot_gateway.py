# hcs_sg_iac/adapters/snapshot_gateway.py
"""Read-only gateway replaying a snapshot file: zero cloud calls.
Powers offline pre-work — resolve + plan against `--snapshot` without
credentials. The write protocols are deliberately ABSENT: the CLI pairs
this reader with the real gateway when --yes writes land."""
from pathlib import Path

from hcs_sg_iac.model.cloud import Snapshot, snapshot_from_json


class SnapshotGateway:
    def __init__(self, path):
        self._snap, self._nics_by_ip = snapshot_from_json(
            Path(path).read_text(encoding="utf-8"))

    # -- SgReader --
    def list_security_groups(self) -> list:
        return list(self._snap.sgs)

    def list_rules(self, sg_id: str) -> list:
        return list(self._snap.rules.get(sg_id, []))

    # -- MembershipReader --
    def find_nics_by_ip(self, ips: list) -> dict:
        return {ip: list(self._nics_by_ip.get(ip, [])) for ip in ips}

    def list_attached_nics(self, sg_id: str) -> list:
        return list(self._snap.attached.get(sg_id, []))

    def inventory(self) -> "tuple[Snapshot, dict]":
        """Fast path for read_snapshot: everything is already in memory
        (normalised so every sg id is keyed in rules/attached, matching
        the per-SG read loop's invariant)."""
        rules = {k: list(v) for k, v in self._snap.rules.items()}
        attached = {k: list(v) for k, v in self._snap.attached.items()}
        for sg in self._snap.sgs:
            rules.setdefault(sg.id, [])
            attached.setdefault(sg.id, [])
        return (Snapshot(sgs=tuple(self._snap.sgs), rules=rules,
                         attached=attached),
                {ip: list(nics) for ip, nics in self._nics_by_ip.items()})
