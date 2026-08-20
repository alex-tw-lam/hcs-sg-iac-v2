# hcs_sg_iac/adapters/snapshot_gateway.py
"""Read-only gateway replaying a snapshot file: zero cloud calls.
Powers offline pre-work — resolve + plan against `--snapshot` without
credentials. The write protocols are deliberately ABSENT: the CLI pairs
this reader with the real gateway when --yes writes land."""
from pathlib import Path

from hcs_sg_iac.model.cloud import Inventory, snapshot_from_json


class SnapshotGateway:
    def __init__(self, path):
        self._inv = snapshot_from_json(Path(path).read_text(encoding="utf-8"))

    # -- SgReader --
    def list_security_groups(self) -> list:
        return list(self._inv.snapshot.sgs)

    def list_rules(self, sg_id: str) -> list:
        return list(self._inv.snapshot.rules.get(sg_id, []))

    # -- MembershipReader --
    def find_nics_by_ip(self, ips: list) -> dict:
        return {ip: list(self._inv.nics_by_ip.get(ip, []))
                for ip in ips}

    def list_attached_nics(self, sg_id: str) -> list:
        return list(self._inv.snapshot.attached.get(sg_id, []))

    def inventory(self) -> Inventory:
        """Fast path for read_snapshot: everything is already in memory
        (Snapshot.__post_init__ guarantees every sg id keyed)."""
        return self._inv
