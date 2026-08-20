# hcs_sg_iac/adapters/snapshot_gateway.py
"""Read-only gateway replaying a snapshot file: zero cloud calls.
Powers offline pre-work — resolve + plan against a snapshot without
credentials. The write protocols are deliberately ABSENT: the CLI pairs
this reader with the real gateway when --yes writes land."""

from pathlib import Path

from hcs_sg_iac.model.cloud import Inventory, snapshot_from_json


class SnapshotGateway:
    def __init__(self, path):
        self._inv = snapshot_from_json(Path(path).read_text(encoding="utf-8"))

    def inventory(self) -> Inventory:
        """The one read seam: everything is already in memory."""
        return self._inv

    def find_nics_by_ip(self, ips: list) -> dict:
        return {ip: list(self._inv.nics_by_ip.get(ip, [])) for ip in ips}
