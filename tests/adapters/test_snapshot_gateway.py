# tests/adapters/test_snapshot_gateway.py
"""The read-only replay gateway behind `--snapshot`: reads come from
the file (zero cloud calls), writers are absent by design."""
import pytest

from hcs_sg_iac.adapters.snapshot_gateway import SnapshotGateway
from hcs_sg_iac.model.cloud import (CloudNic, CloudSg, snapshot_from_json,
                                     snapshot_to_json)


def _write_snapshot(tmp_path, sgs, rules=None, attached=None, nics=None):
    path = tmp_path / "snapshot.json"
    path.write_text(snapshot_to_json(sgs, rules or {}, attached or {},
                                     nics or {}))
    return path


def test_replays_every_read_from_the_file(tmp_path):
    path = _write_snapshot(
        tmp_path,
        sgs=(CloudSg(id="sg-1", name="web", description="d"),),
        attached={"sg-1": [CloudNic(port_id="p1", ip="10.0.1.1")]},
        nics={"10.0.1.1": [CloudNic(port_id="p1", ip="10.0.1.1")]})
    gw = SnapshotGateway(path)
    assert [s.name for s in gw.list_security_groups()] == ["web"]
    assert gw.list_rules("sg-1") == []            # no rules recorded
    assert gw.list_attached_nics("sg-1")[0].port_id == "p1"
    found = gw.find_nics_by_ip(["10.0.1.1", "10.9.9.9"])
    assert found["10.0.1.1"][0].port_id == "p1"   # offline resolution
    assert found["10.9.9.9"] == []                # unknown ip -> empty


def test_write_protocols_are_absent_by_design(tmp_path):
    path = _write_snapshot(tmp_path, sgs=())
    gw = SnapshotGateway(path)
    assert not hasattr(gw, "create_security_group")
    with pytest.raises(AttributeError):
        gw.delete_rule("r1")
