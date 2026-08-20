# tests/model/test_cloud.py
from hcs_sg_iac.model.cloud import (CloudNic, CloudRule, CloudSg, Snapshot,
                                     snapshot_from_json, snapshot_to_json)


def test_snapshot_defaults_are_isolated():
    s1, s2 = Snapshot(), Snapshot()
    s1.rules["x"] = []
    assert s2.rules == {}


def test_snapshot_json_roundtrip():
    """The `hcs-sg snapshot` file format: every field of every value
    type survives a to/from roundtrip untouched."""
    snap = Snapshot(
        sgs=(CloudSg(id="s1", name="web", description="d"),),
        rules={"s1": [CloudRule(id="r1", sg_id="s1", direction="ingress",
                                protocol=None, ports=None,
                                remote_group_id="s1",
                                remote_ip_prefix=None)]},
        attached={"s1": [CloudNic(port_id="p1", ip="10.0.1.1",
                                  vm_name="vm-a")]})
    nics = {"10.0.1.1": [CloudNic(port_id="p1", ip="10.0.1.1",
                                  vm_name="vm-a")]}
    text = snapshot_to_json(snap.sgs, snap.rules, snap.attached, nics)
    snap2, nics2 = snapshot_from_json(text)
    assert snap2 == snap
    assert nics2 == nics
