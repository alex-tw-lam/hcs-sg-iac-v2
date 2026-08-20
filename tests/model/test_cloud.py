# tests/model/test_cloud.py
from hcs_sg_iac.model.cloud import Snapshot


def test_snapshot_defaults_are_isolated():
    s1, s2 = Snapshot(), Snapshot()
    s1.rules["x"] = []
    assert s2.rules == {}
