# tests/test_drift.py
"""Drift diff: every change kind reports its line; the --json shape is
Liquibase-diff; identical snapshots are empty."""

from hcs_sg_iac.cli.render import render_drift_lines
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg, Snapshot
from hcs_sg_iac.usecases.drift import diff_inventory


def _snap(sgs=(), rules=None, attached=None):
    return Snapshot(sgs=tuple(sgs), rules=rules or {}, attached=attached or {})


def test_every_change_kind_reports_a_line():
    old = _snap(
        sgs=[
            CloudSg(id="g1", name="web", description="old"),
            CloudSg(id="g2", name="gone", description=""),
        ],
        rules={
            "g1": [
                CloudRule(
                    id="r-dead",
                    sg_id="g1",
                    direction="ingress",
                    protocol="tcp",
                    ports="22",
                    remote_group_id=None,
                    remote_ip_prefix="10.0.0.0/8",
                ),
                CloudRule(
                    id="r-chg",
                    sg_id="g1",
                    direction="egress",
                    protocol="tcp",
                    ports="80",
                    remote_group_id=None,
                    remote_ip_prefix="10.0.0.0/8",
                ),
            ]
        },
        attached={"g1": [CloudNic(port_id="p-gone", ip="10.0.1.9")]},
    )
    new = _snap(
        sgs=[
            CloudSg(id="g1", name="web", description="new"),
            CloudSg(id="g3", name="born", description=""),
        ],
        rules={
            "g1": [
                CloudRule(
                    id="r-new",
                    sg_id="g1",
                    direction="ingress",
                    protocol="tcp",
                    ports="443",
                    remote_group_id=None,
                    remote_ip_prefix="10.0.0.0/8",
                ),
                CloudRule(
                    id="r-chg",
                    sg_id="g1",
                    direction="egress",
                    protocol="tcp",
                    ports="8080",
                    remote_group_id=None,
                    remote_ip_prefix="10.0.0.0/8",
                ),
            ]
        },
        attached={"g1": [CloudNic(port_id="p-new", ip="10.0.1.10")]},
    )
    lines = render_drift_lines(diff_inventory(old, new))
    text = "\n".join(lines)
    for expected in (
        "- group gone",
        "+ group born",
        "description changed",
        "- rule r-dead",
        "+ rule r-new",
        "~ rule r-chg",
        "- member p-gone",
        "+ member p-new",
    ):
        assert expected in text, expected


def test_json_shape_is_liquibase_diff():
    old = _snap(sgs=[CloudSg(id="g1", name="web", description="")])
    result = diff_inventory(old, _snap())  # whole group vanished
    assert {"missing", "unexpected", "changed"} == set(result)
    entry = result["missing"][0]
    assert entry["type"] == "group" and entry["id"] == "g1"


def test_identical_snapshots_are_empty():
    snap = _snap(sgs=[CloudSg(id="g1", name="web", description="")])
    assert diff_inventory(snap, snap) == {
        "missing": [],
        "unexpected": [],
        "changed": [],
    }
    assert render_drift_lines(diff_inventory(snap, snap)) == ()
