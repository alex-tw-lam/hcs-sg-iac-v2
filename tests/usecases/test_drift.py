# tests/usecases/test_drift.py
"""Drift diff depth: every change kind (group add/remove/rename/desc,
rule add/remove/change, member attach/detach), the Liquibase-shaped
structured result, and duplicate-name safety (keyed by id)."""
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg, Snapshot
from hcs_sg_iac.usecases.drift import diff_inventory, format_lines


def _rule(rid, sg, **kw):
    base = dict(id=rid, sg_id=sg, direction="ingress", protocol="tcp",
                ports="80", remote_group_id=None, remote_ip_prefix="0.0.0.0/0")
    base.update(kw)
    return CloudRule(**base)


def test_every_change_kind_reports_one_line():
    old = Snapshot(
        sgs=(CloudSg(id="s-web", name="web", description=""),
             CloudSg(id="s-db", name="db", description=""),
             CloudSg(id="s-chg", name="same", description="")),
        rules={"s-chg": [_rule("r-same", "s-chg"), _rule("r-gone", "s-chg")]},
        attached={"s-chg": [CloudNic(port_id="p-gone", ip="10.0.0.9")]})
    new = Snapshot(
        sgs=(CloudSg(id="s-web", name="web", description=""),
             CloudSg(id="s-chg", name="same", description="new desc"),
             CloudSg(id="s-new", name="fresh", description="")),
        rules={"s-chg": [_rule("r-same", "s-chg", ports="443"),
                         _rule("r-new", "s-chg")]},
        attached={"s-chg": [CloudNic(port_id="p-new", ip="10.0.0.8")]})
    joined = "\n".join(format_lines(diff_inventory(old, new)))
    assert "- group db (s-db) deleted" in joined
    assert "+ group fresh (s-new) created" in joined
    assert "~ group same (s-chg): description changed" in joined
    assert "- rule r-gone of same" in joined
    assert "+ rule r-new of same" in joined
    assert "~ rule r-same of same: ports changed" in joined
    assert "- member p-gone detached from same" in joined
    assert "+ member p-new attached to same" in joined


def test_structured_result_is_liquibase_shaped():
    """missing/unexpected/changed with per-field differences — the shape
    `drift --json` emits (reference = snapshot, target = cloud)."""
    old = Snapshot(sgs=(CloudSg(id="s1", name="old", description="a"),),
                   rules={"s1": [_rule("r1", "s1")]},
                   attached={"s1": [CloudNic(port_id="p1", ip="10.0.0.1")]})
    new = Snapshot(sgs=(CloudSg(id="s1", name="new", description="a"),
                        CloudSg(id="s2", name="added", description="")),
                   rules={"s1": [_rule("r1", "s1", ports="443"),
                                 _rule("r9", "s1")]},
                   attached={})
    result = diff_inventory(old, new)
    assert {"type": "group", "id": "s2", "name": "added"} in result["unexpected"]
    assert {"type": "rule", "id": "r9", "sg": "new"} in result["unexpected"]
    assert result["missing"] == [{"type": "member", "id": "p1", "sg": "new"}]
    group_chg, rule_chg = result["changed"]
    assert group_chg["differences"] == [{"field": "name",
                                         "referenceValue": "old",
                                         "comparedValue": "new"}]
    assert rule_chg["differences"] == [{"field": "ports",
                                        "referenceValue": "80",
                                        "comparedValue": "443"}]


def test_identical_snapshots_report_no_drift():
    snap = Snapshot(sgs=(CloudSg(id="s1", name="web"),),
                    rules={"s1": [_rule("r1", "s1")]},
                    attached={"s1": [CloudNic(port_id="p1", ip="10.0.0.1")]})
    result = diff_inventory(snap, snap)
    assert result == {"missing": [], "unexpected": [], "changed": []}
    assert format_lines(result) == ()


def test_duplicate_names_never_confuse_the_diff():
    """Two SGs sharing a name (cloud reality) diff safely: keyed by id,
    a rename of one is a change on that id, not a swap of identities."""
    old = Snapshot(sgs=(CloudSg(id="s1", name="dup", description="a"),
                        CloudSg(id="s2", name="dup", description="b")))
    new = Snapshot(sgs=(CloudSg(id="s1", name="dup", description="a"),
                        CloudSg(id="s2", name="other", description="b")))
    assert format_lines(diff_inventory(old, new)) == (
        "~ group s2: renamed 'dup' -> 'other'",)
