# tests/cli/test_render.py
"""Render depth tests that no REND-* frame row pins; the breadth lives
in the frame catalogue (tests/specs/frames.py)."""
import json

from hcs_sg_iac.cli.render import render_json, render_plan
from hcs_sg_iac.model.quota import QuotaPlan
from hcs_sg_iac.model.actions import Action, ActionList, ActionResult


def _al():
    return ActionList(
        actions=(
            Action("+", "member", "web-tier", "ip 10.0.1.12 (vm=web-01)",
                   "abc-123", None),
            Action("~", "group", "web-tier", 'description: "a" -> "b"',
                   "9f3e01", None),
            Action("-", "rule", "app-tier", "ingress tcp 5432 from group:web",
                   "ab12cd34", None),
        ),
        unmanaged=("egress rules of web-tier (3 cloud rules untouched)",),
        overlap=("10.0.1.10 in groups web-tier, monitoring",))


def test_json_shape():
    """REND-03 pins summary/quota/unmanaged/overlap for its own data and
    ACT-01 the counting; unique here: the per-action entry shape and the
    prefixed cloud_id, plus non-empty info passthrough."""
    out = render_json(_al(), quota=QuotaPlan(needed=8, left=22))
    data = json.loads(out)
    assert data["actions"][0] == {"action": "+", "type": "member",
                                  "group": "web-tier",
                                  "detail": "ip 10.0.1.12 (vm=web-01)",
                                  "cloud_id": "nic=abc-123"}
    assert data["quota"] == {"needed": 8, "left": 22}  # shape pinned
    assert data["unmanaged"] and data["overlap"]


def test_reversed_executed_results_pair_by_key():
    """REND-02 renders naturally-ordered results; unique here: results
    arriving out of order must still pair with their action by key."""
    al = _al()
    executed = list(reversed([
        ActionResult(Action("+", "member", "web-tier",
                            "ip 10.0.1.12 (vm=web-01)", "abc-123", None), "ok"),
        ActionResult(Action("-", "rule", "app-tier",
                            "ingress tcp 5432 from group:web",
                            "ab12cd34", None), "throttled", "x")]))
    out = render_plan(al, quota=None, executed=executed, dry_run=False)
    member_line = next(l for l in out.splitlines() if "nic=abc-123" in l)
    rule_line = next(l for l in out.splitlines() if "rule=ab12cd34" in l)
    assert member_line.rstrip().endswith("ok")
    assert rule_line.rstrip().endswith("throttled")


def test_unmatched_plan_row_renders_dash_and_new_renders():
    """REND-02's executed list covers every action; unique here: a plan
    row with no matching result renders '-', a new one '(new)'."""
    al = ActionList(actions=(
        Action("~", "group", "g", "d", "s1", None),
        Action("+", "rule", "g", "ingress tcp 22 from cidr:0.0.0.0/0",
               None, None),
    ), unmanaged=(), overlap=())
    out = render_plan(al, quota=None, executed=[], dry_run=False)
    assert "(new)" in out
    group_line = next(l for l in out.splitlines() if "sg=s1" in l)
    assert group_line.rstrip().endswith("-")


def test_falsy_quota_omits_table_line():
    # REND-03 pins the json null; unique: the table line disappears
    out = render_plan(_al(), quota=None, dry_run=True)
    assert "Quota:" not in out


def test_unknown_quota_left_renders_remaining_unknown():
    out = render_plan(_al(), quota=QuotaPlan(needed=8, left=None), dry_run=True)
    assert "Quota: 8 calls needed, remaining unknown." in out
    assert "None left" not in out
    assert json.loads(
        render_json(_al(), quota=QuotaPlan(needed=8, left=None)))["quota"]["left"] \
        is None
