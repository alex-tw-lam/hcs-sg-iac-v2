# tests/helpers.py
"""Shared test scaffolding (importable because tests/ is a package)."""
from hcs_sg_iac.usecases.plan import plan, read_snapshot
from hcs_sg_iac.usecases.resolve import resolve_memberships


def plan_state(gw, state):
    """The resolve -> snapshot -> plan pipeline every planning test uses."""
    res = resolve_memberships(gw, state)
    assert res.report.ok, res.report.errors
    return plan(state, res, read_snapshot(gw, gw))
