# tests/helpers.py
"""Shared test scaffolding (importable because tests/ is a package)."""

import time

from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.errors import QuotaExhausted
from hcs_sg_iac.usecases.plan import plan, read_snapshot
from hcs_sg_iac.usecases.resolve import resolve_memberships


def plan_state(gw, state):
    """The resolve -> snapshot -> plan pipeline every planning test uses."""
    res = resolve_memberships(gw, state)
    assert res.report.ok, res.report.errors
    return plan(state, res, read_snapshot(gw, gw))


class ExhaustOnce(FakeGateway):
    """Raises QuotaExhausted carrying a retry deadline (now + `delay`
    seconds) on the FIRST create_security_group, then behaves normally —
    the gateway shape the wait-and-continue executor tests need."""

    def __init__(self, delay: float = 60.0):
        super().__init__()
        self._deadline = time.time() + delay
        self.raised = False

    def create_security_group(self, name, description):
        if not self.raised:
            self.raised = True
            raise QuotaExhausted(
                "budget exhausted for this window", retry_at=self._deadline
            )
        return super().create_security_group(name, description)
