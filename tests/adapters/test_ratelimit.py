# tests/adapters/test_ratelimit.py
"""Row coverage for acquire semantics lives in tests/specs/frames.py
(RATE-01: budget, RATE-02: rollover, RATE-03/03.a: the throttle acquire
patterns). What stays is the snapshot() surface no row asserts."""
from hcs_sg_iac.adapters.ratelimit import FixedWindowLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_external_throttle_halves_effective_limit_snapshot():
    clock = FakeClock()
    lim = FixedWindowLimiter(budget=10, window_seconds=300, clock=clock)
    lim.try_acquire()                        # used = 1
    lim.report_external_throttle()
    # effective limit is now max(used, 10 // 2) = 5
    assert lim.snapshot()["effective_limit"] == 5
    clock.now += 301                         # rollover clears the override
    assert lim.snapshot()["effective_limit"] == 10


def test_external_throttle_late_in_window_pins_limit_to_used():
    clock = FakeClock()
    lim = FixedWindowLimiter(budget=10, window_seconds=300, clock=clock)
    for _ in range(7):
        lim.try_acquire()                    # used = 7
    lim.report_external_throttle()
    # effective limit is now max(used=7, 10 // 2) = 7 → no more calls this window
    assert lim.snapshot()["effective_limit"] == 7
    clock.now += 301                         # rollover clears the override
    assert lim.snapshot()["effective_limit"] == 10


def test_snapshot_fields():
    clock = FakeClock()
    lim = FixedWindowLimiter(budget=25, window_seconds=300, clock=clock)
    lim.try_acquire()
    snap = lim.snapshot()
    assert snap == {
        "service_budget_calls": 25,
        "used_calls": 1,
        "effective_limit": 25,
        "window_resets_at": 1300.0,  # window_start + window_seconds
    }
