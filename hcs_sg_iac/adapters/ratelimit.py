# app/ratelimit.py
"""Fixed-window rate limiter.

Zero project imports (stdlib only) — this file can be copied into any
project unmodified.

Not thread-safe; safe on a single event loop (no await points). Wrap in
a lock if called from threads.
"""

import time

from hcs_sg_iac.model.quota import Quota


class FixedWindowLimiter:
    """Allows up to `budget` calls per `window_seconds`.

    `report_external_throttle()` shrinks the effective limit of the CURRENT
    window to half the budget (adaptive backoff when the shared cloud-side
    quota is exhausted by other consumers). The override clears on rollover.
    """

    def __init__(
        self, budget: int, window_seconds: float = 300.0, clock=time.time
    ):
        self._budget = budget
        self._window = window_seconds
        self._clock = clock
        self._used = 0
        self._window_start: float = clock()
        self._limit_override: int | None = None

    @property
    def limit(self) -> int:
        return (
            self._limit_override
            if self._limit_override is not None
            else self._budget
        )

    def _rollover(self) -> None:
        now = self._clock()
        if now - self._window_start >= self._window:
            self._window_start = now
            self._used = 0
            self._limit_override = None

    def try_acquire(self) -> bool:
        """Reserve one call slot. Returns False when the window is exhausted."""
        self._rollover()
        if self._used >= self.limit:
            return False
        self._used += 1
        return True

    def report_external_throttle(self) -> None:
        """Cloud-side throttling seen: halve our slice for this window."""
        self._rollover()
        self._limit_override = max(self._used, self._budget // 2)

    def snapshot(self) -> Quota:
        self._rollover()
        return Quota(
            used_calls=self._used,
            effective_limit=self.limit,
            window_resets_at=self._window_start + self._window,
        )
