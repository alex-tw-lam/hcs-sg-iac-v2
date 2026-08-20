# hcs_sg_iac/model/quota.py
"""The rate-budget vocabulary shared by the limiter, the gateways, the
pipeline and the renderer — one typed shape instead of four same-keyed
reports (used/limit this window); `QuotaPlan` is what a plan table
shows (calls needed vs what is left)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Quota:
    used_calls: int
    effective_limit: int
    window_resets_at: "float | None" = None

    @property
    def left(self) -> int:
        return self.effective_limit - self.used_calls


@dataclass(frozen=True)
class QuotaPlan:
    needed: int
    left: "int | None"  # None = gateway without quota_snapshot

    def asdict(self) -> dict:
        return {"needed": self.needed, "left": self.left}
