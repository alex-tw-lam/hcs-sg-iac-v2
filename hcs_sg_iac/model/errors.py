# hcs_sg_iac/model/errors.py
"""Domain exceptions raised by gateways and consumed by use cases.

QuotaExhausted / CloudThrottled carry `retry_at` (epoch seconds — the
moment the rate window rolls over) when the gateway knows it, so the
executor can choose to wait and continue instead of stopping."""


class QuotaExhausted(Exception):
    """Our own call-budget slice for this window is exhausted."""

    def __init__(self, message: str, retry_at: "float | None" = None):
        super().__init__(message)
        self.retry_at = retry_at


class CloudThrottled(Exception):
    """The cloud-side (shared) quota throttled us."""

    def __init__(self, message: str, retry_at: "float | None" = None):
        super().__init__(message)
        self.retry_at = retry_at


class CloudError(Exception):
    """Any other cloud/API failure, with error detail in the message."""
