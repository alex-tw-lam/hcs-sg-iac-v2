# hcs_sg_iac/model/errors.py
"""Domain exceptions raised by gateways and consumed by use cases."""


class QuotaExhausted(Exception):
    """Our own call-budget slice for this window is exhausted."""


class CloudThrottled(Exception):
    """The cloud-side (shared) quota throttled us."""


class CloudError(Exception):
    """Any other cloud/API failure, with error detail in the message."""
