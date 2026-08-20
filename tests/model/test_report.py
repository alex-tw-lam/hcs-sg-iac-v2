# tests/model/test_report.py
"""Warnings-don't-fail is row-covered (STORE-06/06.a assert expect_ok
alongside expect_warn). What stays: the exact "where: message" format
and the exception-class distinctness — rows only do substring checks
and behavioural separation."""

from hcs_sg_iac.model.errors import CloudError, CloudThrottled, QuotaExhausted
from hcs_sg_iac.model.report import Report


def test_report_collects_errors_and_warnings():
    r = Report()
    assert r.ok
    r.error("groups/web-tier.yaml", "bad thing")
    r.warning("plan", "overlap allowed")
    assert not r.ok
    assert r.errors == ["groups/web-tier.yaml: bad thing"]
    assert r.warnings == ["plan: overlap allowed"]


def test_cloud_exceptions_are_distinct():
    assert len({QuotaExhausted, CloudThrottled, CloudError}) == 3
    assert not isinstance(CloudError("x"), (QuotaExhausted, CloudThrottled))
