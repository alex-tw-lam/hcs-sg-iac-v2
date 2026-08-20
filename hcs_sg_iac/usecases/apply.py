# hcs_sg_iac/usecases/apply.py
"""Execute an ActionList through the writer protocols. Sequential —
the rate budget beats parallelism. Per-action isolation: a failure
never aborts the run; dependents of a failed group create are skipped,
not orphaned. With a `sleep` hook injected, rate exhaustion carrying a
retry deadline waits the window out and retries — a run continues
across windows instead of stopping."""

import logging
import time
from typing import Literal

from hcs_sg_iac.model.actions import (
    ActionList,
    ActionResult,
    AttachNic,
    CreateRule,
    CreateSg,
    DeleteRule,
    DeleteSg,
    DetachNic,
    UpdateSg,
)
from hcs_sg_iac.model.common import CloudThrottled, QuotaExhausted

_log = logging.getLogger(__name__)  # --verbose: wired by the CLI

# Execution order: create the SG first (so later ops can reference it),
# then metadata, then allow-rules and members, then removals, SG delete last.
_ORDER = {
    CreateSg: 0,
    UpdateSg: 1,
    CreateRule: 2,
    AttachNic: 3,
    DeleteRule: 4,
    DetachNic: 5,
    DeleteSg: 6,
}

_MAX_WAITS = 5  # per action: refuse to spin on a stuck window


def wait_for_window(e, *, sleep, notify, what: str) -> bool:
    """Shared wait-and-continue hook (executor actions AND the planning
    read loop in pipeline.py): sleep until the exception's retry_at
    (window rollover), notifying first. Returns True when the caller
    should retry; False when no sleep hook / no deadline (the classic
    throttle-and-skip or clean-error path stands)."""
    deadline = getattr(e, "retry_at", None)
    if sleep is None or deadline is None:
        return False
    wait_for = max(0.0, deadline - time.time())
    if notify:
        notify(
            f"rate window exhausted — waiting {int(wait_for)}s, then "
            f"continuing ({what})"
        )
    sleep(wait_for)
    return True


def _record(
    results: list,
    action,
    status: Literal["ok", "failed", "throttled"],
    error=None,
) -> None:
    """Append one result and log it (--verbose): the run is visible
    action-by-action instead of only via the end-of-run table."""
    results.append(ActionResult(action, status, error))
    log = _log.info if status == "ok" else _log.warning
    log("action %s: %s %s %s", status, action.sign, action.type, action.group)


def _perform(op, action, *, sg_writer, rule_writer, binder, resolve_sg_id):
    """Dispatch ONE payload to its writer call (the op type picks the
    writer; resolve_sg_id substitutes ids of SGs created earlier in this
    run). Returns the created sg id for CreateSg, else None."""
    if isinstance(op, CreateSg):
        sg = sg_writer.create_security_group(action.group, op.description)
        return sg.id
    if isinstance(op, UpdateSg):
        sg_writer.update_security_group_description(op.sg_id, op.description)
    elif isinstance(op, DeleteSg):
        sg_writer.delete_security_group(op.sg_id)
    elif isinstance(op, CreateRule):
        rule_writer.create_rule(resolve_sg_id(action.group, op.sg_id), op.rule)
    elif isinstance(op, DeleteRule):
        rule_writer.delete_rule(op.rule_id)
    elif isinstance(op, AttachNic):
        binder.attach_nic(resolve_sg_id(action.group, op.sg_id), op.port_id)
    elif isinstance(op, DetachNic):
        binder.detach_nic(resolve_sg_id(action.group, op.sg_id), op.port_id)
    else:  # unreachable by construction
        raise RuntimeError(f"unknown payload {type(op).__name__}")
    return None


def execute(
    action_list: ActionList,
    *,
    sg_writer,
    rule_writer,
    binder,
    sleep=None,
    notify=None,
) -> list:
    """Run every action with an op. Returns one ActionResult per action.

    `sleep`/`notify` opt into wait-and-continue on rate exhaustion:
    notify(msg) is called before each wait (the CLI prints to stderr);
    without `sleep` the classic behaviour stands (mark throttled, skip
    the rest — a re-run resumes, idempotent)."""
    ordered = sorted(
        (a for a in action_list.actions if a.op is not None),
        key=lambda a: _ORDER[type(a.op)],
    )
    results: list = []
    created_sg_ids: dict = {}  # group name -> sg_id (CreateSg ran)
    failed_creates: set = set()  # groups whose CreateSg failed
    throttled = False

    def resolve_sg_id(group: str, payload_sg_id: str) -> str:
        return payload_sg_id or created_sg_ids.get(group, "")

    for action in ordered:
        op = action.op
        if throttled:
            _record(
                results,
                action,
                "throttled",
                "skipped: budget exhausted earlier",
            )
            continue
        if (
            isinstance(op, (CreateRule, AttachNic))
            and action.group in failed_creates
            and resolve_sg_id(action.group, op.sg_id) == ""
        ):
            _record(
                results,
                action,
                "failed",
                "group creation failed — skipping dependent",
            )
            continue
        waits = 0
        _log.info(
            "executing %s %s %s — %s",
            action.sign,
            action.type,
            action.group,
            action.detail,
        )
        while True:
            try:
                new_sg_id = _perform(
                    op,
                    action,
                    sg_writer=sg_writer,
                    rule_writer=rule_writer,
                    binder=binder,
                    resolve_sg_id=resolve_sg_id,
                )
                if new_sg_id:
                    created_sg_ids[action.group] = new_sg_id
                _record(results, action, "ok")
                break
            except (QuotaExhausted, CloudThrottled) as e:
                if waits < _MAX_WAITS and wait_for_window(
                    e,
                    sleep=sleep,
                    notify=notify,
                    what=f"action {action.type} {action.group}",
                ):
                    waits += 1
                    continue  # window rolled over: retry
                throttled = True
                _record(results, action, "throttled", str(e))
                break
            except Exception as e:
                if isinstance(op, CreateSg):
                    failed_creates.add(action.group)  # skip its dependents
                _record(results, action, "failed", str(e))
                break

    return results
