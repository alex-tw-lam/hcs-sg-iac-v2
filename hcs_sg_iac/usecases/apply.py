# hcs_sg_iac/usecases/apply.py
"""Execute an ActionList through the writer protocols. Sequential —
throttling is waited out inside the gateway, so the loop stays simple.
Per-action isolation: a failure never aborts the run; dependents of a
failed group create are skipped, not orphaned."""

import logging
from typing import Literal

from hcs_sg_iac.contracts import CloudGateway
from hcs_sg_iac.usecases.actions import (
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


def _record(
    results: list, action, status: 'Literal["ok", "failed"]', error=None
) -> None:
    """Append one result and log it (--verbose): the run is visible
    action-by-action instead of only via the end-of-run table."""
    results.append(ActionResult(action, status, error))
    log = _log.info if status == "ok" else _log.warning
    log("action %s: %s %s %s", status, action.sign, action.type, action.group)


def _perform(op, action, gateway, resolve_sg_id):
    """Dispatch ONE payload to its gateway call (the op type picks the
    method; resolve_sg_id substitutes ids of SGs created earlier in this
    run). Returns the created sg id for CreateSg, else None."""
    if isinstance(op, CreateSg):
        sg = gateway.create_security_group(action.group, op.description)
        return sg.id
    if isinstance(op, UpdateSg):
        gateway.update_security_group_description(op.sg_id, op.description)
    elif isinstance(op, DeleteSg):
        gateway.delete_security_group(op.sg_id)
    elif isinstance(op, CreateRule):
        gateway.create_rule(resolve_sg_id(action.group, op.sg_id), op.rule)
    elif isinstance(op, DeleteRule):
        gateway.delete_rule(op.rule_id)
    elif isinstance(op, AttachNic):
        gateway.attach_nic(resolve_sg_id(action.group, op.sg_id), op.port_id)
    elif isinstance(op, DetachNic):
        gateway.detach_nic(resolve_sg_id(action.group, op.sg_id), op.port_id)
    else:  # unreachable by construction
        raise RuntimeError(f"unknown payload {type(op).__name__}")
    return None


def execute(action_list: ActionList, *, gateway: "CloudGateway") -> list:
    """Run every action with an op. Returns one ActionResult per action;
    a failure never aborts the run."""
    ordered = sorted(
        (a for a in action_list.actions if a.op is not None),
        key=lambda a: _ORDER[type(a.op)],
    )
    results: list = []
    created_sg_ids: dict = {}  # group name -> sg_id (CreateSg ran)
    failed_creates: set = set()  # groups whose CreateSg failed

    def resolve_sg_id(group: str, payload_sg_id: str) -> str:
        return payload_sg_id or created_sg_ids.get(group, "")

    for action in ordered:
        op = action.op
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
        _log.info(
            "executing %s %s %s — %s",
            action.sign,
            action.type,
            action.group,
            action.detail,
        )
        try:
            new_sg_id = _perform(op, action, gateway, resolve_sg_id)
            if new_sg_id:
                created_sg_ids[action.group] = new_sg_id
            _record(results, action, "ok")
        except Exception as e:
            if isinstance(op, CreateSg):
                failed_creates.add(action.group)  # skip its dependents
            _record(results, action, "failed", str(e))

    return results
