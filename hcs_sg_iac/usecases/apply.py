# hcs_sg_iac/usecases/apply.py
"""Execute an ActionList through the writer protocols. Sequential —
the rate budget beats parallelism. Per-action isolation: a failure
never aborts the run (dependents of a failed group create are skipped,
not orphaned); quota exhaustion throttles the REST."""
import datetime

from hcs_sg_iac.model.actions import (ActionList, ActionResult,
                                      AttachNic, CreateRule, CreateSg,
                                      DeleteRule, DeleteSg, DetachNic, UpdateSg)
from hcs_sg_iac.model.errors import CloudThrottled, QuotaExhausted

# Execution order: create the SG first (so later ops can reference it),
# then metadata, then allow-rules and members, then removals, SG delete last.
_ORDER = {CreateSg: 0, UpdateSg: 1, CreateRule: 2, AttachNic: 3,
          DeleteRule: 4, DetachNic: 5, DeleteSg: 6}


def execute(action_list: ActionList, *, sg_writer, rule_writer, binder,
            audit=None) -> list:
    """Run every action with an op. Returns one ActionResult per action."""
    ordered = sorted((a for a in action_list.actions if a.op is not None),
                     key=lambda a: _ORDER[type(a.op)])
    results: list = []
    created_sg_ids: dict = {}          # group name -> sg_id (CreateSg ran)
    failed_creates: set = set()        # groups whose CreateSg failed
    throttled = False

    def resolve_sg_id(group: str, payload_sg_id: str) -> str:
        return payload_sg_id or created_sg_ids.get(group, "")

    for action in ordered:
        op = action.op
        if throttled:
            results.append(ActionResult(action, "throttled",
                                        "skipped: budget exhausted earlier"))
            continue
        if (isinstance(op, (CreateRule, AttachNic))
                and action.group in failed_creates
                and resolve_sg_id(action.group, op.sg_id) == ""):
            results.append(ActionResult(
                action, "failed",
                "group creation failed — skipping dependent"))
            continue
        try:
            if isinstance(op, CreateSg):
                sg = sg_writer.create_security_group(action.group,
                                                     op.description)
                created_sg_ids[action.group] = sg.id
            elif isinstance(op, UpdateSg):
                sg_writer.update_security_group_description(op.sg_id,
                                                            op.description)
            elif isinstance(op, DeleteSg):
                sg_writer.delete_security_group(op.sg_id)
            elif isinstance(op, CreateRule):
                rule_writer.create_rule(resolve_sg_id(action.group, op.sg_id),
                                        op.rule)
            elif isinstance(op, DeleteRule):
                rule_writer.delete_rule(op.rule_id)
            elif isinstance(op, AttachNic):
                binder.attach_nic(resolve_sg_id(action.group, op.sg_id),
                                  op.port_id)
            elif isinstance(op, DetachNic):
                binder.detach_nic(resolve_sg_id(action.group, op.sg_id),
                                  op.port_id)
            else:                                   # unreachable by construction
                raise RuntimeError(f"unknown payload {type(op).__name__}")
            results.append(ActionResult(action, "ok"))
        except (QuotaExhausted, CloudThrottled) as e:
            throttled = True
            results.append(ActionResult(action, "throttled", str(e)))
        except Exception as e:                      # noqa: BLE001 — isolate
            if isinstance(op, CreateSg):
                failed_creates.add(action.group)    # skip its dependents
            results.append(ActionResult(action, "failed", str(e)))

    if audit is not None:
        audit({
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            "summary": {k: sum(1 for r in results if r.status == k)
                        for k in ("ok", "failed", "throttled")},
            "created": dict(created_sg_ids),
            "actions": [{"group": r.action.group, "type": r.action.type,
                         "cloud_id": r.action.cloud_id,
                         "detail": r.action.detail, "status": r.status,
                         "error": r.error} for r in results],
        })
    return results
