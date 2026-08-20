# hcs_sg_iac/usecases/pipeline.py
"""The orchestration seam (docs/architecture.md): sequences
load → validate → resolve → snapshot → plan, and for --execute
confirm-hook → execute → audit. The loader, confirmation hook and audit
sink are INJECTED by the presentation layer (the CLI today; a web API or
GUI tomorrow) — usecases never import adapters, so this module stays
import-pure."""
from hcs_sg_iac.model.actions import ActionList
from hcs_sg_iac.usecases import apply as apply_uc
from hcs_sg_iac.usecases import plan as plan_uc, resolve, validate


def plan_project(load_project, gateway, project) -> "tuple[ActionList | None, list]":
    """The full planning pipeline. Returns (ActionList, []) on success,
    or (None, error lines) for any failure — load, validate, resolve, or
    the duplicate-cloud-name ValueError raised by the plan engine."""
    state, report = load_project(project)
    if state is None:
        return None, list(report.errors)
    report = validate.validate_state(state)
    if not report.ok:
        return None, list(report.errors)
    resolution = resolve.resolve_memberships(gateway, state)
    if not resolution.report.ok:
        return None, list(resolution.report.errors)
    snapshot = plan_uc.read_snapshot(gateway, gateway)
    try:
        return plan_uc.plan(state, resolution, snapshot), []
    except ValueError as e:                     # duplicate cloud SG names etc.
        return None, [f"error: {e}"]


def plan_destroy_project(gateway, name: str) -> ActionList:
    """Whole-SG teardown plan; the ActionList is empty when no cloud SG
    has that name (the caller decides how to report it)."""
    return plan_uc.plan_destroy(name, plan_uc.read_snapshot(gateway, gateway))


def execute_confirmed(gateway, al: ActionList, *, prompt: str, expect: str,
                      confirm, audit) -> "list | None":
    """The execute flow after a plan: confirmation gate → audit sink →
    run. `confirm` is the presentation's (prompt, expect) -> bool hook;
    `audit` is a zero-arg factory so the sink (and its quota context) is
    captured only when a run really starts. Returns one ActionResult per
    action, or None when confirmation declined."""
    if not confirm(prompt, expect):
        return None
    return apply_uc.execute(al, sg_writer=gateway, rule_writer=gateway,
                            binder=gateway, audit=audit())


def quota(gateway, actions) -> dict:
    """Calls needed vs budget left; left is None for gateways without a
    quota snapshot."""
    snap = getattr(gateway, "quota_snapshot", None)
    left = None
    if snap:
        s = snap()
        left = s["effective_limit"] - s["used_calls"]
    needed = sum(1 for a in actions if a.op is not None)
    return {"needed": needed, "left": left}
