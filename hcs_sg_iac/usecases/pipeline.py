# hcs_sg_iac/usecases/pipeline.py
"""The orchestration seam (docs/architecture.md): sequences
load → validate → resolve → snapshot → plan, and for --yes:
confirm-hook → execute → audit. The loader, confirmation hook and audit
sink are INJECTED by the presentation layer (the CLI today; a web API or
GUI tomorrow) — usecases never import adapters, so this module stays
import-pure."""

import logging

from hcs_sg_iac.model.actions import ActionList
from hcs_sg_iac.model.errors import CloudError, CloudThrottled, QuotaExhausted
from hcs_sg_iac.model.quota import QuotaPlan
from hcs_sg_iac.usecases import apply as apply_uc
from hcs_sg_iac.usecases import plan as plan_uc
from hcs_sg_iac.usecases import resolve, validate

_log = logging.getLogger(__name__)  # --verbose: wired by the CLI

_MAX_WAITS = 5  # per plan attempt: refuse to spin on a stuck window


def plan_project(
    load_project, gateway, project, *, sleep=None, notify=None
) -> "tuple[ActionList | None, list]":
    """The full planning pipeline. Returns (ActionList, []) on success,
    or (None, error lines) for any failure — load, validate, resolve, or
    the duplicate-cloud-name ValueError raised by the plan engine. The
    READ side (resolution + snapshot) shares apply's wait-and-continue:
    rate exhaustion with a retry deadline and a sleep hook waits out the
    window and re-reads; anything unretryable (or exhausted retries)
    surfaces as a clean "error: ..." line, never a traceback."""
    state, report = load_project(project)
    if state is None:
        return None, list(report.errors)
    report = validate.validate_state(state)
    if not report.ok:
        return None, list(report.errors)
    waits = 0
    while True:
        try:
            _log.info(
                "phase: resolving %d member IPs",
                sum(len(g.members) for g in state.groups.values()),
            )
            resolution = resolve.resolve_memberships(gateway, state)
            if not resolution.report.ok:
                return None, list(resolution.report.errors)
            snapshot = plan_uc.read_snapshot(gateway, gateway)
            return plan_uc.plan(state, resolution, snapshot), []
        except ValueError as e:  # duplicate cloud SG names etc.
            return None, [f"error: {e}"]
        except (QuotaExhausted, CloudThrottled) as e:
            if waits < _MAX_WAITS and apply_uc.wait_for_window(
                e, sleep=sleep, notify=notify, what="planning reads"
            ):
                waits += 1
                continue
            return None, [f"error: {e}"]
        except CloudError as e:
            return None, [f"error: {e}"]


def plan_destroy_project(
    gateway, name: str, *, sleep=None, notify=None
) -> ActionList:
    """Whole-SG teardown plan; the ActionList is empty when no cloud SG
    has that name (the caller decides how to report it). Same
    wait-and-continue on rate exhaustion as plan_project."""
    waits = 0
    while True:
        try:
            return plan_uc.plan_destroy(
                name, plan_uc.read_snapshot(gateway, gateway)
            )
        except (QuotaExhausted, CloudThrottled) as e:
            if waits < _MAX_WAITS and apply_uc.wait_for_window(
                e, sleep=sleep, notify=notify, what="destroy reads"
            ):
                waits += 1
                continue
            raise  # CLI reports it cleanly


def execute_confirmed(
    gateway,
    al: ActionList,
    *,
    prompt: str,
    expect: str,
    confirm,
    audit,
    sleep=None,
    notify=None,
) -> "list | None":
    """The execute flow after a plan: confirmation gate → audit sink →
    run. `confirm` is the presentation's (prompt, expect) -> bool hook;
    `audit` is a zero-arg factory so the sink (and its quota context) is
    captured only when a run really starts. `sleep`/`notify` opt into
    wait-and-continue on rate exhaustion (see usecases/apply.py). Returns
    one ActionResult per action, or None when confirmation declined."""
    if not confirm(prompt, expect):
        return None
    _log.info(
        "phase: executing %d confirmed actions",
        sum(1 for a in al.actions if a.op is not None),
    )
    return apply_uc.execute(
        al,
        sg_writer=gateway,
        rule_writer=gateway,
        binder=gateway,
        audit=audit(),
        sleep=sleep,
        notify=notify,
    )


def quota(gateway, actions) -> QuotaPlan:
    """Calls needed vs budget left; left is None for gateways without a
    quota snapshot."""
    snap = getattr(gateway, "quota_snapshot", None)
    left = snap().left if snap else None
    needed = sum(1 for a in actions if a.op is not None)
    return QuotaPlan(needed=needed, left=left)
