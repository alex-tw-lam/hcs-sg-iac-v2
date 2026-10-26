# hcs_sg_iac/usecases/pipeline.py
"""The orchestration seam: load → resolve → snapshot → plan, and for
--yes: execute. The loader is INJECTED by the presentation layer (the
CLI today; a web API tomorrow) — usecases never import adapters, so
this module stays import-pure."""

import logging

from hcs_sg_iac.contracts import CloudError, CloudGateway, CloudReader
from hcs_sg_iac.usecases import apply as apply_uc
from hcs_sg_iac.usecases import plan as plan_uc
from hcs_sg_iac.usecases import resolve
from hcs_sg_iac.usecases.actions import ActionList

_log = logging.getLogger(__name__)  # --verbose: wired by the CLI


def plan_project(load_project, gateway: "CloudReader", project):
    """The full planning pipeline. Returns (ActionList, []) on success,
    or (None, error lines) for any failure — load, resolve, or the
    duplicate-cloud-name ValueError raised by the plan engine. Throttled
    reads are waited out and retried inside the gateway; anything that
    still escapes surfaces as a clean "error: ..." line, never a
    traceback."""
    state, report = load_project(project)
    if state is None:
        return None, list(report.errors)
    try:
        _log.info(
            "phase: resolving %d member IPs",
            sum(len(g.members) for g in state.groups.values()),
        )
        resolution = resolve.resolve_memberships(gateway, state)
        if not resolution.report.ok:
            return None, list(resolution.report.errors)
        snapshot = plan_uc.read_snapshot(gateway)
        return plan_uc.plan(state, resolution, snapshot), []
    except ValueError as e:  # duplicate cloud SG names etc.
        return None, [f"error: {e}"]
    except CloudError as e:
        return None, [f"error: {e}"]


def plan_destroy_project(gateway: "CloudReader", name: str) -> ActionList:
    """Whole-SG teardown plan; the ActionList is empty when no cloud SG
    has that name (the caller decides how to report it). CloudError
    propagates — the CLI reports it cleanly."""
    return plan_uc.plan_destroy(name, plan_uc.read_snapshot(gateway))


def execute_confirmed(gateway: "CloudGateway", al: ActionList) -> list:
    """The execute flow after a confirmed plan (--yes IS the consent)."""
    _log.info(
        "phase: executing %d confirmed actions",
        sum(1 for a in al.actions if a.op is not None),
    )
    return apply_uc.execute(al, gateway=gateway)
