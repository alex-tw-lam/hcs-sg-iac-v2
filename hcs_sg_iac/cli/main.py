# hcs_sg_iac/cli/main.py
"""Argparse presentation layer: parse → config → gateway → pipeline →
render. Dry run is the DEFAULT; --yes is the ONLY path to real writes —
it confirms the preview the command prints first (no prompts)."""
import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from hcs_sg_iac.adapters import audit as audit_adapter
from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.cli import render
from hcs_sg_iac.model.errors import (CloudError, CloudThrottled,
                                     QuotaExhausted)
from hcs_sg_iac.usecases import pipeline, schema_export, validate


@dataclass(frozen=True)
class Config:
    hcs_ak: str
    hcs_sk: str
    hcs_project_id: str
    hcs_endpoint: str
    ca_bundle: str = ""
    ssl_verify: bool = True
    budget: int = 25


def load_config() -> Config:
    try:
        budget = int(os.environ.get("SERVICE_CALL_BUDGET", "25"))
    except ValueError:                       # non-numeric env → safe default
        budget = 25
    return Config(
        hcs_ak=os.environ.get("HCS_AK", ""),
        hcs_sk=os.environ.get("HCS_SK", ""),
        hcs_project_id=os.environ.get("HCS_PROJECT_ID", ""),
        hcs_endpoint=os.environ.get("HCS_ENDPOINT", ""),
        ca_bundle=os.environ.get("CA_BUNDLE", ""),
        ssl_verify=os.environ.get("SSL_VERIFY", "true").lower() == "true",
        budget=budget,
    )


class _ReadOnlyPlanParser(argparse.ArgumentParser):
    """Read-only verbs (plan/validate/schema) accept no --execute/--yes:
    the writing flag cannot reach them by flag fumbling — parse-time
    rejection (exit 2) that says what to run instead. argparse funnels
    subparser unrecognized-arg errors here, so the guard sits on the
    root parser (and is inherited harmlessly by the subparsers)."""

    def error(self, message):
        if "unrecognized" in message and ("--execute" in message
                                          or "--yes" in message):
            self.exit(2, f"{self.prog}: read-only — use "
                         f"'hcs-sg apply --yes' to write\n")
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    # Shared flags sit AFTER the subcommand via a parent parser:
    # `hcs-sg plan --project X --json` — exactly how the tests invoke it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project", default=".",
                        help="project directory (contains groups/ and rules/)")
    common.add_argument("--json", action="store_true",
                        help="machine-readable output")
    common.add_argument("--verbose", action="store_true",
                        help="progress log to stderr (gateway calls, "
                             "phases, per-action results)")
    p = _ReadOnlyPlanParser(prog="hcs-sg",
                            description="Security-group-as-code for HCS "
                                        "(dry run by default)")
    sub = p.add_subparsers(dest="command", required=True,
                           parser_class=_ReadOnlyPlanParser)
    sub.add_parser("validate", parents=[common],
                   help="validate files only (no cloud reads)")
    sub.add_parser("plan", parents=[common],
                   help="diff code vs cloud (read-only; never writes)")
    ap = sub.add_parser("apply", parents=[common],
                        help="apply changes (dry run unless --yes)")
    ap.add_argument("--yes", action="store_true",
                    help="confirm and perform the writes after the "
                         "preview (the write gate)")
    dp = sub.add_parser("destroy", parents=[common],
                        help="delete one security group and detach its members")
    dp.add_argument("name")
    dp.add_argument("--yes", action="store_true",
                    help="confirm and delete after the preview")
    sp = sub.add_parser("schema", parents=[common],
                        help="print the JSON Schema of the config files")
    sp.add_argument("which", nargs="?", choices=["group", "rules", "all"],
                    default="all",
                    help="which schema (default: both, keyed group_file/"
                         "rules_file)")
    return p


def _configure_logging() -> None:
    """--verbose: per-call/phase/action progress to stderr; stdout stays
    pure (JSON-safe). Without the flag no handler exists, so INFO records
    go nowhere. Handler binds sys.stderr at call time (test-friendly)."""
    log = logging.getLogger("hcs_sg_iac")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("hcs-sg: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


def _build_gateway(config: Config):
    from hcs_sg_iac.adapters import huawei_gateway   # deferred: SDK import
    return huawei_gateway.build_gateway(config)


def _audit_factory(project: Path, gateway):
    """adapters.audit wiring handed to the pipeline's execute path (the
    sink is built — and its quota context captured — only when a run
    really starts). Lives here because usecases never import adapters."""
    return lambda: audit_adapter.enrich(
        audit_adapter.jsonl_sink(project / "audit.jsonl"),
        project=str(project.resolve()),
        quota=gateway.quota_snapshot() if hasattr(gateway, "quota_snapshot") else None,
    )


def _print_plan(al, *, quota, args, executed=None) -> None:
    if args.json:
        print(render.render_json(al, quota=quota, executed=executed))
    else:
        print(render.render_plan(al, quota=quota, executed=executed,
                                 dry_run=executed is None))


def _print_preview(gateway, al, args) -> None:
    """The plan table shown BEFORE a confirmation prompt — "the changes
    above" the prompt refers to must already be on screen. Dry-run form:
    no RESULT column, no Dry-run trailer. Under --json the preview goes
    to stderr so stdout stays one pure JSON document."""
    table = render.render_plan(al, quota=pipeline.quota(gateway, al.actions),
                               dry_run=False)
    print(table, file=sys.stderr if args.json else sys.stdout)


def _notify(msg: str) -> None:
    """Wait-and-continue notices go to stderr so --json stdout stays pure."""
    print(f"hcs-sg: {msg}", file=sys.stderr)


def _execute(gateway, al, *, args, project):
    """Shared write tail for apply --yes and destroy --yes: audit sink →
    run. --yes IS the consent (the preview printed above is the plan);
    rate exhaustion waits out the window and continues (notice on
    stderr; --json stdout stays pure data)."""
    return pipeline.execute_confirmed(
        gateway, al, prompt="", expect="",
        confirm=lambda prompt, expect: True,
        audit=_audit_factory(project, gateway),
        sleep=time.sleep, notify=_notify)


def _finish(gateway, al, results, args) -> int:
    """Shared post-execute tail: fresh quota (the writes just spent it);
    any failure (or a declined confirmation) maps to rc 1."""
    if results is None:
        print("aborted", file=sys.stderr)
        return 1
    _print_plan(al, quota=pipeline.quota(gateway, al.actions), args=args,
                executed=results)
    return 0 if all(r.status == "ok" for r in results) else 1


def main(argv=None, gateway=None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        _configure_logging()
    project = Path(args.project)

    if args.command == "schema":
        print(schema_export.dumps(args.which))
        return 0

    if args.command == "validate":
        state, report = yaml_config.load_project(project)
        if state is not None:
            report = validate.validate_state(state)
        if not report.ok:
            print("\n".join(report.errors), file=sys.stderr)
            return 1
        print(f"OK: {len(state.groups)} groups, "
              f"{sum(len(rf.ingress) + len(rf.egress) for rf in state.rules.values())} "
              f"rules — validation passed")
        return 0

    # plan / apply / destroy need a gateway
    if gateway is None:
        config = load_config()
        if not (config.hcs_ak and config.hcs_sk and config.hcs_endpoint
                and config.hcs_project_id):
            print("error: HCS_AK / HCS_SK / HCS_PROJECT_ID / HCS_ENDPOINT "
                  "are required for plan/apply/destroy "
                  "(validate needs no credentials)",
                  file=sys.stderr)
            return 1
        gateway = _build_gateway(config)

    # Everything below touches the gateway: rate exhaustion waits out
    # the window and continues; anything unretryable that still escapes
    # (destroy reads, unexpected SDK failures) is ONE clean error line,
    # never a traceback.
    try:
        if args.command == "destroy":
            al = pipeline.plan_destroy_project(gateway, args.name,
                                               sleep=time.sleep, notify=_notify)
            if not al.actions:
                print(f"error: no cloud security group named {args.name!r}",
                      file=sys.stderr)
                return 1
            if not args.yes:
                _print_plan(al, quota=pipeline.quota(gateway, al.actions),
                            args=args)
                return 0
            _print_preview(gateway, al, args)
            results = _execute(gateway, al, args=args, project=project)
            return _finish(gateway, al, results, args)

        # plan / apply share the pipeline
        al, errors = pipeline.plan_project(yaml_config.load_project, gateway,
                                           project, sleep=time.sleep,
                                           notify=_notify)
        if al is None:
            print("\n".join(errors), file=sys.stderr)
            return 1

        if args.command == "plan" or not args.yes:
            _print_plan(al, quota=pipeline.quota(gateway, al.actions), args=args)
            return 0

        _print_preview(gateway, al, args)     # changes visible, THEN write
        results = _execute(gateway, al, args=args, project=project)
        return _finish(gateway, al, results, args)
    except (CloudError, CloudThrottled, QuotaExhausted) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
