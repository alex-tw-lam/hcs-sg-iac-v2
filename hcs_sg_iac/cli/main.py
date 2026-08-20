# hcs_sg_iac/cli/main.py
"""Argparse presentation layer: parse → config → gateway → pipeline →
render. Dry run is the DEFAULT; --execute is the only path to real
writes."""
import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from hcs_sg_iac.adapters import audit as audit_adapter
from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.cli import render
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


def build_parser() -> argparse.ArgumentParser:
    # Shared flags sit AFTER the subcommand via a parent parser:
    # `hcs-sg plan --project X --json` — exactly how the tests invoke it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project", default=".",
                        help="project directory (contains groups/ and rules/)")
    common.add_argument("--json", action="store_true",
                        help="machine-readable output")
    p = argparse.ArgumentParser(prog="hcs-sg",
                                description="Security-group-as-code for HCS "
                                            "(dry run by default)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", parents=[common],
                   help="validate files only (no cloud reads)")
    sub.add_parser("plan", parents=[common],
                   help="diff code vs cloud (read-only)")
    ap = sub.add_parser("apply", parents=[common],
                        help="apply changes (dry run unless --execute)")
    ap.add_argument("--execute", action="store_true",
                    help="actually perform writes (prompts unless --yes)")
    ap.add_argument("--yes", action="store_true",
                    help="skip confirmation (never implies --execute)")
    dp = sub.add_parser("destroy", parents=[common],
                        help="delete one security group and detach its members")
    dp.add_argument("name")
    dp.add_argument("--execute", action="store_true")
    dp.add_argument("--yes", action="store_true")
    sp = sub.add_parser("schema", parents=[common],
                        help="print the JSON Schema of the config files")
    sp.add_argument("which", nargs="?", choices=["group", "rules", "all"],
                    default="all",
                    help="which schema (default: both, keyed group_file/"
                         "rules_file)")
    return p


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


def _confirm(prompt: str, expect: str, *, quiet: bool = False) -> bool:
    text = f"{prompt} (type {expect!r} to continue): "
    try:
        if quiet:      # --json: prompts go to stderr so stdout stays pure data
            print(text, end="", flush=True, file=sys.stderr)
            answer = input().strip()
        else:
            answer = input(text).strip()
    except (EOFError, KeyboardInterrupt):    # non-interactive stdin (cron/CI)
        print("aborted", file=sys.stderr)
        return False
    return answer == expect


def _execute(gateway, al, *, prompt, expect, args, project):
    """Shared execute tail for apply and destroy: confirm (skipped by
    --yes) → audit sink → run. Returns the result list, or None when
    confirmation declined."""
    confirm = ((lambda prompt, expect: True) if args.yes
               else (lambda prompt, expect: _confirm(prompt, expect,
                                                     quiet=args.json)))
    return pipeline.execute_confirmed(gateway, al, prompt=prompt, expect=expect,
                                      confirm=confirm,
                                      audit=_audit_factory(project, gateway))


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

    if args.command == "destroy":
        al = pipeline.plan_destroy_project(gateway, args.name)
        if not al.actions:
            print(f"error: no cloud security group named {args.name!r}",
                  file=sys.stderr)
            return 1
        if not args.execute:
            _print_plan(al, quota=pipeline.quota(gateway, al.actions), args=args)
            return 0
        results = _execute(gateway, al,
                           prompt=(f"This deletes security group "
                                   f"{args.name!r} after detaching "
                                   f"its members"),
                           expect=args.name, args=args, project=project)
        return _finish(gateway, al, results, args)

    # plan / apply share the pipeline
    al, errors = pipeline.plan_project(yaml_config.load_project, gateway,
                                       project)
    if al is None:
        print("\n".join(errors), file=sys.stderr)
        return 1

    if args.command == "plan" or not args.execute:
        _print_plan(al, quota=pipeline.quota(gateway, al.actions), args=args)
        return 0

    # WARN only for managed+empty directions the plan will ACTUALLY strip
    # (the plan engine computed that set as ActionList.clears): a
    # []-direction with no cloud rules deletes nothing — no false alarm.
    extra = (f"\nWARNING: this removes ALL {', '.join(al.clears)}."
             if al.clears else "")
    results = _execute(gateway, al, prompt="Apply the changes above" + extra,
                       expect="yes", args=args, project=project)
    return _finish(gateway, al, results, args)


if __name__ == "__main__":
    sys.exit(main())
