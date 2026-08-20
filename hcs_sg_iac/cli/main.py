# hcs_sg_iac/cli/main.py
"""Argparse presentation layer: parse → config → gateway → pipeline →
render. Dry run is the DEFAULT; --yes is the ONLY path to real writes —
it confirms the preview the command prints first (no prompts)."""

import argparse
import datetime
import json
import logging
import os
import sys
import time
import typing
from dataclasses import dataclass
from pathlib import Path

from hcs_sg_iac.adapters import audit as audit_adapter
from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.adapters.snapshot_gateway import SnapshotGateway
from hcs_sg_iac.cli import render
from hcs_sg_iac.model.cloud import snapshot_from_json, snapshot_to_json
from hcs_sg_iac.model.errors import CloudError, CloudThrottled, QuotaExhausted
from hcs_sg_iac.usecases import drift as drift_uc
from hcs_sg_iac.usecases import importer, pipeline, schema_export, validate
from hcs_sg_iac.usecases.plan import read_snapshot

_log = logging.getLogger("hcs_sg_iac.cli")  # --verbose: wired below


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
    except ValueError:  # non-numeric env → safe default
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
        if "unrecognized" in message and (
            "--execute" in message or "--yes" in message
        ):
            self.exit(
                2,
                f"{self.prog}: read-only — use "
                f"'hcs-sg apply --yes' to write\n",
            )
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    # Shared flags sit AFTER the subcommand via a parent parser:
    # `hcs-sg plan --project X --json` — exactly how the tests invoke it.
    common = _ReadOnlyPlanParser(add_help=False)
    common.add_argument(
        "--project",
        default=".",
        help="project directory (contains groups/ and rules/)",
    )
    common.add_argument(
        "--json", action="store_true", help="machine-readable output"
    )
    common.add_argument(
        "--verbose",
        action="store_true",
        help="progress log to stderr (gateway calls, "
        "phases, per-action results)",
    )
    p = _ReadOnlyPlanParser(
        prog="hcs-sg",
        description="Security-group-as-code for HCS " "(dry run by default)",
    )
    sub = p.add_subparsers(
        dest="command", required=True, parser_class=_ReadOnlyPlanParser
    )
    sub.add_parser(
        "validate",
        parents=[common],
        help="validate files only (no cloud reads)",
    )
    pp = sub.add_parser(
        "plan",
        parents=[common],
        help="diff code vs cloud (read-only; never writes)",
    )
    pp.add_argument(
        "--snapshot",
        metavar="FILE",
        help="plan offline from a snapshot file: zero cloud "
        "reads, no credentials",
    )
    ap = sub.add_parser(
        "apply", parents=[common], help="apply changes (dry run unless --yes)"
    )
    ap.add_argument(
        "--snapshot",
        metavar="FILE",
        help="plan offline from a snapshot file; --yes writes "
        "still go to the real cloud",
    )
    ap.add_argument(
        "--yes",
        action="store_true",
        help="confirm and perform the writes after the "
        "preview (the write gate)",
    )
    dp = sub.add_parser(
        "destroy",
        parents=[common],
        help="delete one security group and detach its members",
    )
    dp.add_argument("name")
    dp.add_argument(
        "--snapshot",
        metavar="FILE",
        help="plan the teardown offline from a snapshot file",
    )
    dp.add_argument(
        "--yes",
        action="store_true",
        help="confirm and delete after the preview",
    )
    snp = sub.add_parser(
        "snapshot",
        parents=[common],
        help="export the cloud inventory (SGs, members, "
        "rules, member NICs) to a JSON file",
    )
    snp.add_argument(
        "--out",
        default="snapshot.json",
        help="output file inside the project " "(default: snapshot.json)",
    )
    dr = sub.add_parser(
        "drift",
        parents=[common],
        help="diff the live cloud against a snapshot "
        "(default: snapshot.json in the project; "
        "rc 1 when anything drifted)",
    )
    dr.add_argument(
        "--snapshot",
        metavar="FILE",
        help="snapshot file to compare against "
        "(default: snapshot.json when present)",
    )
    imp = sub.add_parser(
        "import",
        parents=[common],
        help="generate groups/ and rules/ YAML from a "
        "snapshot (offline, zero cloud calls — the "
        "adopt-the-estate path)",
    )
    imp.add_argument(
        "--snapshot",
        metavar="FILE",
        help="source snapshot (default: snapshot.json in " "the project)",
    )
    imp.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing groups/*.yaml and " "rules/*.yaml files",
    )
    sp = sub.add_parser(
        "schema",
        parents=[common],
        help="print the JSON Schema of the config files",
    )
    sp.add_argument(
        "which",
        nargs="?",
        choices=["group", "ingress", "egress", "all"],
        default="all",
        help="which schema (default: all, keyed group_file/"
        "ingress_file/egress_file)",
    )
    return p


class _VerboseHandler(logging.StreamHandler):
    """The one stderr handler --verbose installs. isinstance marks it:
    idempotent wiring without dynamic attributes."""

    def __init__(self) -> None:
        super().__init__(sys.stderr)
        self.setFormatter(logging.Formatter("hcs-sg: %(message)s"))


def _configure_logging() -> None:
    """--verbose: per-call/phase/action progress to stderr; stdout stays
    pure (JSON-safe). Without the flag no handler exists, so INFO records
    go nowhere. Handler binds sys.stderr at call time (test-friendly) and
    wiring twice in one process adds no duplicate lines (embedders and
    test runners call main() repeatedly)."""
    log = logging.getLogger("hcs_sg_iac")
    ours = next(
        (h for h in log.handlers if isinstance(h, _VerboseHandler)), None
    )
    if ours is not None:
        ours.stream = sys.stderr  # rebind: capture swaps sys.stderr per test
        return
    log.addHandler(_VerboseHandler())
    log.setLevel(logging.INFO)
    log.propagate = False


def _build_gateway(config: Config):
    from hcs_sg_iac.adapters import huawei_gateway  # deferred: SDK import

    return huawei_gateway.build_gateway(config)


def _audit_factory(project: Path, gateway):
    """adapters.audit wiring handed to the pipeline's execute path (the
    sink is built — and its quota context captured — only when a run
    really starts). Lives here because usecases never import adapters."""
    return lambda: audit_adapter.enrich(
        audit_adapter.jsonl_sink(project / "audit.jsonl"),
        project=str(project.resolve()),
        quota=(
            gateway.quota_snapshot().asdict()
            if hasattr(gateway, "quota_snapshot")
            else None
        ),
    )


def _print_plan(al, *, quota, args, executed=None) -> None:
    if args.json:
        print(render.render_json(al, quota=quota, executed=executed))
    else:
        print(
            render.render_plan(
                al, quota=quota, executed=executed, dry_run=executed is None
            )
        )


def _print_preview(gateway, al, args) -> None:
    """The plan table shown BEFORE a confirmation prompt — "the changes
    above" the prompt refers to must already be on screen. Dry-run form:
    no RESULT column, no Dry-run trailer. Under --json the preview goes
    to stderr so stdout stays one pure JSON document."""
    table = render.render_plan(
        al, quota=pipeline.quota(gateway, al.actions), dry_run=False
    )
    print(table, file=sys.stderr if args.json else sys.stdout)


def _notify(msg: str) -> None:
    """Wait-and-continue notices go to stderr so --json stdout stays pure."""
    print(f"hcs-sg: {msg}", file=sys.stderr)


def _snapshot_stale_note(snap_arg) -> None:
    """Writes just landed against a plan built from --snapshot: the file
    is now stale. Deliberately NOT auto-updated — a snapshot is a
    point-in-time artifact, not a hidden state file (the repo's
    no-state-file rule); refresh or verify explicitly."""
    if snap_arg:
        print(
            f"hcs-sg: note: {snap_arg} is now stale (writes applied) — "
            f"refresh with 'hcs-sg snapshot' or verify with "
            f"'hcs-sg drift --snapshot {snap_arg}'",
            file=sys.stderr,
        )


def _execute(gateway, al, *, args, project):
    """Shared write tail for apply --yes and destroy --yes: audit sink →
    run. --yes IS the consent (the preview printed above is the plan);
    rate exhaustion waits out the window and continues (notice on
    stderr; --json stdout stays pure data)."""
    return pipeline.execute_confirmed(
        gateway,
        al,
        prompt="",
        expect="",
        confirm=lambda prompt, expect: True,
        audit=_audit_factory(project, gateway),
        sleep=time.sleep,
        notify=_notify,
    )


def _finish(gateway, al, results, args) -> int:
    """Shared post-execute tail: fresh quota (the writes just spent it);
    any failure (or a declined confirmation) maps to rc 1."""
    if results is None:
        print("aborted", file=sys.stderr)
        return 1
    _print_plan(
        al,
        quota=pipeline.quota(gateway, al.actions),
        args=args,
        executed=results,
    )
    return 0 if all(r.status == "ok" for r in results) else 1


@dataclass(frozen=True)
class _Ctx:
    """What the cloud-command handlers share: the project dir, the
    gateway (real SDK or injected), the reader the pipeline sees (a
    SnapshotGateway when planning offline), and the snapshot provenance
    the post-write staleness note needs."""

    project: Path
    # Any: the CLI drives every Protocol role (reader/writer/binder) of
    # whichever gateway it was handed — no single type says that.
    gateway: typing.Any = None
    readers: typing.Any = None
    snap_arg: "str | None" = None
    snap_file: "Path | None" = None
    auto: bool = False
    yes: bool = False
    offline: bool = False

    def stale_note_source(self):
        return self.snap_arg or ("snapshot.json" if self.auto else None)


def _resolve_ctx(args, project, gateway) -> "tuple[_Ctx, int | None]":
    """Snapshot provenance + gateway/credentials gate for the cloud
    commands. Returns (ctx, None) to proceed, or (ctx, rc) to exit with
    rc: plan/apply/destroy may run their pre-work OFFLINE from a
    snapshot file (zero reads, no credentials); live reads
    (snapshot/drift), online planning and --yes writes need the real
    gateway. Flags live on their own subparsers, so read them
    tolerantly."""
    snap_arg = getattr(args, "snapshot", None)
    snap_file, auto = None, False
    if snap_arg:
        p_ = Path(snap_arg)
        snap_file = p_ if p_.is_absolute() else project / p_
    else:  # snapshot.json present -> plan from it, no flag needed
        default = project / "snapshot.json"
        if (
            args.command in ("plan", "apply", "destroy", "drift")
            and default.exists()
        ):
            snap_file, auto = default, True
    yes = getattr(args, "yes", False)
    offline = snap_file is not None and args.command in (
        "plan",
        "apply",
        "destroy",
    )
    writing = args.command in ("apply", "destroy") and yes
    if gateway is None and (
        args.command in ("snapshot", "drift") or writing or not offline
    ):
        config = load_config()
        if not (
            config.hcs_ak
            and config.hcs_sk
            and config.hcs_endpoint
            and config.hcs_project_id
        ):
            print(
                "error: HCS_AK / HCS_SK / HCS_PROJECT_ID / HCS_ENDPOINT "
                "are required for live reads and writes (validate is "
                "offline; plan can run against --snapshot FILE)",
                file=sys.stderr,
            )
            return _Ctx(project=project), 1
        gateway = _build_gateway(config)
    readers = SnapshotGateway(snap_file) if offline else gateway
    if auto and args.command != "drift":
        print(
            "hcs-sg: planning from snapshot.json (offline) — refresh "
            "with 'hcs-sg snapshot', or delete the file to read live",
            file=sys.stderr,
        )
    return (
        _Ctx(
            project=project,
            gateway=gateway,
            readers=readers,
            snap_arg=snap_arg,
            snap_file=snap_file,
            auto=auto,
            yes=yes,
            offline=offline,
        ),
        None,
    )


def _cmd_validate(args, project) -> int:
    _log.info("phase: validating the project")
    state, load_report = yaml_config.load_project(project)
    if state is None:
        print("\n".join(load_report.errors), file=sys.stderr)
        return 1
    report = validate.validate_state(state)
    if not report.ok:
        print("\n".join(report.errors), file=sys.stderr)
        return 1
    print(
        f"OK: {len(state.groups)} groups, "
        f"{sum(len(rf.ingress) + len(rf.egress) for rf in state.rules.values())} "
        f"rules — validation passed"
    )
    return 0


def _cmd_import(args, project) -> int:
    """Fully offline: a snapshot file in, config files out — the reverse
    of `apply`. Existing files are never clobbered without --force
    (import must not eat hand-written config)."""
    src_arg = getattr(args, "snapshot", None)
    if src_arg:
        p_ = Path(src_arg)
        src = p_ if p_.is_absolute() else project / p_
    else:
        src = project / "snapshot.json"
    if not src.exists():
        print(
            "error: import needs a snapshot — run 'hcs-sg snapshot' "
            "or pass --snapshot FILE",
            file=sys.stderr,
        )
        return 1
    _log.info("phase: importing from %s", src)
    imported = importer.import_snapshot(
        snapshot_from_json(src.read_text(encoding="utf-8")).snapshot
    )
    writes: dict = {}
    for n, g in imported.groups.items():
        writes.update(
            yaml_config.dump_security_group_dir(g, imported.rules.get(n))
        )
    clashes = sorted(
        rel for rel in writes if (project / rel).exists() and not args.force
    )
    if clashes:
        print(
            "error: refusing to overwrite existing file(s) without "
            f"--force: {', '.join(clashes)}",
            file=sys.stderr,
        )
        return 1
    _log.info("phase: writing %d files", len(writes))
    for rel, text in sorted(writes.items()):
        p_ = project / rel
        p_.parent.mkdir(parents=True, exist_ok=True)
        p_.write_text(text, encoding="utf-8")
    n_rules = sum(
        len(rf.ingress) + len(rf.egress) for rf in imported.rules.values()
    )
    if args.json:
        print(
            json.dumps(
                {
                    "imported": sorted(imported.groups),
                    "rules": n_rules,
                    "files": sorted(writes),
                    "notes": list(imported.notes),
                },
                indent=2,
            )
        )
        return 0
    print(
        f"import: {len(imported.groups)} groups, {n_rules} rules -> "
        f"{len(writes)} files under {project}"
    )
    for note in imported.notes:
        print(f"note: {note}")
    print(
        "imported groups are now managed: 'hcs-sg plan' reconciles "
        "the cloud to these files; delete a file to unmanage."
    )
    return 0


def _cmd_drift(args, ctx: _Ctx) -> int:
    _log.info("phase: diffing %s against the live cloud", ctx.snap_file)
    if ctx.snap_file is None:
        print(
            "error: drift needs a snapshot — run 'hcs-sg snapshot' "
            "or pass --snapshot FILE",
            file=sys.stderr,
        )
        return 1
    old = snapshot_from_json(
        ctx.snap_file.read_text(encoding="utf-8")
    ).snapshot
    result = drift_uc.diff_inventory(
        old, read_snapshot(ctx.gateway, ctx.gateway)
    )
    n = sum(len(result[k]) for k in ("missing", "unexpected", "changed"))
    if args.json:  # Liquibase-diff shape (reference=snapshot)
        print(
            json.dumps(
                {
                    "diff": {
                        "created": datetime.datetime.now(
                            datetime.UTC
                        ).isoformat(),
                        "reference": {
                            "kind": "snapshot",
                            "file": ctx.snap_arg or "snapshot.json",
                        },
                        "target": {"kind": "cloud"},
                        "missingObjects": result["missing"],
                        "unexpectedObjects": result["unexpected"],
                        "changedObjects": result["changed"],
                    }
                },
                indent=2,
            )
        )
        return 1 if n else 0
    lines = drift_uc.format_lines(result)
    if lines:
        print("\n".join(lines))
        print(f"\nDrift: {n} change(s) since the snapshot.")
        return 1
    print("no drift: the cloud matches the snapshot")
    return 0


def _cmd_snapshot(args, ctx: _Ctx) -> int:
    _log.info("phase: snapshotting the cloud")
    state, report = yaml_config.load_project(ctx.project)
    if state is None:
        print("\n".join(report.errors), file=sys.stderr)
        return 1
    gateway = ctx.gateway
    if hasattr(gateway, "inventory"):  # whole cloud, 2 calls
        inv = gateway.inventory()
        snap, nics_by_ip = inv.snapshot, inv.nics_by_ip
    else:  # protocol-level fallback
        all_ips = sorted(
            {m.ip for g in state.groups.values() for m in g.members}
        )
        nics_by_ip = gateway.find_nics_by_ip(all_ips) if all_ips else {}
        snap = read_snapshot(gateway, gateway)
    path = ctx.project / args.out
    path.write_text(
        snapshot_to_json(snap.sgs, snap.rules, snap.attached, nics_by_ip),
        encoding="utf-8",
    )
    print(
        f"snapshot: {len(snap.sgs)} groups, "
        f"{sum(len(v) for v in snap.rules.values())} rules, "
        f"{sum(len(v) for v in snap.attached.values())} members, "
        f"{sum(len(v) for v in nics_by_ip.values())} known "
        f"member NICs -> {path}"
    )
    return 0


def _cmd_destroy(args, ctx: _Ctx) -> int:
    al = pipeline.plan_destroy_project(
        ctx.readers, args.name, sleep=time.sleep, notify=_notify
    )
    if not al.actions:
        print(
            f"error: no cloud security group named {args.name!r}",
            file=sys.stderr,
        )
        return 1
    if not ctx.yes:
        _print_plan(
            al, quota=pipeline.quota(ctx.readers, al.actions), args=args
        )
        return 0
    _print_preview(ctx.gateway, al, args)
    results = _execute(ctx.gateway, al, args=args, project=ctx.project)
    rc = _finish(ctx.gateway, al, results, args)
    _snapshot_stale_note(ctx.stale_note_source())
    return rc


def _cmd_plan_apply(args, ctx: _Ctx) -> int:
    planned, errors = pipeline.plan_project(
        yaml_config.load_project,
        ctx.readers,
        ctx.project,
        sleep=time.sleep,
        notify=_notify,
    )
    if planned is None:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.command == "plan" or not ctx.yes:
        _print_plan(
            planned,
            quota=pipeline.quota(ctx.readers, planned.actions),
            args=args,
        )
        return 0
    _print_preview(ctx.gateway, planned, args)  # changes visible, THEN write
    results = _execute(ctx.gateway, planned, args=args, project=ctx.project)
    rc = _finish(ctx.gateway, planned, results, args)
    _snapshot_stale_note(ctx.stale_note_source())
    return rc


def main(argv=None, gateway=None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        _configure_logging()
    project = Path(args.project)

    if args.command == "schema":
        print(schema_export.dumps(args.which))
        return 0
    if args.command == "validate":
        return _cmd_validate(args, project)
    if args.command == "import":
        return _cmd_import(args, project)

    ctx, rc = _resolve_ctx(args, project, gateway)
    if rc is not None:
        return rc
    # Everything below touches a gateway: rate exhaustion waits out the
    # window and continues; anything unretryable that still escapes is
    # ONE clean error line, never a traceback.
    try:
        handlers = {
            "drift": _cmd_drift,
            "snapshot": _cmd_snapshot,
            "destroy": _cmd_destroy,
            "plan": _cmd_plan_apply,
            "apply": _cmd_plan_apply,
        }
        return handlers[args.command](args, ctx)
    except (CloudError, CloudThrottled, QuotaExhausted) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
