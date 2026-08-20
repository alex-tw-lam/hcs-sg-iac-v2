# hcs_sg_iac/cli/render.py
"""Presentation: ONE ActionList → table or JSON. Prefix discipline:
member→nic=, group→sg=, rule→rule=; "+ rule" rows without a cloud id
print (new)."""

import datetime
import json

_PREFIX = {"member": "nic=", "group": "sg=", "rule": "rule="}


def _display_id(action) -> str:
    if action.cloud_id is None:
        return "(new)" if action.sign == "+" else ""
    return _PREFIX.get(action.type, "") + action.cloud_id


def _row(cells: list, widths: list) -> str:
    return "  ".join(
        str(c).ljust(w) for c, w in zip(cells, widths, strict=True)
    ).rstrip()


def _table(al, executed) -> list:
    """The plan table: header + one aligned row per action, with the
    RESULT column paired by key when execution results are given."""
    headers = ["ACTION", "TYPE", "GROUP", "DETAIL", "CLOUD ID"]
    if executed is not None:
        headers.append("RESULT")
    rows = [
        [a.sign, a.type, a.group, a.detail, _display_id(a)] for a in al.actions
    ]
    if executed is not None:
        by_key = {r.action: r for r in executed}  # Action is frozen/hashable
        for row, a in zip(rows, al.actions, strict=True):
            r = by_key.get(a)
            row.append(r.status if r else "-")
    widths = [
        max(len(str(r[i])) for r in [headers, *rows])
        for i in range(len(headers))
    ]
    return [_row(headers, widths)] + [_row(row, widths) for row in rows]


def render_plan(al, quota=None, executed=None, dry_run: bool = True) -> str:
    lines = _table(al, executed)

    s = al.summary()
    lines.append("")
    lines.append(
        f"Plan: {s['add']} to add, {s['change']} to change, "
        f"{s['destroy']} to destroy."
    )
    # WARN only for managed+empty directions the plan will ACTUALLY strip
    # (the plan engine computed that set as ActionList.clears): a
    # []-direction with no cloud rules deletes nothing — no false alarm.
    if al.clears:
        lines.append(f"WARNING: this removes ALL {', '.join(al.clears)}.")
    if quota:
        if quota.left is None:  # gateway without quota_snapshot
            lines.append(
                f"Quota: {quota.needed} calls needed, " f"remaining unknown."
            )
        else:
            lines.append(
                f"Quota: {quota.needed} calls needed, "
                f"{quota.left} left in this window."
            )
    for u in al.unmanaged:
        lines.append(f"NOT MANAGED: {u}")
    for o in al.overlap:
        lines.append(f"INFO: IP overlap (allowed): {o}.")
    if executed is not None:
        counts = {
            k: sum(1 for r in executed if r.status == k)
            for k in ("ok", "failed", "throttled")
        }
        lines.append("")
        lines.append(
            f"Apply complete: {counts['ok']} ok, "
            f"{counts['failed']} failed, {counts['throttled']} "
            f"throttled (re-run to resume)."
        )
    if dry_run and executed is None:
        lines.append("")
        lines.append("Dry run — re-run with --yes to perform these changes.")
    return "\n".join(lines)


def render_json(al, quota=None, executed=None) -> str:
    data = {
        "actions": [
            {
                "action": a.sign,
                "type": a.type,
                "group": a.group,
                "detail": a.detail,
                "cloud_id": _display_id(a),
            }
            for a in al.actions
        ],
        "summary": al.summary(),
        "quota": quota.asdict() if quota else None,
        "unmanaged": list(al.unmanaged),
        "overlap": list(al.overlap),
    }
    if executed is not None:
        data["results"] = [
            {"status": r.status, "error": r.error, "detail": r.action.detail}
            for r in executed
        ]
    return json.dumps(data, indent=2)


def render_drift_lines(result: dict) -> tuple:
    """Human text for a diff_inventory result — one line per change,
    grouped '-/+'/'~' (the CLI prints; rc 1 when non-empty)."""
    lines = []
    for e in result["missing"]:
        if e["type"] == "group":
            lines.append(f"- group {e['name']} ({e['id']}) deleted")
        elif e["type"] == "rule":
            lines.append(f"- rule {e['id']} of {e['sg']}")
        else:
            lines.append(f"- member {e['id']} detached from {e['sg']}")
    for e in result["unexpected"]:
        if e["type"] == "group":
            lines.append(f"+ group {e['name']} ({e['id']}) created")
        elif e["type"] == "rule":
            lines.append(f"+ rule {e['id']} of {e['sg']}")
        else:
            lines.append(f"+ member {e['id']} attached to {e['sg']}")
    for e in result["changed"]:
        d = {x["field"]: x for x in e["differences"]}
        if e["type"] == "group":
            if "name" in d:
                lines.append(
                    f"~ group {e['id']}: renamed "
                    f"{d['name']['referenceValue']!r} -> "
                    f"{d['name']['comparedValue']!r}"
                )
            if "description" in d:
                lines.append(
                    f"~ group {e['name']} ({e['id']}): " f"description changed"
                )
        else:
            fields = ", ".join(d)
            lines.append(f"~ rule {e['id']} of {e['sg']}: {fields} changed")
    return tuple(lines)


def render_drift_json(result: dict, reference_file: str) -> dict:
    """The complete Liquibase-diff envelope (the --json document body):
    the whole wire shape lives in THIS ring, not split with the CLI."""
    return {
        "diff": {
            "created": datetime.datetime.now(datetime.UTC).isoformat(),
            "reference": {"kind": "snapshot", "file": reference_file},
            "target": {"kind": "cloud"},
            "missingObjects": result["missing"],
            "unexpectedObjects": result["unexpected"],
            "changedObjects": result["changed"],
        }
    }
