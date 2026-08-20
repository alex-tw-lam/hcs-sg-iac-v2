# hcs_sg_iac/usecases/drift.py
"""Cloud-side drift: diff two Snapshots (a saved file vs a fresh read),
Liquibase-diff shaped: missing (in the reference, gone from the cloud),
unexpected (appeared in the cloud), changed (same id, different
fields). Keyed by cloud ID throughout — duplicated names (SGs, VMs)
never confuse the diff; renames surface as a `name` difference."""

from hcs_sg_iac.model.cloud import Snapshot

_RULE_FIELDS = (
    "direction",
    "protocol",
    "ports",
    "remote_group_id",
    "remote_ip_prefix",
)


def diff_inventory(old: Snapshot, new: Snapshot) -> dict:
    """reference = old (the snapshot), target = new (the live cloud).
    Returns {"missing": [...], "unexpected": [...], "changed": [...]};
    entries carry {"type": group|rule|member, "id", name/sg} and
    changed ones add {"differences": [{"field", "referenceValue",
    "comparedValue"}]}."""
    missing, unexpected, changed = [], [], []
    old_sgs, new_sgs = {s.id: s for s in old.sgs}, {s.id: s for s in new.sgs}
    for sid in sorted(set(old_sgs) - set(new_sgs)):
        missing.append({"type": "group", "id": sid, "name": old_sgs[sid].name})
    for sid in sorted(set(new_sgs) - set(old_sgs)):
        unexpected.append(
            {"type": "group", "id": sid, "name": new_sgs[sid].name}
        )
    for sid in sorted(set(old_sgs) & set(new_sgs)):
        o, n = old_sgs[sid], new_sgs[sid]
        label = n.name or sid
        diffs = [
            {
                "field": f,
                "referenceValue": getattr(o, f),
                "comparedValue": getattr(n, f),
            }
            for f in ("name", "description")
            if getattr(o, f) != getattr(n, f)
        ]
        if diffs:
            changed.append(
                {
                    "type": "group",
                    "id": sid,
                    "name": label,
                    "differences": diffs,
                }
            )
        _diff_rules(old, new, sid, label, missing, unexpected, changed)
        _diff_members(old, new, sid, label, missing, unexpected)
    return {"missing": missing, "unexpected": unexpected, "changed": changed}


def _diff_rules(old, new, sid, label, missing, unexpected, changed):
    old_rules = {r.id: r for r in old.rules.get(sid, [])}
    new_rules = {r.id: r for r in new.rules.get(sid, [])}
    for rid in sorted(set(old_rules) - set(new_rules)):
        missing.append({"type": "rule", "id": rid, "sg": label})
    for rid in sorted(set(new_rules) - set(old_rules)):
        unexpected.append({"type": "rule", "id": rid, "sg": label})
    for rid in sorted(set(old_rules) & set(new_rules)):
        a, b = old_rules[rid], new_rules[rid]
        diffs = [
            {
                "field": f,
                "referenceValue": getattr(a, f),
                "comparedValue": getattr(b, f),
            }
            for f in _RULE_FIELDS
            if getattr(a, f) != getattr(b, f)
        ]
        if diffs:
            changed.append(
                {"type": "rule", "id": rid, "sg": label, "differences": diffs}
            )


def _diff_members(old, new, sid, label, missing, unexpected):
    old_ports = {x.port_id for x in old.attached.get(sid, [])}
    new_ports = {x.port_id for x in new.attached.get(sid, [])}
    for pid in sorted(old_ports - new_ports):
        missing.append({"type": "member", "id": pid, "sg": label})
    for pid in sorted(new_ports - old_ports):
        unexpected.append({"type": "member", "id": pid, "sg": label})


def format_lines(result: dict) -> tuple:
    """Human text for a diff_inventory result — one line per change,
    grouped '-/+'/'~' (the shape the CLI prints; rc 1 when non-empty)."""
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
