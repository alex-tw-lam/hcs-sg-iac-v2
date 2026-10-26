# hcs_sg_iac/engine.py
"""The brain, pure calculation: desired state + observed state →
actions, two snapshots → drift, an action list → executed through a
writer. No I/O of its own (dicts and dataclasses in, actions out);
only execute() touches a gateway, and only through the write Protocol.

Plan semantics: security groups are matched by name; the member IP
list is the truth for membership. Deleting a group = removing its
security-groups/<name>/ directory — the plan detaches its members,
then deletes the SG (the same road additions travel; the API refuses
an SG with ports). An empty groups/ against a non-empty cloud refuses
to plan at all (the whole-estate guard).

New groups: their CreateRule/AttachNic payloads carry sg_id="" — the
executor substitutes the id of the SG it just created for that name."""

import json
import logging
from dataclasses import dataclass, field
from typing import Literal

from hcs_sg_iac.contracts import CloudGateway
from hcs_sg_iac.entities import (
    DesiredState,
    PortSet,
    RemoteGroup,
    Report,
    Rule,
)
from hcs_sg_iac.snapshot import Snapshot

_log = logging.getLogger(__name__)  # --verbose: wired by the CLI


# ---- plan output + executable payloads ----
# One ActionList feeds the renderer (dry-run display) and the executor
# — a single source of truth.


@dataclass(frozen=True)
class CreateSg:
    description: str


@dataclass(frozen=True)
class UpdateSg:
    sg_id: str
    description: str


@dataclass(frozen=True)
class DeleteSg:
    sg_id: str


@dataclass(frozen=True)
class AttachNic:
    sg_id: str
    port_id: str


@dataclass(frozen=True)
class DetachNic:
    sg_id: str
    port_id: str


@dataclass(frozen=True)
class CreateRule:
    sg_id: str
    rule: Rule


@dataclass(frozen=True)
class DeleteRule:
    rule_id: str


@dataclass(frozen=True)
class Action:
    sign: 'Literal["+", "-", "~"]'
    type: 'Literal["member", "rule", "group"]'
    group: str
    detail: str
    cloud_id: str | None = None
    op: "CreateSg | UpdateSg | DeleteSg | AttachNic | DetachNic | CreateRule | DeleteRule | None" = (
        None  # payload above; None for display-only rows
    )


@dataclass(frozen=True)
class ActionList:
    actions: tuple
    unmanaged: tuple  # NOT MANAGED lines
    overlap: tuple  # INFO lines
    clears: tuple = ()  # "egress rules of web" per managed+code-empty
    # direction the plan actually strips

    def summary(self) -> dict:
        counts = {"add": 0, "change": 0, "destroy": 0}
        for a in self.actions:
            counts[{"+": "add", "-": "destroy", "~": "change"}[a.sign]] += 1
        return counts


@dataclass(frozen=True)
class ActionResult:
    action: Action
    status: 'Literal["ok", "failed"]'
    error: str | None = None


# ---- membership resolution (pure: the IP → NIC index comes in) ----


@dataclass(frozen=True)
class Resolution:
    nics: dict = field(default_factory=dict)  # ip -> CloudNic
    report: Report = field(default_factory=Report)
    overlaps: tuple = ()


def _q(s: str) -> str:
    """Double-quoted display form (json quoting escapes embedded quotes)."""
    return json.dumps(s)


def _sub_rules(rule: Rule) -> tuple:
    """One code rule with a multi-entry ports
    list expands to one cloud rule per entry ("22,443" -> "22" + "443");
    ports=None stays a single rule. Cloud identities are always
    single-range, so planning against the expanded sub-rules is what
    makes multi-port rules converge against the real API."""
    if rule.ports is None:
        return (rule,)
    return tuple(
        Rule(
            direction=rule.direction,
            protocol=rule.protocol,
            ports=PortSet(p),
            remote=rule.remote,
        )
        for p in rule.ports.entries
    )


def _fmt_rule_detail(direction: str, protocol: str, ports, remote) -> str:
    """Shared display form for code rules and cloud rules alike."""
    remote_s = (
        f"group:{remote.name}"
        if isinstance(remote, RemoteGroup)
        else f"cidr:{remote.cidr}"
    )
    prep = "from" if direction == "ingress" else "to"
    return f"{direction} {protocol} {ports or 'all'} {prep} {remote_s}"


def _name_to_sg(snapshot: Snapshot) -> dict:
    """cloud name -> CloudSg; raises (with EVERY duplicate name and id
    enumerated) when the cloud holds a duplicated name — reporting only
    the first pair found would hide the rest of the cleanup work."""
    by_name: dict = {}
    for sg in snapshot.sgs:
        by_name.setdefault(sg.name, []).append(sg)
    dupes = {n: sgs for n, sgs in by_name.items() if len(sgs) > 1}
    if dupes:
        raise ValueError(
            "duplicate cloud security group name(s) — rename in the cloud "
            "before planning: "
            + "; ".join(
                f"'{name}' ({', '.join(s.id for s in sgs)})"
                for name, sgs in sorted(dupes.items())
            )
        )
    return {sg.name: sg for sg in snapshot.sgs}


def _plan_group_row(gname, group, cloud_sg, actions):
    """The group's own row: create when absent, update on description
    drift."""
    if cloud_sg is None:
        actions.append(
            Action(
                "+",
                "group",
                gname,
                f"description: {_q(group.description)}",
                op=CreateSg(description=group.description),
            )
        )
    elif group.description != cloud_sg.description:
        actions.append(
            Action(
                "~",
                "group",
                gname,
                f"description: {_q(cloud_sg.description)} -> "
                f"{_q(group.description)}",
                cloud_id=cloud_sg.id,
                op=UpdateSg(sg_id=cloud_sg.id, description=group.description),
            )
        )


def _plan_members(gname, group, cloud_sg, snapshot, resolution, actions):
    """Membership: the IP list is the truth (missing -> attach, extra ->
    detach)."""
    desired_ips = {m.ip for m in group.members}
    attached_ips = (
        {n.ip for n in snapshot.attached[cloud_sg.id]} if cloud_sg else set()
    )
    for m in group.members:
        if cloud_sg and m.ip in attached_ips:
            continue
        nic = resolution.nics.get(m.ip)
        if nic is None:  # proven unreachable when resolution passed,
            raise ValueError(  # but a raise survives `python -O`
                f"ip {m.ip} did not resolve — resolution.report must "
                f"be ok before plan()"
            )
        detail = f"ip {m.ip}" + (f" (vm={nic.vm_name})" if nic.vm_name else "")
        actions.append(
            Action(
                "+",
                "member",
                gname,
                detail,
                cloud_id=nic.port_id,
                op=AttachNic(
                    sg_id=cloud_sg.id if cloud_sg else "",
                    port_id=nic.port_id,
                ),
            )
        )
    if not cloud_sg:
        return
    for n in snapshot.attached[cloud_sg.id]:
        if n.ip not in desired_ips:
            actions.append(
                Action(
                    "-",
                    "member",
                    gname,
                    f"ip {n.ip or n.port_id}",
                    cloud_id=n.port_id,
                    op=DetachNic(sg_id=cloud_sg.id, port_id=n.port_id),
                )
            )


def _plan_managed_direction(
    gname, cloud_sg, direction, wanted, snapshot, id_to_name, actions, clears
):
    """One MANAGED direction: create what code wants and the cloud
    lacks; delete what the cloud has and code does not (self-referential
    cloud rules are never stale — see _plan_rules)."""
    cloud_now = [
        r
        for r in (snapshot.rules.get(cloud_sg.id, []) if cloud_sg else [])
        if r.direction == direction
    ]
    own_id = cloud_sg.id if cloud_sg else None
    subs = list(
        {s.identity(): s for r in wanted for s in _sub_rules(r)}.values()
    )
    wanted_ids = {s.identity() for s in subs}
    cloud_ids = {r.identity(id_to_name) for r in cloud_now}
    for s in subs:
        if s.identity() not in cloud_ids:
            actions.append(
                Action(
                    "+",
                    "rule",
                    gname,
                    _fmt_rule_detail(*s.identity()),
                    cloud_id=None,
                    op=CreateRule(
                        sg_id=cloud_sg.id if cloud_sg else "", rule=s
                    ),
                )
            )
    stale = [
        cr
        for cr in cloud_now
        if cr.identity(id_to_name) not in wanted_ids
        and cr.remote_group_id != own_id
    ]
    for cr in stale:
        actions.append(
            Action(
                "-",
                "rule",
                gname,
                _fmt_rule_detail(*cr.identity(id_to_name)),
                cloud_id=cr.id,
                op=DeleteRule(rule_id=cr.id),
            )
        )
    # A managed direction with an empty code list strips every cloud
    # rule except the preserved self rules: that fact travels as data
    # (clears), so the clear-all warning never parses display strings.
    # Only when stale is non-empty — a []-direction with nothing (or
    # only self rules) to delete must not raise a false alarm.
    if not wanted and stale:
        clears.append(f"{direction} rules of {gname}")


def _plan_rules(
    gname, cloud_sg, rf, snapshot, id_to_name, actions, unmanaged, clears
):
    """Rules per direction. An UNMANAGED direction (no rules file for
    the group, or the direction file absent) never touches the cloud
    side — its cloud rules are only inventoried into `unmanaged`.
    HCS auto-adds self-referential rules on SG create (allow within the
    SG: remote_group_id = the SG's own id): they stay visible so a
    CODED self-reference still matches them, but they are never stale —
    convergence must not strip the cloud's own defaults, not even for a
    managed [] direction."""
    directions = (
        (
            ("ingress", rf.ingress_managed, rf.ingress),
            ("egress", rf.egress_managed, rf.egress),
        )
        if rf is not None
        else (
            ("ingress", False, ()),
            ("egress", False, ()),
        )
    )
    for direction, managed, wanted in directions:
        if not managed:
            if cloud_sg and snapshot.rules.get(cloud_sg.id):
                n = sum(
                    1
                    for r in snapshot.rules[cloud_sg.id]
                    if r.direction == direction
                )
                if n:
                    unmanaged.append(
                        f"{direction} rules of {gname} "
                        f"({n} cloud rules untouched)"
                    )
            continue
        _plan_managed_direction(
            gname,
            cloud_sg,
            direction,
            wanted,
            snapshot,
            id_to_name,
            actions,
            clears,
        )


def _plan_absent_groups(state: DesiredState, snapshot: Snapshot, actions):
    """Cloud SGs whose security-groups/<name>/ directory is gone: the
    directory's absence IS the delete instruction — detach the members
    first (the API refuses an SG with ports), then delete the SG. Rules
    go implicitly with the SG cascade."""
    for sg in snapshot.sgs:
        if sg.name in state.groups:
            continue
        for n in snapshot.attached[sg.id]:
            actions.append(
                Action(
                    "-",
                    "member",
                    sg.name,
                    f"ip {n.ip or n.port_id}",
                    cloud_id=n.port_id,
                    op=DetachNic(sg_id=sg.id, port_id=n.port_id),
                )
            )
        actions.append(
            Action(
                "-",
                "group",
                sg.name,
                "delete security group (directory removed)",
                cloud_id=sg.id,
                op=DeleteSg(sg_id=sg.id),
            )
        )


def plan(
    state: DesiredState, resolution: Resolution, snapshot: Snapshot
) -> ActionList:
    actions: list = []
    unmanaged: list = []
    clears: list = []  # managed+code-empty directions we strip
    id_to_name = {sg.id: sg.name for sg in snapshot.sgs}
    name_to_sg = _name_to_sg(snapshot)

    if not state.groups and snapshot.sgs:
        raise ValueError(
            f"security-groups/ is empty but the cloud holds "
            f"{len(snapshot.sgs)} security group(s) — refusing to plan "
            f"the deletion of the whole estate"
        )
    _plan_absent_groups(state, snapshot, actions)

    for gname in sorted(state.groups):
        group = state.groups[gname]
        cloud_sg = name_to_sg.get(gname)
        _plan_group_row(gname, group, cloud_sg, actions)
        _plan_members(gname, group, cloud_sg, snapshot, resolution, actions)
        _plan_rules(
            gname,
            cloud_sg,
            state.rules.get(gname),
            snapshot,
            id_to_name,
            actions,
            unmanaged,
            clears,
        )

    return ActionList(
        actions=tuple(actions),
        unmanaged=tuple(unmanaged),
        overlap=resolution.overlaps,
        clears=tuple(sorted(clears)),
    )


# ---- membership resolution ----


def resolve_memberships(nics_by_ip: dict, state: DesiredState) -> Resolution:
    """Every member IP must resolve to exactly one NIC in the account
    (the IP → NIC index comes from the inventory, so this is pure).
    Overlaps between groups are allowed → info."""
    report = Report()
    nics: dict = {}
    for g in state.groups.values():
        for m in g.members:
            found = nics_by_ip.get(m.ip, [])
            if not found:
                report.error(
                    f"security-groups/{g.name}/group.yaml",
                    f"ip {m.ip}: no NIC found in any VPC of the account",
                )
            elif len(found) > 1:
                cands = ", ".join(
                    f"port={n.port_id}"
                    + (f" vm={n.vm_name}" if n.vm_name else "")
                    for n in found
                )
                report.error(
                    f"security-groups/{g.name}/group.yaml",
                    f"ip {m.ip}: matches multiple NICs ({cands})"
                    f"use a unique IP or a nic: entry",
                )
            else:
                nics[m.ip] = found[0]

    owner: dict = {}
    for gname in sorted(state.groups):
        for m in state.groups[gname].members:
            if m.ip in nics:
                owner.setdefault(m.ip, []).append(gname)
    overlaps = []
    for ip, groups in sorted(owner.items()):
        if len(groups) > 1:
            overlaps.append(f"{ip} in groups {', '.join(sorted(groups))}")

    return Resolution(nics=nics, report=report, overlaps=tuple(overlaps))


# ---- execution ----

# Execution order: create the SG first (so later ops can reference it),
# then metadata, then allow-rules and members, then removals, SG delete
# last.
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
    a failure never aborts the run; dependents of a failed group create
    are skipped, not orphaned."""
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


# ---- drift: two snapshots → a Liquibase-diff-shaped report ----

_RULE_FIELDS = (
    "direction",
    "protocol",
    "ports",
    "remote_group_id",
    "remote_ip_prefix",
)


def diff_inventory(old: Snapshot, new: Snapshot) -> dict:
    """Cloud-side drift. reference = old (the snapshot), target = new
    (the live cloud). Returns {"missing": [...], "unexpected": [...],
    "changed": [...]}; entries carry {"type": group|rule|member, "id",
    name/sg} and changed ones add {"differences": [{"field",
    "referenceValue", "comparedValue"}]} — keyed by cloud ID throughout,
    so duplicated names never confuse the diff; renames surface as a
    `name` difference."""
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
