# hcs_sg_iac/usecases/plan.py
"""The plan engine (pure): desired state + snapshot → ActionList.
No state file: security groups are matched by name; the member IP list
is the truth for membership.

New groups: their CreateRule/AttachNic payloads carry sg_id="" — apply
substitutes the id of the SG it just created for that group name."""

import json
import logging

from hcs_sg_iac.model.actions import (
    Action,
    ActionList,
    AttachNic,
    CreateRule,
    CreateSg,
    DeleteRule,
    DeleteSg,
    DetachNic,
    UpdateSg,
)
from hcs_sg_iac.model.cloud import Snapshot
from hcs_sg_iac.model.common import RemoteGroup
from hcs_sg_iac.model.entities import DesiredState, Rule
from hcs_sg_iac.model.portset import PortSet
from hcs_sg_iac.usecases.resolve import Resolution

_log = logging.getLogger(__name__)  # --verbose: wired by the CLI


def _q(s: str) -> str:
    """Double-quoted display form (json quoting escapes embedded quotes)."""
    return json.dumps(s)


def read_snapshot(gateway) -> Snapshot:
    """The observed cloud in one pass. inventory() is THE read seam
    (every gateway implements it); the old per-SG fallback loop died
    with the protocol sprawl."""
    _log.info("phase: reading cloud snapshot")
    return gateway.inventory().snapshot


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


def plan(
    state: DesiredState, resolution: Resolution, snapshot: Snapshot
) -> ActionList:
    actions: list = []
    unmanaged: list = []
    clears: list = []  # managed+code-empty directions we strip
    id_to_name = {sg.id: sg.name for sg in snapshot.sgs}
    name_to_sg = _name_to_sg(snapshot)

    for sg in snapshot.sgs:
        if sg.name not in state.groups:
            unmanaged.append(
                f"security group '{sg.name}' "
                f"(no security-groups/{sg.name}/)"
            )

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


def plan_destroy(name: str, snapshot: Snapshot) -> ActionList:
    """Explicit whole-SG deletion: detach everything, then delete the SG.
    Rules are deleted implicitly by the SG cascade — no per-rule ops and
    no per-rule quota cost."""
    sg = next((s for s in snapshot.sgs if s.name == name), None)
    if sg is None:
        return ActionList(actions=(), unmanaged=(), overlap=())
    actions = [
        Action(
            "-",
            "member",
            name,
            f"ip {n.ip or n.port_id}",
            cloud_id=n.port_id,
            op=DetachNic(sg_id=sg.id, port_id=n.port_id),
        )
        for n in snapshot.attached.get(sg.id, [])
    ]
    actions.append(
        Action(
            "-",
            "group",
            name,
            "delete security group",
            cloud_id=sg.id,
            op=DeleteSg(sg_id=sg.id),
        )
    )
    return ActionList(actions=tuple(actions), unmanaged=(), overlap=())
