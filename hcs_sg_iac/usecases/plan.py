# hcs_sg_iac/usecases/plan.py
"""The plan engine (pure): desired state + snapshot → ActionList.
No state file: security groups are matched by name; the member IP list
is the truth for membership.

New groups: their CreateRule/AttachNic payloads carry sg_id="" — apply
substitutes the id of the SG it just created for that group name."""
import json

from hcs_sg_iac.model.actions import (Action, ActionList, AttachNic,
                                      CreateRule, CreateSg, DeleteRule,
                                      DeleteSg, DetachNic, UpdateSg)
from hcs_sg_iac.model.cloud import CloudRule, Snapshot
from hcs_sg_iac.model.entities import DesiredState, Rule
from hcs_sg_iac.model.remote import RemoteCidr, RemoteGroup
from hcs_sg_iac.usecases.resolve import Resolution


def _q(s: str) -> str:
    """Double-quoted display form (json quoting escapes embedded quotes)."""
    return json.dumps(s)


def read_snapshot(sg_reader, membership_reader) -> Snapshot:
    """Assemble the cloud snapshot via the reader protocols."""
    sgs = tuple(sg_reader.list_security_groups())
    rules = {sg.id: list(sg_reader.list_rules(sg.id)) for sg in sgs}
    attached = {sg.id: list(membership_reader.list_attached_nics(sg.id))
                for sg in sgs}
    return Snapshot(sgs=sgs, rules=rules, attached=attached)


def _cloud_rule_identity(cr: CloudRule, id_to_name: dict):
    if cr.remote_group_id:
        remote = RemoteGroup(name=id_to_name.get(cr.remote_group_id,
                                                 cr.remote_group_id))
    elif cr.remote_ip_prefix:
        try:
            remote = RemoteCidr(cidr=cr.remote_ip_prefix)
        except ValueError:
            # e.g. an IPv6 remote our IPv4-only model cannot express:
            # an identity no code rule can ever match -> honest delete.
            remote = RemoteGroup(name=f"unrepresentable-remote"
                                      f"({cr.remote_ip_prefix})")
    else:
        remote = RemoteCidr(cidr="0.0.0.0/0")     # API default when unset
    return (cr.direction, cr.protocol or "all", cr.ports, remote)


def _sub_rules(rule: Rule) -> tuple:
    """docs/design-spec.md §6: one code rule with a multi-entry ports
    list expands to one cloud rule per entry ("22,443" -> "22" + "443");
    ports=None stays a single rule. Cloud identities are always
    single-range, so planning against the expanded sub-rules is what
    makes multi-port rules converge against the real API."""
    if rule.ports is None:
        return (rule,)
    return tuple(Rule(direction=rule.direction, protocol=rule.protocol,
                      ports=p, remote=rule.remote)
                 for p in rule.ports.split(","))


def _fmt_rule_detail(direction: str, protocol: str, ports, remote) -> str:
    """Shared display form for code rules and cloud rules alike."""
    remote_s = (f"group:{remote.name}" if isinstance(remote, RemoteGroup)
                else f"cidr:{remote.cidr}")
    prep = "from" if direction == "ingress" else "to"
    return f"{direction} {protocol} {ports or 'all'} {prep} {remote_s}"


def _rule_detail(rule: Rule) -> str:
    return _fmt_rule_detail(rule.direction, rule.protocol, rule.ports,
                            rule.remote)


def _cloud_rule_detail(cr: CloudRule, id_to_name: dict) -> str:
    direction, protocol, ports, remote = _cloud_rule_identity(cr, id_to_name)
    return _fmt_rule_detail(direction, protocol, ports, remote)


def plan(state: DesiredState, resolution: Resolution, snapshot: Snapshot) -> ActionList:
    actions: list = []
    unmanaged: list = []
    clears: list = []                # managed+code-empty directions we strip
    id_to_name = {sg.id: sg.name for sg in snapshot.sgs}
    name_to_sg: dict = {}
    for sg in snapshot.sgs:
        if sg.name in name_to_sg:
            raise ValueError(f"duplicate cloud security group name '{sg.name}' "
                             f"({name_to_sg[sg.name].id}, {sg.id}) — "
                             f"rename one in the cloud before planning")
        name_to_sg[sg.name] = sg

    for sg in snapshot.sgs:
        if sg.name not in state.groups:
            unmanaged.append(f"security group '{sg.name}' "
                             f"(no groups/{sg.name}.yaml)")

    for gname in sorted(state.groups):
        group = state.groups[gname]
        rf = state.rules.get(gname)
        cloud_sg = name_to_sg.get(gname)

        if cloud_sg is None:
            actions.append(Action("+", "group", gname,
                                  f"description: {_q(group.description)}",
                                  op=CreateSg(description=group.description)))
        else:
            if group.description != cloud_sg.description:
                actions.append(Action(
                    "~", "group", gname,
                    f"description: {_q(cloud_sg.description)} -> "
                    f"{_q(group.description)}",
                    cloud_id=cloud_sg.id,
                    op=UpdateSg(sg_id=cloud_sg.id,
                                description=group.description)))

        # ---- membership: the IP list is the truth ----
        desired_ips = {m.ip for m in group.members}
        attached_ips = ({n.ip for n in snapshot.attached[cloud_sg.id]}
                        if cloud_sg else set())
        for m in group.members:
            if cloud_sg and m.ip in attached_ips:
                continue
            nic = resolution.nics.get(m.ip)
            assert nic is not None, (f"ip {m.ip} did not resolve — "
                                     f"resolution.report must be ok "
                                     f"before plan()")
            detail = f"ip {m.ip}" + (f" (vm={nic.vm_name})" if nic.vm_name else "")
            actions.append(Action("+", "member", gname, detail,
                                  cloud_id=nic.port_id,
                                  op=AttachNic(sg_id=cloud_sg.id if cloud_sg else "",
                                               port_id=nic.port_id)))

        if cloud_sg:
            for n in snapshot.attached[cloud_sg.id]:
                if n.ip not in desired_ips:
                    actions.append(Action("-", "member", gname,
                                          f"ip {n.ip or n.port_id}",
                                          cloud_id=n.port_id,
                                          op=DetachNic(sg_id=cloud_sg.id,
                                                       port_id=n.port_id)))

        # ---- rules per managed direction ----
        # No rules file for the group: BOTH directions are unmanaged
        # (docs/design-spec.md §2.3).
        if rf is not None:
            directions = (("ingress", rf.ingress_managed, rf.ingress),
                          ("egress", rf.egress_managed, rf.egress))
        else:
            directions = (("ingress", False, ()),
                          ("egress", False, ()))
        for direction, managed, wanted in directions:
            if not managed:
                if cloud_sg and snapshot.rules.get(cloud_sg.id):
                    n = sum(1 for r in snapshot.rules[cloud_sg.id]
                            if r.direction == direction)
                    if n:
                        unmanaged.append(f"{direction} rules of {gname} "
                                         f"({n} cloud rules untouched)")
                continue
            cloud_now = [r for r in (snapshot.rules.get(cloud_sg.id, [])
                                     if cloud_sg else [])
                         if r.direction == direction]
            subs = list({s.identity(): s
                         for r in wanted for s in _sub_rules(r)}.values())
            wanted_ids = {s.identity() for s in subs}
            cloud_ids = {_cloud_rule_identity(r, id_to_name)
                         for r in cloud_now}
            for s in subs:
                if s.identity() not in cloud_ids:
                    actions.append(Action(
                        "+", "rule", gname, _rule_detail(s),
                        cloud_id=None,
                        op=CreateRule(sg_id=cloud_sg.id if cloud_sg else "",
                                      rule=s)))
            stale = [cr for cr in cloud_now
                     if _cloud_rule_identity(cr, id_to_name) not in wanted_ids]
            for cr in stale:
                actions.append(Action(
                    "-", "rule", gname,
                    _cloud_rule_detail(cr, id_to_name),
                    cloud_id=cr.id, op=DeleteRule(rule_id=cr.id)))
            # A managed direction with an empty code list strips every
            # cloud rule: that fact travels as data (clears), so the
            # clear-all warning never parses display strings. Only when
            # stale is non-empty — a []-direction with no cloud rules
            # deletes nothing and must not raise a false alarm.
            if not wanted and stale:
                clears.append(f"{direction} rules of {gname}")

    return ActionList(actions=tuple(actions), unmanaged=tuple(unmanaged),
                      overlap=resolution.overlaps, clears=tuple(sorted(clears)))


def plan_destroy(name: str, snapshot: Snapshot) -> ActionList:
    """Explicit whole-SG deletion: detach everything, then delete the SG.
    Rules are deleted implicitly by the SG cascade — no per-rule ops and
    no per-rule quota cost."""
    sg = next((s for s in snapshot.sgs if s.name == name), None)
    if sg is None:
        return ActionList(actions=(), unmanaged=(), overlap=())
    actions = [Action("-", "member", name, f"ip {n.ip or n.port_id}",
                      cloud_id=n.port_id,
                      op=DetachNic(sg_id=sg.id, port_id=n.port_id))
               for n in snapshot.attached.get(sg.id, [])]
    actions.append(Action("-", "group", name, "delete security group",
                          cloud_id=sg.id, op=DeleteSg(sg_id=sg.id)))
    return ActionList(actions=tuple(actions), unmanaged=(), overlap=())
