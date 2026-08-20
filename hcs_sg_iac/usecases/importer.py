# hcs_sg_iac/usecases/importer.py
"""Reverse import: a cloud Snapshot becomes config files — the
"adopt the estate" path, offline. Deliberately conservative: anything
the config format cannot represent EXACTLY is skipped WITH a note,
never silently approximated (a skipped RULE becomes an honest stale
delete on the next plan; a skipped GROUP stays unmanaged). Both
directions of every imported group are managed."""

from dataclasses import dataclass, field

from hcs_sg_iac.model.cloud import Snapshot
from hcs_sg_iac.model.common import RemoteCidr, RemoteGroup
from hcs_sg_iac.model.entities import (
    GROUP_NAME_RE,
    PROTOCOLS,
    Group,
    Member,
    Rule,
    RulesFile,
)

_DELETE_NOTE = (
    " — apply will plan this rule as a delete (remove it in "
    "the cloud first if you want to keep it)"
)


@dataclass(frozen=True)
class ImportedState:
    groups: dict = field(default_factory=dict)  # name -> Group
    rules: dict = field(default_factory=dict)  # name -> RulesFile
    notes: tuple = ()  # every skip, human-readable


def _representable(snap: Snapshot) -> "tuple[dict, list]":
    """Which cloud SGs can become a config file at all: sg_id -> name
    (the FIRST occurrence of a duplicate name wins; losers noted)."""
    notes: list = []
    representable: dict = {}
    by_name: dict = {}  # name -> winning sg_id
    for sg in sorted(snap.sgs, key=lambda s: (s.name, s.id)):
        if not GROUP_NAME_RE.fullmatch(sg.name):
            notes.append(
                f"skip group {sg.name!r} ({sg.id}): name cannot "
                f"become a config file (must match "
                f"{GROUP_NAME_RE.pattern})"
            )
        elif sg.name in by_name:
            notes.append(
                f"skip group {sg.name!r} ({sg.id}): duplicate "
                f"cloud name — config keys groups by name "
                f"(kept {by_name[sg.name]})"
            )
        else:
            by_name[sg.name] = sg.id
            representable[sg.id] = sg.name
    return representable, notes


def import_snapshot(snap: Snapshot) -> ImportedState:
    representable, notes = _representable(snap)
    id_to_name = {s.id: s.name for s in snap.sgs}

    groups: dict = {}
    rules: dict = {}
    for sg in sorted(snap.sgs, key=lambda s: (s.name, s.id)):
        name = representable.get(sg.id)
        if name is None:
            continue
        members = tuple(
            Member(ip=ip)
            for ip in dict.fromkeys(  # order-preserving dedupe
                n.ip
                for n in snap.attached.get(sg.id, ())
                if n.ip and "." in n.ip
            )
        )
        wanted: dict = {"ingress": [], "egress": []}
        identities: dict = {"ingress": set(), "egress": set()}
        self_rules = 0
        for r in snap.rules.get(sg.id, ()):
            if r.remote_group_id == sg.id:
                self_rules += 1
                continue
            protocol = r.protocol or "all"
            if r.direction not in wanted or protocol not in PROTOCOLS:
                notes.append(
                    f"skip rule {r.id} of {name!r}: "
                    f"{r.direction}/{r.protocol!r} not representable"
                    f"{_DELETE_NOTE}"
                )
                continue
            remote: RemoteGroup | RemoteCidr
            if r.remote_group_id:
                target = representable.get(r.remote_group_id)
                if target is None:
                    notes.append(
                        f"skip rule {r.id} of {name!r}: references "
                        f"group {id_to_name.get(r.remote_group_id)!r} "
                        f"that cannot be imported{_DELETE_NOTE}"
                    )
                    continue
                remote = RemoteGroup(name=target)
            elif r.remote_ip_prefix:
                try:
                    remote = RemoteCidr(cidr=r.remote_ip_prefix)
                except ValueError:
                    notes.append(
                        f"skip rule {r.id} of {name!r}: "
                        f"{r.remote_ip_prefix!r} is not a v4 CIDR"
                        f"{_DELETE_NOTE}"
                    )
                    continue
            else:
                # Unset remote == anywhere: the plan engine already gives
                # such cloud rules the 0.0.0.0/0 identity ("API default
                # when unset"); import must agree or the rule would show
                # up as a phantom stale delete on the next plan.
                remote = RemoteCidr(cidr="0.0.0.0/0")
            rule = Rule(
                direction=r.direction,
                protocol=protocol,
                ports=r.ports,
                remote=remote,
            )
            if rule.identity() in identities[r.direction]:
                notes.append(
                    f"skip rule {r.id} of {name!r}: duplicate of an "
                    f"imported rule{_DELETE_NOTE}"
                )
                continue
            identities[r.direction].add(rule.identity())
            wanted[r.direction].append(rule)
        if self_rules:
            notes.append(
                f"{name!r}: {self_rules} self-referential rule(s) "
                f"not written (the platform re-adds them; the plan "
                f"preserves them)"
            )
        groups[name] = Group(
            name=name, description=sg.description, members=members
        )
        rules[name] = RulesFile(
            security_group=name,
            ingress=tuple(wanted["ingress"]),
            egress=tuple(wanted["egress"]),
            ingress_managed=True,
            egress_managed=True,
        )
    return ImportedState(groups=groups, rules=rules, notes=tuple(notes))
