# hcs_sg_iac/usecases/resolve.py
"""Cloud membership validation: every member IP must resolve to exactly
one NIC in the account. Overlaps between groups are allowed → info."""
from dataclasses import dataclass, field

from hcs_sg_iac.model.entities import DesiredState
from hcs_sg_iac.model.report import Report


@dataclass(frozen=True)
class Resolution:
    nics: dict = field(default_factory=dict)     # ip -> CloudNic
    report: Report = field(default_factory=Report)
    overlaps: tuple = ()


def resolve_memberships(reader, state: DesiredState) -> Resolution:
    report = Report()
    all_ips = sorted({m.ip for g in state.groups.values() for m in g.members})
    matches = reader.find_nics_by_ip(all_ips) if all_ips else {}
    nics: dict = {}
    for g in state.groups.values():
        for m in g.members:
            found = matches.get(m.ip, [])
            if not found:
                report.error(f"groups/{g.name}.yaml",
                             f"ip {m.ip}: no NIC found in any VPC of the account")
            elif len(found) > 1:
                cands = ", ".join(f"port={n.port_id}"
                                  + (f" vm={n.vm_name}" if n.vm_name else "")
                                  for n in found)
                report.error(f"groups/{g.name}.yaml",
                             f"ip {m.ip}: matches multiple NICs ({cands}) — "
                             f"use a unique IP or a nic: entry")
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
