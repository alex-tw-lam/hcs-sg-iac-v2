# hcs_sg_iac/usecases/validate.py
"""Cross-file semantic validation (pure). Field-level checks already
happened at model construction; this layer sees the whole project."""
from hcs_sg_iac.model.entities import DesiredState
from hcs_sg_iac.model.remote import RemoteGroup
from hcs_sg_iac.model.report import Report


def validate_state(state: DesiredState) -> Report:
    report = Report()
    for gname, rf in state.rules.items():
        where = f"rules/{gname}.yaml"
        if gname not in state.groups:            # loader also catches this;
            report.error(where,                  # belt and braces for direct use
                         f"security_group {gname!r} has no groups/{gname}.yaml")
        for rule in rf.ingress + rf.egress:
            if isinstance(rule.remote, RemoteGroup) and \
                    rule.remote.name not in state.groups:
                report.error(where,
                             f"{rule.direction} references unknown group "
                             f"{rule.remote.name!r}")
    return report
