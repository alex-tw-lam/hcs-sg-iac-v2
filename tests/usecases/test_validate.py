# tests/usecases/test_validate.py
from hcs_sg_iac.model.entities import DesiredState, Group, Rule, RulesFile
from hcs_sg_iac.model.remote import RemoteGroup
from hcs_sg_iac.usecases.validate import validate_state


def _state(rules=None):
    groups = {"web": Group("web", "", ()), "db": Group("db", "", ())}
    return DesiredState(groups=groups, rules=rules or {})


def test_multiple_bad_refs_all_reported():
    """XVAL-01/02/03 pin the single-error frames; unique here: one pass
    reports EVERY bad reference (exactly two errors, no dedup)."""
    rf = RulesFile("db", (Rule("ingress", "tcp", "5432", RemoteGroup("ghost1")),
                          Rule("egress", "tcp", "80", RemoteGroup("ghost2"))),
                   (), True, False)
    r = validate_state(_state({"db": rf}))
    assert len(r.errors) == 2
