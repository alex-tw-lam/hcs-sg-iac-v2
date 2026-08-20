# tests/model/test_entities.py
"""Row coverage for parse_group/parse_rules_file lives in
tests/specs/frames.py (NAME/DESC/MEMB/MIP/SGF/SECT/PROTO/PP/DUPRULE
rows, one bad thing per parse). What stays here is error ACCUMULATION
within a single document — no row parses several bad things at once."""
from hcs_sg_iac.model.entities import parse_group, parse_rules_file
from hcs_sg_iac.model.report import Report


def test_parse_group_collects_all_errors():
    r = Report()
    g = parse_group({"name": "Web_Tier", "description": "x",
                     "members": [{"ip": "10.0.1.10"}, {"ip": "10.0.1.10"}, {}]},
                    "groups/web-tier.yaml", r)
    assert g is None
    assert len(r.errors) == 3      # bad name charset, dup ip, member without ip


def test_rule_semantics_validated():
    r = Report()
    rf = parse_rules_file({"security_group": "x", "ingress": [
        {"source": "a", "protocol": "icmp", "ports": "80"},       # icmp with ports
        {"source": "b", "protocol": "sctp"},                       # unknown protocol
        {"source": "c", "protocol": "all", "ports": "80"},         # all with ports
        {"source": "d", "protocol": "tcp", "ports": "70000"},      # bad port
        {"source": "d", "protocol": "tcp", "ports": "80"},         # valid: earlier
                                                                   # same-tuple entry
                                                                   # errored before
                                                                   # being recorded
    ]}, "rules/x.yaml", r)
    assert rf is None or not r.ok
    assert len(r.errors) >= 4
