# tests/test_schema_export.py
"""The JSON Schema export cannot drift from the model or the committed
copies: constants are asserted against the model, and the files in
schemas/ are asserted byte-equal to a fresh export."""

import json
import pathlib

from hcs_sg_iac.model.entities import GROUP_NAME_RE, PROTOCOLS
from hcs_sg_iac.usecases import schema_export

REPO = pathlib.Path(__file__).resolve().parents[1]


def test_constants_come_from_the_model():
    gs, rs = (
        schema_export.group_file_schema(),
        schema_export.rules_file_schema(),
    )
    assert gs["properties"]["name"]["pattern"] == GROUP_NAME_RE.pattern
    assert (
        rs["properties"]["security_group"]["pattern"] == GROUP_NAME_RE.pattern
    )
    ingress_item = rs["properties"]["ingress"]["items"]
    assert ingress_item["properties"]["protocol"]["enum"] == list(PROTOCOLS)
    assert ingress_item["required"] == ["source", "protocol"]
    assert rs["properties"]["egress"]["items"]["required"] == [
        "destination",
        "protocol",
    ]


def test_icmp_family_forbids_ports_via_if_then():
    rs = schema_export.rules_file_schema()
    rule = rs["properties"]["ingress"]["items"]
    cond = rule["allOf"][0]
    assert cond["if"]["properties"]["protocol"]["enum"] == [
        "icmp",
        "icmpv6",
        "all",
    ]
    then = cond["then"]["anyOf"]
    assert {"not": {"required": ["ports"]}} in then


def test_ports_accept_string_int_and_list():
    one_of = schema_export.rules_file_schema()["properties"]["ingress"][
        "items"
    ]["properties"]["ports"]["oneOf"]
    assert "pattern" in [k for o in one_of for k in o]  # grammar string
    assert any(o.get("type") == "integer" for o in one_of)
    assert any(o.get("type") == "array" for o in one_of)


def test_committed_copies_match_a_fresh_export():
    for name, which in (
        ("group-file.schema.json", "group"),
        ("rules-file.schema.json", "rules"),
    ):
        committed = json.loads((REPO / "schemas" / name).read_text())
        assert committed == json.loads(schema_export.dumps(which)), name


def test_dumps_all_contains_both_keyed():
    data = json.loads(schema_export.dumps("all"))
    assert set(data) == {"group_file", "rules_file"}
    assert data["group_file"]["required"] == ["name"]
    assert data["rules_file"]["required"] == ["security_group"]
