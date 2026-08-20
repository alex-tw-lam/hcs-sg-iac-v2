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
    gs = schema_export.group_file_schema()
    assert gs["properties"]["name"]["pattern"] == GROUP_NAME_RE.pattern
    ing = schema_export.direction_file_schema("ingress")
    eg = schema_export.direction_file_schema("egress")
    assert ing["items"]["properties"]["protocol"]["enum"] == list(PROTOCOLS)
    assert ing["items"]["required"] == ["source", "protocol"]
    assert eg["items"]["required"] == ["destination", "protocol"]


def test_direction_files_are_bare_lists():
    for direction in ("ingress", "egress"):
        d = schema_export.direction_file_schema(direction)
        assert d["type"] == "array"
        assert "ABSENT file" in d["$comment"]


def test_icmp_family_forbids_ports_via_if_then():
    rule = schema_export.direction_file_schema("ingress")["items"]
    cond = rule["allOf"][0]
    assert cond["if"]["properties"]["protocol"]["enum"] == [
        "icmp",
        "icmpv6",
        "all",
    ]
    then = cond["then"]["anyOf"]
    assert {"not": {"required": ["ports"]}} in then


def test_ports_accept_string_int_and_list():
    one_of = schema_export.direction_file_schema("ingress")["items"][
        "properties"
    ]["ports"]["oneOf"]
    assert "pattern" in [k for o in one_of for k in o]  # grammar string
    assert any(o.get("type") == "integer" for o in one_of)
    assert any(o.get("type") == "array" for o in one_of)


def test_committed_copies_match_a_fresh_export():
    for name, which in (
        ("group-file.schema.json", "group"),
        ("ingress-file.schema.json", "ingress"),
        ("egress-file.schema.json", "egress"),
    ):
        committed = (REPO / "schemas" / name).read_text(encoding="utf-8")
        assert committed == schema_export.dumps(which) + "\n", name


def test_dumps_all_contains_keyed_schemas():
    data = json.loads(schema_export.dumps("all"))
    assert set(data) == {"group_file", "ingress_file", "egress_file"}
