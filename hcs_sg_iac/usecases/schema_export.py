# hcs_sg_iac/usecases/schema_export.py
"""JSON Schema (draft 2020-12) export of the config-file models.

Single source of truth: the pattern and enum below come from the model
constants (GROUP_NAME_RE, PROTOCOLS), so this export cannot drift from
the parsers. Constraints that live OUTSIDE a single document — filename
stem must equal the group name, source/destination group refs must exist,
member IPs must resolve to exactly one NIC at plan time, the 20-entry
merged-port cap — are noted in $comment; a schema validates one file,
not the project or the cloud.
"""

import json

from hcs_sg_iac.model.entities import GROUP_NAME_RE, PROTOCOLS

_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_NO_PORTS = ["icmp", "icmpv6", "all"]
_PORTS_PATTERN = r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$"
_PORTS_VALUE = {
    "description": 'port spec: "80", "22,443", "8000-9000" (mixed ok, '
    "max 20 entries after merge); bare integer or list of "
    "integers accepted; absent/empty = all ports",
    "oneOf": [
        {"type": "string", "pattern": _PORTS_PATTERN},
        {"type": "string", "enum": [""]},
        {"type": "integer", "minimum": 1, "maximum": 65535},
        {
            "type": "array",
            "items": {"type": "integer", "minimum": 1, "maximum": 65535},
        },
    ],
}


def _rule(remote_key: str) -> dict:
    return {
        "type": "object",
        "required": [remote_key, "protocol"],
        "properties": {
            remote_key: {
                "type": "string",
                "description": "group name, or IPv4 CIDR (bare IP auto-/32); "
                "IPv6 is not supported",
            },
            "protocol": {"enum": list(PROTOCOLS)},
            "ports": _PORTS_VALUE,
        },
        "allOf": [
            {  # icmp/icmpv6/all rules carry no ports ("" or [] tolerated)
                "if": {"properties": {"protocol": {"enum": _NO_PORTS}}},
                "then": {
                    "anyOf": [
                        {"not": {"required": ["ports"]}},
                        {"properties": {"ports": {"enum": ["", []]}}},
                    ]
                },
            },
        ],
    }


def _direction(remote_key: str) -> dict:
    return {
        "type": "array",
        "description": "absent key = direction unmanaged (never touched); "
        "[] = remove all rules in this direction",
        "items": _rule(remote_key),
    }


def group_file_schema() -> dict:
    """Schema of one security-groups/<name>/group.yaml document."""
    return {
        "$schema": _DRAFT,
        "$id": "https://hcs-sg.local/schemas/group-file.schema.json",
        "title": "hcs-sg group file",
        "$comment": "security-groups/<name>/group.yaml — the directory "
        "name must equal `name`; duplicate member IPs within "
        "a group are rejected at load time; extra keys in "
        "member entries are tolerated (reserved for future "
        "nic:/vm: types).",
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {
                "type": "string",
                "pattern": GROUP_NAME_RE.pattern,
                "description": "must not parse as an IP/CIDR (enforced "
                "beyond the pattern at load time)",
            },
            "description": {"type": "string"},
            "members": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["ip"],
                    "properties": {
                        "ip": {"type": "string", "format": "ipv4"},
                    },
                },
            },
        },
    }


def direction_file_schema(direction: str) -> dict:
    """Schema of one security-groups/<name>/<direction>.yaml document
    (a bare list of rules)."""
    remote_key = "source" if direction == "ingress" else "destination"
    return {
        "$schema": _DRAFT,
        "$id": f"https://hcs-sg.local/schemas/{direction}-file.schema.json",
        "title": f"hcs-sg {direction} rules file",
        "$comment": f"security-groups/<name>/{direction}.yaml — a bare "
        "list; an ABSENT file = the direction is unmanaged, "
        "[] = remove all rules in it; the sibling group.yaml "
        "must exist with the same directory name; remote "
        "group references must point at existing groups "
        "(cross-file, validated at load/plan time).",
        **_direction(remote_key),
    }


def dumps(which: str = "all") -> str:
    """Render one schema (group|ingress|egress) or all as JSON text."""
    one = {
        "group": group_file_schema(),
        "ingress": direction_file_schema("ingress"),
        "egress": direction_file_schema("egress"),
    }
    schema = one.get(which) or {
        "group_file": one["group"],
        "ingress_file": one["ingress"],
        "egress_file": one["egress"],
    }
    return json.dumps(schema, indent=2)
