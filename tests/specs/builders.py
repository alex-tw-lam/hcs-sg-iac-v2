# tests/specs/builders.py
"""Shared concrete builders interpreting Frame rows (docs/testing-strategy.md):
project files on disk, seeded FakeGateway state, declarative cloud checks.
stdlib + the package's model/pure adapters only — no pytest, no PyYAML,
no SDK (same discipline as frames.py)."""

from pathlib import Path

from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg
from hcs_sg_iac.model.errors import CloudError, CloudThrottled, QuotaExhausted
from hcs_sg_iac.model.remote import RemoteCidr, RemoteGroup

_EXCEPTIONS = {
    "CloudError": CloudError,
    "CloudThrottled": CloudThrottled,
    "QuotaExhausted": QuotaExhausted,
}


def make_project(tmp_path, files: dict) -> Path:
    """Write a frame's `files` mapping under tmp_path (bytes = binary)."""
    root = Path(tmp_path)
    for rel, text in (files or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text, encoding="utf-8")
    return root


def remote_from_tag(tag: tuple):
    """("group", name) / ("cidr", prefix) -> Remote value."""
    return (
        RemoteGroup(name=tag[1])
        if tag[0] == "group"
        else RemoteCidr(cidr=tag[1])
    )


def seed_gateway(spec: dict) -> FakeGateway:
    """Interpret a frame's `cloud` seed spec:
    {"sgs": [{"id","name","description"}],
     "rules": [{"id","sg","direction","protocol","ports","rgid","prefix"}],
     "nics": [{"port_id","ip","vm"}],
     "attached": [[sg_id, port_id]],
     "budget": int|None,
     "raises": [{"method","name"?,"exc","msg"?}]}"""
    spec = spec or {}
    gw = FakeGateway()
    for s in spec.get("sgs", []):
        gw.add_sg(
            CloudSg(
                id=s["id"],
                name=s["name"],
                description=s.get("description", ""),
            )
        )
    for r in spec.get("rules", []):
        gw.add_rule(
            CloudRule(
                id=r["id"],
                sg_id=r["sg"],
                direction=r["direction"],
                protocol=r.get("protocol"),
                ports=r.get("ports"),
                remote_group_id=r.get("rgid"),
                remote_ip_prefix=r.get("prefix"),
            )
        )
    for n in spec.get("nics", []):
        gw.add_nic(
            CloudNic(port_id=n["port_id"], ip=n["ip"], vm_name=n.get("vm"))
        )
    for sg_id, port_id in spec.get("attached", []):
        gw._attached.add((sg_id, port_id))  # seed without spending call_log
    gw.budget = spec.get("budget")
    for r in spec.get("raises", []):
        _inject_raise(gw, r)
    return gw


def _inject_raise(gw: FakeGateway, spec: dict) -> None:
    """Make one gateway method raise a domain exception — optionally only
    for a matching first positional argument (e.g. the SG name)."""
    method, original = spec["method"], getattr(gw, spec["method"])
    exc, name = _EXCEPTIONS[spec["exc"]], spec.get("name")
    msg = spec.get("msg", "boom")

    def wrapped(*args, **kwargs):
        if name is None or name in args:
            raise exc(msg)
        return original(*args, **kwargs)

    setattr(gw, method, wrapped)


def _sg_id(gw: FakeGateway, ref: str) -> str:
    if ref.startswith("sg-of:"):
        matches = [s for s in gw.list_security_groups() if s.name == ref[6:]]
        assert len(matches) == 1, f"sg-of lookup {ref!r}: {matches}"
        return matches[0].id
    return ref


def check_cloud(gw: FakeGateway, checks: tuple) -> None:
    """Evaluate declarative post-run cloud assertions:
    ("sg_exists", name) · ("sg_missing", name) · ("sg_count", n)
    ("sg_desc", name, desc) · ("rule_count", ref, n)
    ("rule_match", ref, {field: value}) · ("attached", ref, port)
    ("detached", ref, port)   — ref is an sg id or "sg-of:<name>"."""
    for check in checks or ():
        op = check[0]
        if op == "sg_exists":
            assert any(
                s.name == check[1] for s in gw.list_security_groups()
            ), check
        elif op == "sg_missing":
            assert not any(
                s.name == check[1] for s in gw.list_security_groups()
            ), check
        elif op == "sg_count":
            assert len(gw.list_security_groups()) == check[1], check
        elif op == "sg_desc":
            sg = next(
                s for s in gw.list_security_groups() if s.name == check[1]
            )
            assert sg.description == check[2], check
        elif op == "rule_count":
            assert len(gw.list_rules(_sg_id(gw, check[1]))) == check[2], check
        elif op == "rule_match":
            fields = check[2]
            rules = gw.list_rules(_sg_id(gw, check[1]))
            assert any(
                all(getattr(r, k) == v for k, v in fields.items())
                for r in rules
            ), (check, rules)
        elif op == "attached":
            ports = [
                n.port_id for n in gw.list_attached_nics(_sg_id(gw, check[1]))
            ]
            assert check[2] in ports, (check, ports)
        elif op == "detached":
            ports = [
                n.port_id for n in gw.list_attached_nics(_sg_id(gw, check[1]))
            ]
            assert check[2] not in ports, (check, ports)
        else:
            raise AssertionError(f"unknown expect_cloud op {op!r}")
