# tests/test_architecture.py
"""Imports point inward; the inner rings never know the outer ones exist.

Third-party designation: model/ and usecases/ import stdlib + hcs_sg_iac
only; cli/ imports stdlib + hcs_sg_iac only; adapters/ files import
exactly their designated third-party lib.

Ring direction: every internal import of a file must stay within its
ring's allowed internal prefixes (an unregistered direction FAILS).
"""

import ast
import pathlib
import sys

import pytest

PKG = pathlib.Path(__file__).resolve().parents[1] / "hcs_sg_iac"
STDLIB = sys.stdlib_module_names

RINGS = ("model", "usecases", "adapters", "cli")

ADAPTER_THIRD_PARTY = {
    "yaml_config.py": {"yaml"},
    "huawei_gateway.py": {"huaweicloudsdkcore", "huaweicloudsdkvpc"},
    "ratelimit.py": set(),
    "fake_gateway.py": set(),
    "audit.py": set(),
    "snapshot_gateway.py": set(),
    "__init__.py": set(),
}
ALLOWED_INTERNAL = {"hcs_sg_iac"}

# Per-ring allowed internal import prefixes (docs/architecture.md):
# model imports itself; usecases add themselves; adapters add themselves
# (huawei_gateway imports ratelimit — same ring, allowed); cli, the
# outermost ring, may import anything in the package.
RING_ALLOWED_INTERNAL = {
    "model": {"hcs_sg_iac.model"},
    "usecases": {"hcs_sg_iac.model", "hcs_sg_iac.usecases"},
    "adapters": {"hcs_sg_iac.model", "hcs_sg_iac.adapters"},
    "cli": {"hcs_sg_iac"},
}


def _package_of(path: pathlib.Path) -> str:
    """Containing package of a module file, as a dotted path
    (…/hcs_sg_iac/usecases/x.py -> hcs_sg_iac.usecases)."""
    parts = path.relative_to(PKG.parent).with_suffix("").parts
    return ".".join(parts[:-1])


def _imports(path: pathlib.Path) -> "tuple[set, set]":
    """(third-party roots, internal module paths) imported by one file.
    Relative imports (level > 0) resolve against the containing package
    so direction checking sees them."""
    package = _package_of(path)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots, internal = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top == "hcs_sg_iac":
                    internal.add(alias.name)
                else:
                    roots.add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                mod = node.module or ""
                if mod.split(".")[0] == "hcs_sg_iac":
                    internal.add(mod)
                    internal.update(f"{mod}.{a.name}" for a in node.names)
                else:
                    roots.add(mod.split(".")[0])
            else:  # from . import x / from .m import y
                base = package.split(".") if package else []
                if node.level > 1:
                    base = base[: len(base) - (node.level - 1)]
                mod = ".".join(
                    base + (node.module.split(".") if node.module else [])
                )
                if mod:
                    internal.add(mod)
                internal.update(
                    f"{mod}.{a.name}" if mod else a.name for a in node.names
                )
    return roots, internal


def _outward(internal: set, allowed: set) -> set:
    return {
        i
        for i in internal
        if not any(i == a or i.startswith(a + ".") for a in allowed)
    }


def _all_files() -> list:
    files = []
    for ring in RINGS:
        d = PKG / ring
        assert d.is_dir(), f"missing package dir: {d}"
        files += sorted(d.glob("*.py"))
    return files


_ALL = _all_files()


def _id(p):
    return f"{p.parent.name}/{p.name}"


@pytest.mark.parametrize("path", _ALL, ids=_id)
def test_third_party_imports_are_designated(path):
    """Stdlib + hcs_sg_iac everywhere; adapters additionally only their
    registered third-party lib (an unregistered adapter file FAILS)."""
    roots = _imports(path)[0] - STDLIB - ALLOWED_INTERNAL
    allowed = (
        ADAPTER_THIRD_PARTY.get(path.name)
        if path.parent.name == "adapters"
        else set()
    )
    assert allowed is not None, (
        f"adapters/{path.name} is unregistered — add it to "
        f"ADAPTER_THIRD_PARTY deliberately"
    )
    assert (
        roots <= allowed
    ), f"{path.parent.name}/{path.name} imports {roots - allowed}"


@pytest.mark.parametrize("path", _ALL, ids=_id)
def test_imports_stay_within_their_ring(path):
    _, internal = _imports(path)
    ring = path.parent.name
    bad = _outward(internal, RING_ALLOWED_INTERNAL[ring])
    assert not bad, f"{ring}/{path.name} imports outward of its ring: {bad}"
