# tests/test_architecture.py
"""Third-party designation: the leaves (entities/snapshot/contracts/
engine) and cli/ import stdlib + hcs_sg_iac only; adapters/ files
import EXACTLY their designated third-party lib (an unregistered
adapter file FAILS — additions are deliberate). Dependency DIRECTION
is tach's job (tach.toml).
"""

import ast
import pathlib
import sys

import pytest

PKG = pathlib.Path(__file__).resolve().parents[1] / "hcs_sg_iac"
STDLIB = sys.stdlib_module_names

RINGS = ("adapters", "cli")
LEAVES = ("contracts.py", "entities.py", "engine.py", "snapshot.py", "__init__.py")

# the vocabulary leaves carry pydantic deliberately (the validated
# types); everything else in the leaves stays stdlib+internal.
LEAF_THIRD_PARTY = {
    "entities.py": {"pydantic"},
    "snapshot.py": {"pydantic"},
}

ADAPTER_THIRD_PARTY = {
    "yaml_config.py": {"yaml"},
    "huawei_gateway.py": {
        "huaweicloudsdkcore",
        "huaweicloudsdkvpc",
        "tenacity",
    },
    "__init__.py": set(),
}
ALLOWED_INTERNAL = {"hcs_sg_iac"}


# the leaves and the rings import each other by name; the leaves carry
# no third-party imports at all, cli stays stdlib+internal, adapters
# carry their designated libs, and cli, the outermost ring, may import
# anything in the package.
def _package_of(path: pathlib.Path) -> str:
    """Containing package of a module file, as a dotted path
    (…/hcs_sg_iac/adapters/x.py -> hcs_sg_iac.adapters)."""
    parts = path.relative_to(PKG.parent).with_suffix("").parts
    return ".".join(parts[:-1])


def _roots(path: pathlib.Path) -> set:
    """Third-party import roots of one file (the dependency-direction
    half is tach's job now)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    return roots


def _all_files() -> list:
    files = [PKG / name for name in LEAVES]
    assert all(f.is_file() for f in files), "missing a vocabulary leaf"
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
    """Stdlib + hcs_sg_iac everywhere; adapters and the pydantic leaves
    additionally only their registered third-party libs (an
    unregistered file FAILS — additions are deliberate)."""
    roots = _roots(path) - STDLIB - ALLOWED_INTERNAL
    if path.parent.name == "adapters":
        allowed = ADAPTER_THIRD_PARTY.get(path.name)
        unregistered = f"adapters/{path.name}"
    elif path.parent.name == "hcs_sg_iac":
        allowed = LEAF_THIRD_PARTY.get(path.name, set())
        unregistered = f"hcs_sg_iac/{path.name}"
    else:  # cli — the outermost ring, stdlib+internal only
        allowed = set()
        unregistered = f"cli/{path.name}"
    assert allowed is not None, (
        f"{unregistered} is unregistered — add it to the third-party "
        f"registry deliberately"
    )
    assert (
        roots <= allowed
    ), f"{path.parent.name}/{path.name} imports {roots - allowed}"
