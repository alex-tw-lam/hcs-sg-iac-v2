# hcs_sg_iac/adapters/yaml_config.py
"""The ONLY file importing PyYAML. Files → dicts → model constructors.
YAML syntax problems (indentation etc.) carry the parser's line numbers;
semantic problems are reported by the model."""

from pathlib import Path

import yaml

from hcs_sg_iac.model.common import RemoteGroup, Report
from hcs_sg_iac.model.entities import (
    GROUP_NAME_RE,
    DesiredState,
    Group,
    RulesFile,
    parse_group,
    parse_rule_list,
)
from hcs_sg_iac.model.portset import PortSet

_FAILED = object()  # sentinel: read/parse failed (error already reported)

# SafeDumper represents known builtins only; teach it that a PortSet IS
# its canonical string (the dump helpers may carry one).
yaml.SafeDumper.add_representer(PortSet, lambda d, x: d.represent_str(x + ""))


def _load_yaml(path: Path, where: str, report: Report) -> object:
    """Read and parse one YAML file.

    Returns the parsed document — which may be None for an empty/null
    document, or a non-dict for e.g. a bare scalar; callers hand those to
    the model, which reports them — or the _FAILED sentinel when the file
    could not be read or parsed (error already in the report).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as e:
        report.error(where, f"cannot read file: {e}")
        return _FAILED
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        loc = f"line {mark.line + 1}" if mark else "unknown position"
        report.error(
            where,
            f"YAML syntax error at {loc}: " f"{getattr(e, 'problem', e)}",
        )
        return _FAILED


def _warn_yml_siblings(directory: Path, label: str, report: Report) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.yml")):
        report.warning(
            f"{label}/{path.name}",
            "ignoring .yml file: expected .yaml extension",
        )


def _load_direction_file(
    entry: Path,
    where_dir: str,
    direction: str,
    remote_key: str,
    report: Report,
) -> "tuple[tuple | None, bool]":
    """One optional <direction>.yaml inside an SG directory. Absent file
    -> (None, False) = unmanaged; present -> (rules, True)."""
    path = entry / f"{direction}.yaml"
    if not path.is_file():
        return None, False
    dwhere = f"{where_dir}/{direction}.yaml"
    raw = _load_yaml(path, dwhere, report)
    if raw is _FAILED:
        return (), True
    return (
        parse_rule_list(raw, dwhere, report, direction, remote_key),
        True,
    )


def _load_per_sg_layout(
    root: Path, report: Report
) -> "tuple[dict[str, Group], dict[str, RulesFile]]":
    """security-groups/<name>/: one directory per SG — group.yaml plus
    OPTIONAL ingress.yaml/egress.yaml. An absent direction file means
    that direction is UNMANAGED (same semantics as an absent section in
    the flat layout); a file containing [] manages-and-removes-all."""
    sgs_dir = root / "security-groups"
    _warn_yml_siblings(sgs_dir, "security-groups", report)
    groups: dict[str, Group] = {}
    rules: dict[str, RulesFile] = {}
    for entry in sorted(sgs_dir.iterdir()):
        if entry.name.startswith("."):  # .keep & friends: empty-store
            continue  # markers, not groups
        where_dir = f"security-groups/{entry.name}"
        if not entry.is_dir():
            report.warning(
                where_dir,
                "ignoring stray file: expected a directory "
                "per security group",
            )
            continue
        if not GROUP_NAME_RE.fullmatch(entry.name):
            report.error(
                where_dir,
                f"directory name must match {GROUP_NAME_RE.pattern}",
            )
            continue
        if not (entry / "group.yaml").is_file():
            report.error(where_dir, "missing group.yaml")
            continue
        where = f"{where_dir}/group.yaml"
        d = _load_yaml(entry / "group.yaml", where, report)
        if d is _FAILED or d is None:
            if d is None:
                report.error(where, "file is empty or contains no document")
            continue
        g = parse_group(d, where, report)
        if g is None:
            continue
        if g.name != entry.name:
            report.error(
                where,
                f"directory name must equal group name "
                f"({entry.name!r} != {g.name!r})",
            )
            continue
        for stray in sorted(entry.iterdir()):
            if (
                stray.name not in ("group.yaml", "ingress.yaml", "egress.yaml")
                and stray.is_file()
            ):
                report.warning(
                    f"{where_dir}/{stray.name}", "ignoring unexpected file"
                )
        groups[g.name] = g
        ingress, ing_managed = _load_direction_file(
            entry, where_dir, "ingress", "source", report
        )
        egress, eg_managed = _load_direction_file(
            entry, where_dir, "egress", "destination", report
        )
        if ing_managed or eg_managed:
            rules[g.name] = RulesFile(
                security_group=g.name,
                ingress=ingress or (),
                egress=egress or (),
                ingress_managed=ing_managed,
                egress_managed=eg_managed,
            )
    _check_remote_refs(groups, rules, report)
    return groups, rules


def _check_remote_refs(groups: dict, rules: dict, report) -> None:
    """The one cross-file rule: a RemoteGroup reference must point at a
    group this project declares (checked AFTER the loop — the target may
    live in a directory sorted later)."""
    for gname, rf in rules.items():
        for rule in rf.ingress + rf.egress:
            if (
                isinstance(rule.remote, RemoteGroup)
                and rule.remote.name not in groups
            ):
                report.error(
                    f"security-groups/{gname}/",
                    f"{rule.direction} references unknown group "
                    f"{rule.remote.name!r}",
                )


def load_project(root: Path) -> "tuple[DesiredState | None, Report]":
    """One layout: security-groups/<name>/ per-SG directories."""
    report = Report()
    root = Path(root)
    sgs_dir = root / "security-groups"
    if not sgs_dir.is_dir():
        hint = ""
        if (root / "groups").is_dir():
            hint = (
                " (the legacy groups/+rules/ layout was removed — "
                "delete it and run 'hcs-sg import' to regenerate as "
                "security-groups/)"
            )
        report.error(
            "security-groups/",
            f"no security-groups/ directory — nothing to manage{hint}",
        )
        return None, report
    groups, rules = _load_per_sg_layout(root, report)
    if not report.ok:
        return None, report
    return DesiredState(groups=groups, rules=rules), report


# ---- the other direction: entities -> file text (hcs-sg import) ----


def _rule_to_dict(r) -> dict:
    d: dict = {"protocol": r.protocol}
    if r.ports is not None:
        d["ports"] = r.ports
    d["source" if r.direction == "ingress" else "destination"] = (
        r.remote.name if isinstance(r.remote, RemoteGroup) else r.remote.cidr
    )
    return d


def dump_group(g) -> str:
    """Group entity -> groups/<name>.yaml text (the parse_group inverse).
    An empty members list is omitted — absent and [] parse the same."""
    d: dict = {"name": g.name, "description": g.description}
    if g.members:
        d["members"] = [{"ip": m.ip} for m in g.members]
    return yaml.safe_dump(
        d, sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def dump_security_group_dir(g, rf) -> "dict[str, str]":
    """Group + RulesFile entities -> security-groups/<name>/ files (the
    per-SG directory layout). Import manages everything, so both
    direction files are always written ([] = managed remove-all)."""
    files = {f"security-groups/{g.name}/group.yaml": dump_group(g)}
    rf = rf or RulesFile(
        security_group=g.name,
        ingress=(),
        egress=(),
        ingress_managed=True,
        egress_managed=True,
    )
    for direction, rules in (("ingress", rf.ingress), ("egress", rf.egress)):
        files[f"security-groups/{g.name}/{direction}.yaml"] = yaml.safe_dump(
            [_rule_to_dict(r) for r in (rules or ())],
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
    return files
