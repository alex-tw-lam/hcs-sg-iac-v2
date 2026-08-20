# hcs_sg_iac/adapters/yaml_config.py
"""The ONLY file importing PyYAML. Files → dicts → model constructors.
YAML syntax problems (indentation etc.) carry the parser's line numbers;
semantic problems are reported by the model."""
from pathlib import Path
from typing import Optional

import yaml

from hcs_sg_iac.model.entities import (DesiredState, Group, RulesFile,
                                       parse_group, parse_rules_file)
from hcs_sg_iac.model.remote import RemoteGroup
from hcs_sg_iac.model.report import Report

_FAILED = object()   # sentinel: read/parse failed (error already reported)


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
        report.error(where, f"YAML syntax error at {loc}: "
                            f"{getattr(e, 'problem', e)}")
        return _FAILED


def _warn_yml_siblings(directory: Path, label: str, report: Report) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.yml")):
        report.warning(f"{label}/{path.name}",
                       "ignoring .yml file: expected .yaml extension")


def load_project(root: Path) -> "tuple[Optional[DesiredState], Report]":
    report = Report()
    root = Path(root)
    groups_dir, rules_dir = root / "groups", root / "rules"
    if not groups_dir.is_dir():
        report.error("groups/", "no groups/ directory — nothing to manage")
        return None, report
    _warn_yml_siblings(groups_dir, "groups", report)

    groups: dict[str, Group] = {}                      # name -> Group
    seen: dict[str, str] = {}                          # name -> where first declared
    for path in sorted(groups_dir.glob("*.yaml")):
        where = f"groups/{path.name}"
        d = _load_yaml(path, where, report)
        if d is _FAILED:
            continue
        if d is None:
            report.error(where, "file is empty or contains no document")
            continue
        g = parse_group(d, where, report)
        if g is None:
            continue
        if g.name in seen:
            report.error(where, f"duplicate group name {g.name!r} "
                                f"(already defined in {seen[g.name]})")
            continue
        seen[g.name] = where
        if path.stem != g.name:
            report.error(where, f"filename must equal group name "
                                f"({path.stem!r} != {g.name!r})")
            continue
        groups[g.name] = g

    _warn_yml_siblings(rules_dir, "rules", report)
    rules: dict[str, RulesFile] = {}                   # name -> RulesFile
    seen_sg: dict[str, str] = {}                       # sg -> where first declared
    for path in sorted(rules_dir.glob("*.yaml")) if rules_dir.is_dir() else []:
        where = f"rules/{path.name}"
        d = _load_yaml(path, where, report)
        if d is _FAILED:
            continue
        if d is None:
            report.error(where, "file is empty or contains no document")
            continue
        rf = parse_rules_file(d, where, report)
        if rf is None:
            continue
        if rf.security_group in seen_sg:
            report.error(where, f"duplicate rules file for "
                                f"{rf.security_group!r} "
                                f"(already defined in {seen_sg[rf.security_group]})")
            continue
        seen_sg[rf.security_group] = where
        if path.stem != rf.security_group:
            report.error(where, f"filename must equal security_group "
                                f"({path.stem!r} != {rf.security_group!r})")
            continue
        if rf.security_group not in groups:
            report.error(where, f"security_group {rf.security_group!r} has "
                                f"no groups/{rf.security_group}.yaml")
            continue
        rules[rf.security_group] = rf

    if not report.ok:
        return None, report
    return DesiredState(groups=groups, rules=rules), report


# ---- the other direction: entities -> file text (hcs-sg import) ----

def _rule_to_dict(r) -> dict:
    d: dict = {"protocol": r.protocol}
    if r.ports is not None:
        d["ports"] = r.ports
    d["source" if r.direction == "ingress" else "destination"] = (
        r.remote.name if isinstance(r.remote, RemoteGroup)
        else r.remote.cidr)
    return d


def dump_group(g) -> str:
    """Group entity -> groups/<name>.yaml text (the parse_group inverse).
    An empty members list is omitted — absent and [] parse the same."""
    d: dict = {"name": g.name, "description": g.description}
    if g.members:
        d["members"] = [{"ip": m.ip} for m in g.members]
    return yaml.safe_dump(d, sort_keys=False, allow_unicode=True,
                          default_flow_style=False)


def dump_rules_file(rf) -> str:
    """RulesFile entity -> rules/<name>.yaml text (the parse_rules_file
    inverse). A None (unmanaged) direction stays absent; [] stays []."""
    d: dict = {"security_group": rf.security_group}
    for key, rules in (("ingress", rf.ingress), ("egress", rf.egress)):
        if rules is not None:
            d[key] = [_rule_to_dict(r) for r in rules]
    return yaml.safe_dump(d, sort_keys=False, allow_unicode=True,
                          default_flow_style=False)
