# tests/test_plan.py
"""The diff engine's semantics: loader errors, resolution, identity
joins, self-rule preservation, duplicate names, clears, drift cases."""

import pytest
from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.entities import Group
from hcs_sg_iac.usecases.resolve import resolve_memberships

from tests.conftest import GROUP_YAML, make_project, plan_state, seed


def _state(root):
    state, report = yaml_config.load_project(root)
    assert state is not None, report.errors
    return state


def _cloud_rule(**kw):
    base = {
        "id": "r1",
        "sg_id": "sg-web",
        "direction": "ingress",
        "protocol": "tcp",
        "ports": "22",
        "remote_group_id": None,
        "remote_ip_prefix": "203.0.113.0/24",
    }
    base.update(kw)
    return base


# ---- loader ----


def test_loader_absent_direction_is_unmanaged(tmp_path):
    make_project(tmp_path, {"security-groups/web/group.yaml": GROUP_YAML})
    state = _state(tmp_path)
    assert "web" not in state.rules  # both directions unmanaged


def test_loader_legacy_layout_hint(tmp_path):
    make_project(tmp_path, {"groups/web.yaml": GROUP_YAML})
    state, report = yaml_config.load_project(tmp_path)
    assert state is None
    assert any("legacy" in e and "hcs-sg import" in e for e in report.errors)


def test_loader_dirname_must_equal_name(tmp_path):
    make_project(
        tmp_path, {"security-groups/web/group.yaml": "name: db\nmembers: []\n"}
    )
    state, report = yaml_config.load_project(tmp_path)
    assert state is None
    assert any(
        "directory name must equal group name" in e for e in report.errors
    )


def test_loader_yaml_syntax_error(tmp_path):
    make_project(
        tmp_path,
        {"security-groups/web/group.yaml": "name: web\n  members: [\n"},
    )
    state, report = yaml_config.load_project(tmp_path)
    assert state is None and any(
        "YAML syntax error" in e for e in report.errors
    )


def test_dangling_remote_group_ref_rejected(tmp_path):
    from hcs_sg_iac.usecases import pipeline

    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": GROUP_YAML,
            "security-groups/web/ingress.yaml": "- {source: ghost, protocol: tcp, ports: '22'}\n",
        },
    )
    al, errors = pipeline.plan_project(
        yaml_config.load_project, FakeGateway(), tmp_path
    )
    assert al is None
    assert any("ghost" in e for e in errors)


# ---- resolution ----


def test_resolve_zero_and_multi_match(tmp_path):
    from hcs_sg_iac.model.entities import DesiredState, Member

    state = DesiredState(
        groups={
            "web": Group("web", "", (Member(ip="10.9.9.9"),)),
            "db": Group("db", "", (Member(ip="10.0.2.20"),)),
        },
        rules={},
    )
    gw = seed(FakeGateway(), nics=(("10.0.2.20", "pa"), ("10.0.2.20", "pb")))
    res = resolve_memberships(gw, state)
    assert not res.report.ok
    errs = " ".join(res.report.errors)
    assert "no NIC found" in errs and "matches multiple NICs" in errs


# ---- identity joins ----


def test_noncanonical_cidr_converges(tmp_path):
    """10.0.0.1/24 (non-canonical) joins a cloud rule stored as
    10.0.0.0/24 — identity is canonical on BOTH sides."""
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
            "security-groups/web/ingress.yaml": "- {source: 203.0.113.1/24, protocol: tcp, ports: '22'}\n",
        },
    )
    gw = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        rules=(_cloud_rule(remote_ip_prefix="203.0.113.0/24"),),
    )
    assert plan_state(gw, _state(tmp_path)).actions == ()


def test_unset_remote_joins_code_anywhere(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
            "security-groups/web/ingress.yaml": "- {source: 0.0.0.0/0, protocol: all}\n",
        },
    )
    gw = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        rules=(_cloud_rule(protocol=None, ports=None, remote_ip_prefix=None),),
    )
    assert plan_state(gw, _state(tmp_path)).actions == ()


def test_multiport_expands_to_single_range_rules(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
            "security-groups/web/ingress.yaml": "- {source: 203.0.113.0/24, protocol: tcp,"
            " ports: '22,443'}\n",
        },
    )
    gw = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        rules=(
            _cloud_rule(id="a", ports="22"),
            _cloud_rule(id="b", ports="443"),
        ),
    )
    assert plan_state(gw, _state(tmp_path)).actions == ()
    # partial: 443 missing in cloud -> one create
    gw2 = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        rules=(_cloud_rule(id="a", ports="22"),),
    )
    al = plan_state(gw2, _state(tmp_path))
    assert [(a.sign, a.type) for a in al.actions] == [("+", "rule")]


def test_duplicate_code_rules_rejected_at_load(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
            "security-groups/web/ingress.yaml": "- {source: 0.0.0.0/0, protocol: tcp, ports: '22'}\n"
            "- {source: 0.0.0.0/0, protocol: tcp, ports: '22'}\n",
        },
    )
    state, report = yaml_config.load_project(tmp_path)
    assert state is None and any("duplicate" in e for e in report.errors)


def test_duplicate_cloud_names_abort_with_every_id(tmp_path):
    from hcs_sg_iac.model.entities import DesiredState

    gw = seed(FakeGateway(), sgs=(("sg-a", "web", ""), ("sg-b", "web", "")))
    with pytest.raises(ValueError) as ei:
        plan_state(gw, DesiredState(groups={}, rules={}))
    assert "sg-a" in str(ei.value) and "sg-b" in str(ei.value)


# ---- self rules & clears ----


def test_self_rules_preserved_both_directions(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
            "security-groups/web/ingress.yaml": "[]\n",
            "security-groups/web/egress.yaml": "[]\n",
        },
    )
    gw = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        rules=(
            _cloud_rule(
                id="self1",
                direction="ingress",
                protocol="icmp",
                ports=None,
                remote_group_id="sg-web",
                remote_ip_prefix=None,
            ),
            _cloud_rule(
                id="self2",
                direction="egress",
                protocol=None,
                ports=None,
                remote_group_id="sg-web",
                remote_ip_prefix=None,
            ),
        ),
    )
    al = plan_state(gw, _state(tmp_path))
    assert al.actions == ()  # never stale, even for managed [] directions
    assert al.clears == ()  # and no false clear-all alarm


def test_managed_empty_clears_name_the_direction(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
            "security-groups/web/ingress.yaml": "[]\n",
        },
    )
    gw = seed(
        FakeGateway(), sgs=(("sg-web", "web", ""),), rules=(_cloud_rule(),)
    )
    al = plan_state(gw, _state(tmp_path))
    assert [(a.sign, a.type) for a in al.actions] == [("-", "rule")]
    assert al.clears == ("ingress rules of web",)


def test_unmanaged_direction_inventoried_not_touched(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\nmembers: []\n",
        },
    )
    gw = seed(
        FakeGateway(), sgs=(("sg-web", "web", ""),), rules=(_cloud_rule(),)
    )
    al = plan_state(gw, _state(tmp_path))
    assert al.actions == ()
    assert any(
        "ingress rules of web" in u and "untouched" in u for u in al.unmanaged
    )


def test_description_drift_plans_update(tmp_path):
    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": "name: web\ndescription: new\nmembers: []\n"
        },
    )
    gw = seed(FakeGateway(), sgs=(("sg-web", "web", "old"),))
    al = plan_state(gw, _state(tmp_path))
    assert [(a.sign, a.type) for a in al.actions] == [("~", "group")]


def test_cloud_only_group_is_inventoried(tmp_path):
    make_project(
        tmp_path,
        {"security-groups/web/group.yaml": "name: web\nmembers: []\n"},
    )
    gw = seed(
        FakeGateway(), sgs=(("sg-web", "web", ""), ("sg-x", "extra", ""))
    )
    al = plan_state(gw, _state(tmp_path))
    assert al.actions == ()
    assert any(
        "'extra'" in u and "no security-groups/extra/" in u
        for u in al.unmanaged
    )
