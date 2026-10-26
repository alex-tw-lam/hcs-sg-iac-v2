# tests/test_plan.py
"""The diff engine's semantics: loader errors, resolution, identity
joins, self-rule preservation, duplicate names, clears, drift cases."""

from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.engine import resolve_memberships
from hcs_sg_iac.entities import Group

from tests.conftest import (
    GROUP_YAML,
    cloud_rule,
    make_project,
    plan_state,
    seed,
)
from tests.fake_gateway import FakeGateway


def _state(root):
    state, report = yaml_config.load_project(root)
    assert state is not None, report.errors
    return state


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
    from hcs_sg_iac.cli.main import _Ctx, _plan_project

    make_project(
        tmp_path,
        {
            "security-groups/web/group.yaml": GROUP_YAML,
            "security-groups/web/ingress.yaml": "- {source: ghost, protocol: tcp, ports: '22'}\n",
        },
    )
    al, errors = _plan_project(
        _Ctx(project=tmp_path, gateway=FakeGateway())
    )
    assert al is None
    assert any("ghost" in e for e in errors)


# ---- resolution ----


def test_resolve_zero_and_multi_match(tmp_path):
    from hcs_sg_iac.entities import DesiredState, Member

    state = DesiredState(
        groups={
            "web": Group("web", "", (Member(ip="10.9.9.9"),)),
            "db": Group("db", "", (Member(ip="10.0.2.20"),)),
        },
        rules={},
    )
    gw = seed(FakeGateway(), nics=(("10.0.2.20", "pa"), ("10.0.2.20", "pb")))
    res = resolve_memberships(gw.inventory().nics_by_ip, state)
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
        rules=(cloud_rule(remote_ip_prefix="203.0.113.0/24"),),
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
        rules=(cloud_rule(protocol=None, ports=None, remote_ip_prefix=None),),
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
            cloud_rule(id="a", ports="22"),
            cloud_rule(id="b", ports="443"),
        ),
    )
    assert plan_state(gw, _state(tmp_path)).actions == ()
    # partial: 443 missing in cloud -> one create
    gw2 = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        rules=(cloud_rule(id="a", ports="22"),),
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
            cloud_rule(
                id="self1",
                direction="ingress",
                protocol="icmp",
                ports=None,
                remote_group_id="sg-web",
                remote_ip_prefix=None,
            ),
            cloud_rule(
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
        FakeGateway(), sgs=(("sg-web", "web", ""),), rules=(cloud_rule(),)
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
        FakeGateway(), sgs=(("sg-web", "web", ""),), rules=(cloud_rule(),)
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


def test_cloud_only_group_is_planned_for_deletion(tmp_path):
    """A cloud SG with no directory is no longer 'inventoried' — the
    directory's absence IS the delete instruction."""
    make_project(
        tmp_path,
        {"security-groups/web/group.yaml": "name: web\nmembers: []\n"},
    )
    gw = seed(
        FakeGateway(), sgs=(("sg-web", "web", ""), ("sg-x", "extra", ""))
    )
    al = plan_state(gw, _state(tmp_path))
    assert [(a.sign, a.type, a.group) for a in al.actions] == [
        ("-", "group", "extra")
    ]
    assert al.actions[0].op.sg_id == "sg-x"
    assert not any("extra" in u for u in al.unmanaged)


def test_extra_cloud_member_is_detached(tmp_path):
    """Membership truth is the IP list: a cloud-attached NIC the code
    does not list gets a detach action."""
    make_project(
        tmp_path,
        {"security-groups/web/group.yaml": "name: web\nmembers: []\n"},
    )
    gw = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", ""),),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-web", "p1"),),
    )
    al = plan_state(gw, _state(tmp_path))
    assert [(a.sign, a.type, a.cloud_id) for a in al.actions] == [
        ("-", "member", "p1")
    ]


# ---- deleting a group = removing its directory ----


def test_absent_directory_plans_group_deletion(tmp_path):
    """web is in the cloud but its directory is gone: one delete action
    (db's create is its own row), no unmanaged note for web anymore."""
    make_project(
        tmp_path, {"security-groups/db/group.yaml": "name: db\nmembers: []\n"}
    )
    gw = seed(FakeGateway(), sgs=(("sg-1", "web", "web"),))
    al = plan_state(gw, _state(tmp_path))
    web = [a for a in al.actions if a.group == "web"]
    assert [(a.sign, a.type) for a in web] == [("-", "group")]
    assert web[0].op.sg_id == "sg-1"
    assert not any("web" in u for u in al.unmanaged)


def test_absent_directory_detaches_members_before_delete(tmp_path):
    make_project(
        tmp_path, {"security-groups/db/group.yaml": "name: db\nmembers: []\n"}
    )
    gw = seed(
        FakeGateway(),
        sgs=(("sg-1", "web", "web"),),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-1", "p1"),),
    )
    al = plan_state(gw, _state(tmp_path))
    web = [a for a in al.actions if a.group == "web"]
    assert [(a.sign, a.type) for a in web] == [
        ("-", "member"),
        ("-", "group"),
    ]


def test_empty_groups_refuses_whole_estate_deletion(tmp_path):
    """security-groups/ present but empty, cloud non-empty: refuse."""
    (tmp_path / "security-groups").mkdir()
    gw = seed(FakeGateway(), sgs=(("sg-1", "web", "web"),))
    from hcs_sg_iac.cli.main import _Ctx, _plan_project

    al, errors = _plan_project(_Ctx(project=tmp_path, gateway=gw))
    assert al is None and any("refusing" in e for e in errors)
