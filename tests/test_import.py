# tests/test_import.py
"""The adopt-the-estate honesty: convergence property, unrepresentable
remotes become honest deletes, duplicate names, unset remote."""

from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.usecases import importer, pipeline

from tests.conftest import cloud_rule, make_project, seed


def _write_and_plan(tmp_path, gw):
    imp = importer.import_snapshot(gw.inventory().snapshot)
    files = {}
    for n, g in imp.groups.items():
        files.update(yaml_config.dump_security_group_dir(g, imp.rules.get(n)))
    root = make_project(tmp_path, files)
    al, errors = pipeline.plan_project(yaml_config.load_project, gw, root)
    assert al is not None, errors
    return imp, al


def test_import_then_plan_converges(tmp_path):
    gw = seed(
        FakeGateway(),
        sgs=(("sg-web", "web", "web tier"), ("sg-db", "db", "")),
        rules=(
            cloud_rule(
                id="r-self",
                remote_group_id="sg-web",
                remote_ip_prefix=None,
                protocol="icmp",
                ports=None,
            ),
            cloud_rule(id="r-ssh"),
            cloud_rule(
                id="r-db",
                sg_id="sg-db",
                ports="5432",
                remote_group_id="sg-web",
                remote_ip_prefix=None,
            ),
            cloud_rule(
                id="r-any",
                sg_id="sg-db",
                protocol=None,
                ports=None,
                remote_group_id=None,
                remote_ip_prefix=None,
            ),
        ),
        nics=(("10.0.1.10", "p1"),),
        attached=(("sg-web", "p1"),),
    )
    imp, al = _write_and_plan(tmp_path, gw)
    assert sorted(imp.groups) == ["db", "web"]
    assert al.actions == () and al.unmanaged == ()
    assert any("self-referential" in n for n in imp.notes)


def test_unrepresentable_remote_is_delete_planned(tmp_path):
    gw = seed(
        FakeGateway(),
        sgs=(("sg-db", "db", ""),),
        rules=(
            cloud_rule(
                id="r-v6",
                sg_id="sg-db",
                direction="egress",
                protocol=None,
                ports=None,
                remote_ip_prefix="::/0",
            ),
        ),
    )
    imp, al = _write_and_plan(tmp_path, gw)
    assert any("not a v4 CIDR" in n and "delete" in n for n in imp.notes)
    assert any(
        a.sign == "-" and "unrepresentable-remote" in a.detail
        for a in al.actions
    )


def test_duplicate_cloud_names_first_id_wins(tmp_path):
    gw = seed(
        FakeGateway(),
        sgs=(("sg-a", "dup", ""), ("sg-b", "dup", ""), ("sg-c", "app", "")),
    )
    imp = importer.import_snapshot(gw.inventory().snapshot)
    assert sorted(imp.groups) == ["app", "dup"]
    assert any("duplicate cloud name" in n and "sg-b" in n for n in imp.notes)


def test_unset_remote_imports_as_anywhere(tmp_path):
    gw = seed(
        FakeGateway(),
        sgs=(("sg-a", "app", ""),),
        rules=(
            cloud_rule(
                id="r1",
                sg_id="sg-a",
                protocol=None,
                ports=None,
                remote_group_id=None,
                remote_ip_prefix=None,
            ),
        ),
    )
    imp, al = _write_and_plan(tmp_path, gw)
    rf = imp.rules["app"]
    (rule,) = rf.ingress
    assert rule.remote.cidr == "0.0.0.0/0"
    assert al.actions == ()  # converges: no phantom delete
