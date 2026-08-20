# tests/usecases/test_import.py
"""The adopt-the-estate property: import(snapshot) -> files -> load ->
plan must CONVERGE (zero actions, zero unmanaged) for a representable
cloud. Every rule import skips for unrepresentability is an honest
delete in the next plan (identity `unrepresentable-remote(...)`) —
never silent divergence between what import wrote and what apply does."""
from hcs_sg_iac.adapters import yaml_config
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg
from hcs_sg_iac.usecases import importer, pipeline


def _seeded():
    gw = FakeGateway()
    gw.add_sg(CloudSg(id="sg-web", name="web", description="web tier"))
    gw.add_sg(CloudSg(id="sg-db", name="db"))
    gw.add_rule(CloudRule(id="r-self", sg_id="sg-web", direction="ingress",
                          protocol="icmp", ports=None,
                          remote_group_id="sg-web", remote_ip_prefix=None))
    gw.add_rule(CloudRule(id="r-ssh", sg_id="sg-web", direction="ingress",
                          protocol="tcp", ports="22", remote_group_id=None,
                          remote_ip_prefix="203.0.113.0/24"))
    gw.add_rule(CloudRule(id="r-db", sg_id="sg-db", direction="ingress",
                          protocol="tcp", ports="5432",
                          remote_group_id="sg-web", remote_ip_prefix=None))
    gw.add_rule(CloudRule(id="r-any", sg_id="sg-db", direction="ingress",
                          protocol=None, ports=None,          # unset remote
                          remote_group_id=None, remote_ip_prefix=None))
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10", vm_name="vm1"))
    gw._attached.add(("sg-web", "p1"))
    return gw


def _write(root, imp):
    (root / "groups").mkdir(exist_ok=True)
    for name, g in imp.groups.items():
        (root / "groups" / f"{name}.yaml").write_text(
            yaml_config.dump_group(g), encoding="utf-8")
    (root / "rules").mkdir(exist_ok=True)
    for name, rf in imp.rules.items():
        (root / "rules" / f"{name}.yaml").write_text(
            yaml_config.dump_rules_file(rf), encoding="utf-8")


def test_import_then_plan_converges(tmp_path):
    gw = _seeded()
    imp = importer.import_snapshot(gw.inventory().snapshot)
    assert sorted(imp.groups) == ["db", "web"]
    assert any("self-referential" in n for n in imp.notes)
    _write(tmp_path, imp)
    al, errors = pipeline.plan_project(yaml_config.load_project, gw, tmp_path)
    assert al is not None, errors
    assert al.actions == (), [(a.sign, a.type, a.detail) for a in al.actions]
    assert al.unmanaged == ()


def test_unrepresentable_rule_is_delete_planned_not_hidden(tmp_path):
    gw = _seeded()
    gw.add_rule(CloudRule(id="r-v6", sg_id="sg-db", direction="egress",
                          protocol=None, ports=None, remote_group_id=None,
                          remote_ip_prefix="::/0"))
    imp = importer.import_snapshot(gw.inventory().snapshot)
    assert any("not a v4 CIDR" in n and "delete" in n for n in imp.notes)
    _write(tmp_path, imp)
    al, errors = pipeline.plan_project(yaml_config.load_project, gw, tmp_path)
    assert al is not None, errors
    details = " ".join(a.detail for a in al.actions if a.sign == "-")
    assert "unrepresentable-remote" in details
