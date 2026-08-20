# tests/usecases/test_resolve.py
from hcs_sg_iac.adapters.fake_gateway import FakeGateway
from hcs_sg_iac.model.cloud import CloudNic
from hcs_sg_iac.model.entities import DesiredState, Group, Member
from hcs_sg_iac.usecases.resolve import resolve_memberships


def test_multiple_matches_lists_candidates():
    """RES-03 checks only the generic message and RES-03.a only the
    known-vm side; unique here: the port candidates appear in the error
    and the vm= segment is skipped when unknown."""
    gw = FakeGateway()
    gw.add_nic(CloudNic(port_id="p1", ip="10.0.1.10"))
    gw.add_nic(CloudNic(port_id="p2", ip="10.0.1.10"))
    res = resolve_memberships(gw, DesiredState(
        groups={"web": Group("web", "", (Member("10.0.1.10"),))}, rules={}))
    assert not res.report.ok
    assert "p1" in res.report.errors[0] and "p2" in res.report.errors[0]
    assert "vm=" not in res.report.errors[0]    # skip vm segment when unknown
