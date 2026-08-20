# hcs_sg_iac/adapters/fake_gateway.py
"""In-memory gateway. Implements every protocol; powers fast tests,
CLI e2e and the contract suite. call_log records every write."""
from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg
from hcs_sg_iac.model.errors import CloudError, QuotaExhausted


class FakeGateway:
    def __init__(self):
        self._sgs: dict = {}            # sg_id -> CloudSg
        self._rules: dict = {}          # rule_id -> CloudRule
        self._nics: list = []
        self._attached: set = set()     # (sg_id, port_id)
        self.call_log: list = []
        self._next = 0
        self.budget: "int | None" = None    # None = unlimited

    # -- seeding (test/contract scaffolding, not part of protocols) --
    def add_sg(self, sg: CloudSg) -> CloudSg:
        self._sgs[sg.id] = sg
        return sg

    def add_rule(self, rule: CloudRule) -> CloudRule:
        self._rules[rule.id] = rule
        return rule

    def add_nic(self, nic: CloudNic) -> CloudNic:
        self._nics.append(nic)
        return nic

    def _id(self) -> str:
        self._next += 1
        return f"id-{self._next:04d}"

    def _spend(self, what: str):
        self.call_log.append(what)
        if self.budget is not None and len(self.call_log) > self.budget:
            raise QuotaExhausted(f"fake budget exhausted ({self.budget} calls)")

    # -- SgReader --
    def list_security_groups(self) -> list:
        return list(self._sgs.values())

    def list_rules(self, sg_id: str) -> list:
        return [r for r in self._rules.values() if r.sg_id == sg_id]

    # -- MembershipReader --
    def find_nics_by_ip(self, ips: list) -> dict:
        return {ip: [n for n in self._nics if n.ip == ip] for ip in ips}

    def list_attached_nics(self, sg_id: str) -> list:
        return [n for n in self._nics if (sg_id, n.port_id) in self._attached]

    # -- SgWriter --
    def create_security_group(self, name: str, description: str) -> CloudSg:
        self._spend(f"create_sg:{name}")
        sg = CloudSg(id=self._id(), name=name, description=description)
        self._sgs[sg.id] = sg
        return sg

    def update_security_group_description(self, sg_id: str,
                                          description: str) -> None:
        self._spend(f"update_sg:{sg_id}")
        old = self._sgs[sg_id]
        self._sgs[sg_id] = CloudSg(id=old.id, name=old.name,
                                   description=description)

    def delete_security_group(self, sg_id: str) -> None:
        self._spend(f"delete_sg:{sg_id}")
        self._sgs.pop(sg_id)
        self._rules = {rid: r for rid, r in self._rules.items()
                       if r.sg_id != sg_id}
        self._attached = {(s, p) for s, p in self._attached if s != sg_id}

    # -- SgRuleWriter --
    def create_rule(self, sg_id: str, rule) -> CloudRule:
        self._spend(f"create_rule:{sg_id}")
        remote_group_id = None
        remote_ip_prefix = None
        if hasattr(rule.remote, "name"):
            match = [s for s in self._sgs.values() if s.name == rule.remote.name]
            if not match:
                raise CloudError(f"unknown remote group {rule.remote.name!r}")
            remote_group_id = match[0].id
        elif hasattr(rule.remote, "cidr"):
            remote_ip_prefix = rule.remote.cidr
        cr = CloudRule(id=self._id(), sg_id=sg_id, direction=rule.direction,
                       protocol=None if rule.protocol == "all" else rule.protocol,
                       ports=rule.ports,
                       remote_group_id=remote_group_id,
                       remote_ip_prefix=remote_ip_prefix)
        self._rules[cr.id] = cr
        return cr

    def delete_rule(self, rule_id: str) -> None:
        self._spend(f"delete_rule:{rule_id}")
        self._rules.pop(rule_id)

    # -- NicBinder --
    def attach_nic(self, sg_id: str, port_id: str) -> None:
        self._spend(f"attach:{port_id}->{sg_id}")
        if port_id not in {n.port_id for n in self._nics}:
            self._nics.append(CloudNic(port_id=port_id, ip=""))
        self._attached.add((sg_id, port_id))

    def detach_nic(self, sg_id: str, port_id: str) -> None:
        self._spend(f"detach:{port_id}->{sg_id}")
        self._attached.discard((sg_id, port_id))

    # quota display helper used by the CLI (duck-typed, not a protocol)
    def quota_snapshot(self) -> dict:
        used = len(self.call_log)
        limit = 25 if self.budget is None else self.budget
        return {"service_budget_calls": limit,
                "used_calls": used,
                "effective_limit": limit,
                "window_resets_at": None}
