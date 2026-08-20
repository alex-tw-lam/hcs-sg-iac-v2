# hcs_sg_iac/model/gateway.py
"""Ports (interfaces). Small and segregated: plan needs only readers,
apply additionally needs writers. Any gateway (real SDK, in-memory fake)
is substitutable (LSP) — the contract test enforces it."""
from typing import Protocol

from hcs_sg_iac.model.cloud import CloudRule, CloudSg
from hcs_sg_iac.model.entities import Rule


class SgReader(Protocol):
    def list_security_groups(self) -> list: ...
    def list_rules(self, sg_id: str) -> list: ...


class SgWriter(Protocol):
    def create_security_group(self, name: str, description: str) -> CloudSg: ...
    def update_security_group_description(self, sg_id: str, description: str) -> None: ...
    def delete_security_group(self, sg_id: str) -> None: ...


class SgRuleWriter(Protocol):
    def create_rule(self, sg_id: str, rule: Rule) -> CloudRule: ...
    def delete_rule(self, rule_id: str) -> None: ...


class MembershipReader(Protocol):
    def find_nics_by_ip(self, ips: list) -> dict: ...      # ip -> [CloudNic]
    def list_attached_nics(self, sg_id: str) -> list: ...


class NicBinder(Protocol):
    def attach_nic(self, sg_id: str, port_id: str) -> None: ...
    def detach_nic(self, sg_id: str, port_id: str) -> None: ...
