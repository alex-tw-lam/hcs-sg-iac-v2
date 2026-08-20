# hcs_sg_iac/model/gateway.py
"""Ports (interfaces). The read side is ONE seam — inventory() gives the
whole observed cloud in a single pass (every gateway implements it; it
replaced the per-SG read loop and the five-protocol sprawl) plus the
member-IP lookup resolution needs. The write side stays segregated:
apply additionally needs the writers. Any gateway (real SDK, in-memory
fake, snapshot replay) is substitutable (LSP) — the contract suite
enforces it."""

from typing import Protocol

from hcs_sg_iac.model.cloud import CloudNic, CloudRule, CloudSg
from hcs_sg_iac.model.entities import Rule


class CloudReader(Protocol):
    def inventory(self): ...
    def find_nics_by_ip(self, ips: list) -> "dict[str, list[CloudNic]]": ...


class CloudWriter(Protocol):
    def create_security_group(
        self, name: str, description: str
    ) -> CloudSg: ...
    def update_security_group_description(
        self, sg_id: str, description: str
    ) -> None: ...
    def delete_security_group(self, sg_id: str) -> None: ...
    def create_rule(self, sg_id: str, rule: Rule) -> CloudRule: ...
    def delete_rule(self, rule_id: str) -> None: ...
    def attach_nic(self, sg_id: str, port_id: str) -> None: ...
    def detach_nic(self, sg_id: str, port_id: str) -> None: ...
