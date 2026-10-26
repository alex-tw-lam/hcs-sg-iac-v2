# hcs_sg_iac/contracts.py
"""The cloud boundary: two Protocols + the domain error. The read side
is one call — inventory() returns the whole observed cloud in a single
pass, plus a member-IP lookup. The write side is separate: apply
additionally needs the writers. Any object implementing these (the
real SDK gateway, the in-memory test fake) can stand in for any
other."""

from typing import Protocol

from hcs_sg_iac.entities import Rule
from hcs_sg_iac.snapshot import CloudNic, CloudRule, CloudSg


class CloudError(Exception):
    """Cloud/API failure after any in-place retries (one clean line, no
    traceback)."""


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


class CloudGateway(CloudReader, CloudWriter, Protocol):
    """What the CLI hands its handlers: one object filling both seams
    (the real SDK gateway, the in-memory fake)."""
