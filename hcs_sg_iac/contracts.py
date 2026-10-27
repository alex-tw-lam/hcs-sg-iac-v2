# hcs_sg_iac/contracts.py
"""The cloud boundary. `CloudGateway` is a typing.Protocol — an
interface written the Python way: any class with these exact methods
counts as a gateway, no inheritance needed (the `...` bodies are how
Protocol methods are declared; nothing is unfinished). The real
gateway (adapters/huawei_gateway) and the test fake
(tests/fake_gateway) both match it, so tests run through the same
calls production does. CloudError is the one error type that escapes
a gateway: one clean line, never a traceback."""

from typing import Protocol

from hcs_sg_iac.entities import Rule
from hcs_sg_iac.snapshot import CloudRule, CloudSg


class CloudError(Exception):
    """Cloud/API failure after any in-place retries (one clean line, no
    traceback)."""


class CloudGateway(Protocol):
    """Everything the CLI needs from a cloud: one whole-estate read
    (inventory) plus the eight writes apply performs."""

    def inventory(self): ...
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
