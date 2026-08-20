# hcs_sg_iac/model/actions.py
"""Plan output + executable payloads. One ActionList feeds the renderer
(dry-run display) and apply (execution) — a single source of truth."""
from dataclasses import dataclass
from typing import Literal, Optional

from hcs_sg_iac.model.entities import Rule


# ---- executable payloads (discriminated by type) ----
@dataclass(frozen=True)
class CreateSg:
    description: str


@dataclass(frozen=True)
class UpdateSg:
    sg_id: str
    description: str


@dataclass(frozen=True)
class DeleteSg:
    sg_id: str


@dataclass(frozen=True)
class AttachNic:
    sg_id: str
    port_id: str


@dataclass(frozen=True)
class DetachNic:
    sg_id: str
    port_id: str


@dataclass(frozen=True)
class CreateRule:
    sg_id: str
    rule: Rule


@dataclass(frozen=True)
class DeleteRule:
    rule_id: str


Payload = CreateSg | UpdateSg | DeleteSg | AttachNic | DetachNic | CreateRule | DeleteRule


# ---- display + dispatch ----
@dataclass(frozen=True)
class Action:
    sign: 'Literal["+", "-", "~"]'
    type: 'Literal["member", "rule", "group"]' 
    group: str
    detail: str
    cloud_id: Optional[str] = None
    op: "Payload | None" = None  # payload above; None for display-only rows


@dataclass(frozen=True)
class ActionList:
    actions: tuple
    unmanaged: tuple             # NOT MANAGED lines
    overlap: tuple               # INFO lines
    clears: tuple = ()           # "egress rules of web" per managed+code-empty
                                # direction the plan actually strips

    def summary(self) -> dict:
        counts = {"add": 0, "change": 0, "destroy": 0}
        for a in self.actions:
            counts[{"+": "add", "-": "destroy", "~": "change"}[a.sign]] += 1
        return counts


@dataclass(frozen=True)
class ActionResult:
    action: Action
    status: 'Literal["ok", "failed", "throttled"]'
    error: Optional[str] = None
