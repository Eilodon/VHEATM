from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

DeclarationState = Literal["yes", "no", "unknown"]
GateState = Literal["pass", "fail", "unknown", "not_applicable"]
GateLayer = Literal["core", "triggered", "meta"]
PhaseId = Literal["P", "V", "G", "E", "A", "T", "M", "KB"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Framework(StrictModel):
    id: Literal["vheatm"]
    name: Literal["VHEATM"]
    version: str
    status: Literal["alpha", "beta", "stable"]
    legacy_source_version: str
    architecture: tuple[Literal["core_loop"], Literal["specialist_lenses"], Literal["meta_defense"]]


class DecisionSemantics(StrictModel):
    declaration_state: tuple[Literal["yes"], Literal["no"], Literal["unknown"]]
    gate_state: tuple[Literal["pass"], Literal["fail"], Literal["unknown"], Literal["not_applicable"]]
    missing_declaration: Literal["unknown"]
    unknown_gate_effect: Literal["block"]


class Phase(StrictModel):
    id: PhaseId
    name: str = Field(min_length=1)
    order: int = Field(ge=1, le=8)


class Phases(StrictModel):
    total: Literal[8]
    items: list[Phase] = Field(min_length=8, max_length=8)

    @model_validator(mode="after")
    def validate_inventory(self) -> "Phases":
        ids = [item.id for item in self.items]
        orders = [item.order for item in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("phase ids must be unique")
        if sorted(orders) != list(range(1, 9)):
            raise ValueError("phase order must be exactly 1..8")
        if self.total != len(self.items):
            raise ValueError("phase total must equal derived item count")
        return self


class Gate(StrictModel):
    id: str = Field(pattern=r"^HG-[A-Z]+$")
    layer: GateLayer
    activation: str = Field(min_length=1)
    phase: PhaseId
    description: str = Field(min_length=20)


class GateDistribution(StrictModel):
    core: Literal[9]
    triggered: Literal[8]
    meta: Literal[5]


class Gates(StrictModel):
    total: Literal[22]
    distribution: GateDistribution
    items: list[Gate] = Field(min_length=22, max_length=22)

    @model_validator(mode="after")
    def validate_inventory(self) -> "Gates":
        ids = [item.id for item in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("gate ids must be unique")
        derived = Counter(item.layer for item in self.items)
        expected = self.distribution.model_dump()
        if dict(derived) != expected:
            raise ValueError(f"gate distribution mismatch: derived={dict(derived)} expected={expected}")
        if self.total != len(self.items):
            raise ValueError("gate total must equal derived item count")
        return self


class Enforcement(StrictModel):
    on_unknown_security_relevant_declaration: Literal["escalate"]
    on_unknown_required_gate: Literal["block"]
    on_validator_error: Literal["block"]


class Defaults(StrictModel):
    mode: Literal["fast", "standard", "full"]
    target_tier: Literal[1, 2, 3]
    declarations: dict[str, DeclarationState]
    enforcement: Enforcement

    @model_validator(mode="after")
    def reject_fail_open_defaults(self) -> "Defaults":
        security_relevant = {"self_audit", "ai_integrated", "ai_executor", "async_worker", "safety_critical", "financial_path"}
        for key in security_relevant:
            if self.declarations.get(key) != "unknown":
                raise ValueError(f"security-relevant default {key!r} must be unknown")
        return self


class Manifest(StrictModel):
    schema_version: str
    framework: Framework
    decision_semantics: DecisionSemantics
    phases: Phases
    gates: Gates
    defaults: Defaults
