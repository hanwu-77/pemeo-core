from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class RefRule:
    path: str
    expected_kinds: FrozenSet[str] | None = None
    expected_types: FrozenSet[str] | None = None
    optional: bool = True
    many: bool = False
    agent_type_matches_source: bool = False


# Every UUID reference in Protocol v0.1 that has cross-record semantics.
# The validator also scans for unregistered *Ref/*Refs fields to prevent silent omissions.
COMMON_REF_RULES: tuple[RefRule, ...] = (
    RefRule("metadata.source.agentRef", frozenset({"agent"}), optional=True, agent_type_matches_source=True),
    RefRule("metadata.provenance.evidenceRefs", optional=True, many=True),
    RefRule("metadata.provenance.relationRefs", frozenset({"relation"}), optional=True, many=True),
)

TYPE_REF_RULES: dict[str, tuple[RefRule, ...]] = {
    "human_snapshot": (
        RefRule("payload.predictionRefs", frozenset({"entity"}), frozenset({"prediction"}), many=True),
    ),
    "human_confirmation": (
        RefRule("payload.targetRef", frozenset({"entity"}), optional=False),
    ),
    "outcome_commitment": (
        RefRule("payload.proposalRef", frozenset({"entity"}), frozenset({"outcome_proposal"}), optional=False),
    ),
    "recall_pre_outcome": (
        RefRule(
            "payload.informationExposureRefs",
            frozenset({"event"}),
            frozenset({"exposure_presented", "exposure_accessed", "exposure_acknowledged"}),
            many=True,
        ),
    ),
    "recall_post_outcome": (
        RefRule(
            "payload.informationExposureRefs",
            frozenset({"event"}),
            frozenset({"exposure_presented", "exposure_accessed", "exposure_acknowledged"}),
            many=True,
        ),
    ),
    "decision_point": (
        RefRule("payload.contextRef", frozenset({"entity"}), frozenset({"context_snapshot"}), optional=False),
    ),
    "intervention_assignment": (
        RefRule("payload.decisionPointRef", frozenset({"event"}), frozenset({"decision_point"}), optional=False),
    ),
    "ecom_output": (
        RefRule("payload.assignmentRef", frozenset({"event"}), frozenset({"intervention_assignment"}), optional=True),
    ),
    "exposure_presented": (
        RefRule("payload.outputRef", frozenset({"entity"}), frozenset({"ecom_output"}), optional=False),
    ),
    "exposure_accessed": (
        RefRule("payload.outputRef", frozenset({"entity"}), frozenset({"ecom_output"}), optional=False),
    ),
    "exposure_acknowledged": (
        RefRule("payload.outputRef", frozenset({"entity"}), frozenset({"ecom_output"}), optional=False),
    ),
    "proximal_outcome_observation": (
        RefRule("payload.specRef", frozenset({"entity"}), frozenset({"proximal_outcome_spec"}), optional=False),
    ),
    "outcome_observation": (
        RefRule("payload.commitmentRef", frozenset({"entity"}), frozenset({"outcome_commitment"}), optional=True),
    ),
    "confirmation_activity": (
        RefRule("payload.usedRef", frozenset({"entity"}), optional=False),
        RefRule("payload.generatedRef", frozenset({"entity"}), frozenset({"human_confirmation"}), optional=False),
        RefRule("payload.humanAgentRef", frozenset({"agent"}), frozenset({"agent"}), optional=False),
    ),
    "decision_making_activity": (
        RefRule("payload.decisionPointRef", frozenset({"event"}), frozenset({"decision_point"}), optional=False),
        RefRule("payload.humanAgentRef", frozenset({"agent"}), frozenset({"agent"}), optional=False),
        RefRule("payload.usedRefs", optional=True, many=True),
        RefRule(
            "payload.generatedDecisionRefs",
            frozenset({"entity"}),
            frozenset({"human_initial_choice", "final_decision"}),
            optional=True,
            many=True,
        ),
    ),
    "execution_activity": (
        RefRule(
            "payload.decisionRef",
            frozenset({"entity"}),
            frozenset({"human_initial_choice", "final_decision"}),
            optional=False,
        ),
    ),
    "provenance_relation": (
        RefRule("payload.subjectRef", optional=False),
        RefRule("payload.objectRef", optional=False),
    ),
}


# Predicate domain/range rules from the frozen Protocol v0.1 relationRecord schema.
PREDICATE_RULES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "prov:wasDerivedFrom": (frozenset({"entity"}), frozenset({"entity"})),
    "prov:wasGeneratedBy": (frozenset({"entity"}), frozenset({"activity"})),
    "prov:wasAssociatedWith": (frozenset({"activity"}), frozenset({"agent"})),
    "prov:used": (frozenset({"activity"}), frozenset({"entity"})),
    "prov:wasInvalidatedBy": (frozenset({"entity"}), frozenset({"activity"})),
    "ecom:supportedBy": (frozenset({"entity"}), frozenset({"entity"})),
    "ecom:contradictedBy": (frozenset({"entity"}), frozenset({"entity"})),
    "ecom:confirmedBy": (frozenset({"entity"}), frozenset({"entity"})),
}
