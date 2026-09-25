from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from ecom_backend.errors import BusinessInvariantError


def by_type(dataset, type_):
    return next(deepcopy(r) for r in dataset["records"] if r["type"] == type_)


def dependency_closure(dataset, root_record):
    """Return all example records needed by Stage-2 refs for a selected root.

    Simpler than production discovery; tests can also load the full example dataset.
    """
    return deepcopy(dataset["records"])


def test_missing_reference_rejected(service, store, example_dataset):
    rec = by_type(example_dataset, "decision_point")
    rec["payload"]["contextRef"] = str(uuid4())
    with pytest.raises(BusinessInvariantError, match="do not exist"):
        service.append_to_memory(store, [rec])


def test_semantically_wrong_reference_type_rejected(service, store, example_dataset):
    records = deepcopy(example_dataset["records"])
    human_statement = next(r for r in records if r["type"] == "human_statement")
    dp = next(r for r in records if r["type"] == "decision_point")
    dp["payload"]["contextRef"] = human_statement["recordId"]
    with pytest.raises(BusinessInvariantError, match="Semantic reference violation"):
        service.append_to_memory(store, records)


def test_outcome_before_commitment_rejected(service, store, example_dataset):
    records = deepcopy(example_dataset["records"])
    commitment = next(r for r in records if r["type"] == "outcome_commitment")
    # Add a schema-valid observation linked to the commitment.
    observation = {
        "recordId": str(uuid4()),
        "protocolVersion": "0.1",
        "schemaVersion": "0.1.0",
        "kind": "event",
        "type": "outcome_observation",
        "createdAt": commitment["payload"]["committedAt"],
        "occurredAt": commitment["payload"]["committedAt"],
        "metadata": {
            "source": {"kind": "external_sensor"},
            "attestation": "observed",
            "verification": "verified",
            "provenance": {"protocolSourceVersion": "0.1", "evidenceRefs": [], "relationRefs": []},
        },
        "payload": {
            "commitmentRef": commitment["recordId"],
            "observation": {"status": "too-early"},
            "criterionResults": [],
            "notes": None,
        },
    }
    records.append(observation)
    with pytest.raises(BusinessInvariantError, match="must be later"):
        service.append_to_memory(store, records)


def test_null_commitment_reference_is_allowed(service, store, example_dataset):
    sensor_agent = deepcopy(example_dataset["records"][0])
    # Do not use agentRef in metadata to avoid requiring a matching external_sensor agent.
    observation = {
        "recordId": str(uuid4()),
        "protocolVersion": "0.1",
        "schemaVersion": "0.1.0",
        "kind": "event",
        "type": "outcome_observation",
        "createdAt": "2026-09-10T20:00:00Z",
        "occurredAt": "2026-09-10T20:00:00Z",
        "metadata": {
            "source": {"kind": "external_sensor"},
            "attestation": "observed",
            "verification": "verified",
            "provenance": {"protocolSourceVersion": "0.1", "evidenceRefs": [], "relationRefs": []},
        },
        "payload": {"commitmentRef": None, "observation": {"status": "observed"}, "criterionResults": []},
    }
    service.append_to_memory(store, [observation])


def test_mrt_unavailable_must_be_control(service, store, example_dataset):
    records = deepcopy(example_dataset["records"])
    assignment = next(r for r in records if r["type"] == "intervention_assignment")
    assignment["payload"]["availability"] = False
    assignment["payload"]["assignedIntervention"] = "socratic"
    with pytest.raises(BusinessInvariantError, match="availability=false"):
        service.append_to_memory(store, records)


def test_relation_actual_kinds_are_checked(service, store, example_dataset):
    records = deepcopy(example_dataset["records"])
    relation = next(r for r in records if r["type"] == "provenance_relation")
    # Pick an agent and force it into a wasDerivedFrom relation while payload still declares entity.
    agent = next(r for r in records if r["type"] == "agent")
    relation["payload"]["subjectRef"] = agent["recordId"]
    with pytest.raises(BusinessInvariantError):
        service.append_to_memory(store, records)
