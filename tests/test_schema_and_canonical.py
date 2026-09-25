from __future__ import annotations

from copy import deepcopy

import pytest

from ecom_backend.errors import SchemaValidationError
from ecom_backend.models import RecordView


def test_example_passes_schema_and_invariants(service, store, example_dataset):
    ids = service.append_to_memory(store, example_dataset["records"])
    assert len(ids) == len(example_dataset["records"])


def test_canonical_raw_json_preserves_provenance(service, store, example_dataset):
    record = deepcopy(next(r for r in example_dataset["records"] if r["type"] == "inferred_framing"))
    record["metadata"]["tags"] = ["preserve-me"]
    service.append_to_memory(store, [
        next(r for r in example_dataset["records"] if r["type"] == "agent" and r["payload"]["agentType"] == "ecom"),
        next(r for r in example_dataset["records"] if r["type"] == "human_statement"),
        record,
    ])
    stored = store.get(RecordView.model_validate(record).recordId)
    assert stored["metadata"]["provenance"] == record["metadata"]["provenance"]
    assert stored["metadata"]["tags"] == ["preserve-me"]


def test_ai_cannot_spoof_human_snapshot(service, store, example_dataset):
    rec = deepcopy(next(r for r in example_dataset["records"] if r["type"] == "human_snapshot"))
    rec["metadata"]["source"]["kind"] = "ecom"
    rec["metadata"]["attestation"] = "derived"
    with pytest.raises(SchemaValidationError):
        service.append_to_memory(store, [rec])


def test_inferred_framing_confidence_is_metadata_not_payload(service, store, example_dataset):
    agents = [r for r in example_dataset["records"] if r["type"] == "agent"]
    human_statement = next(r for r in example_dataset["records"] if r["type"] == "human_statement")
    rec = deepcopy(next(r for r in example_dataset["records"] if r["type"] == "inferred_framing"))
    assert rec["metadata"]["modelReportedConfidence"] in {"low", "medium", "high"}
    assert "modelReportedConfidence" not in rec["payload"]
    # Need referenced source/evidence records in same batch.
    service.append_to_memory(store, agents + [human_statement, rec])
