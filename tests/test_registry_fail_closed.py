from __future__ import annotations

from copy import deepcopy

import pytest

from ecom_backend.errors import BusinessInvariantError


def test_all_protocol_example_refs_are_registered(service, store, example_dataset):
    # The complete frozen example exercises the current registry and must pass.
    service.append_to_memory(store, deepcopy(example_dataset["records"]))


def test_unregistered_ref_path_fails_closed(service, store, example_dataset):
    """A future *Ref/*Refs field may never silently bypass Stage-2 validation.

    This deliberately calls the business validator through the service's
    validation path after mutating a schema-shaped record. The field itself is
    not part of Protocol v0.1; the point is to lock the fail-closed behavior so
    future protocol additions require a registry update before ingestion.
    """
    records = deepcopy(example_dataset["records"])
    target = next(record for record in records if record["type"] == "agent")
    target["payload"]["someNewThingRef"] = "00000000-0000-4000-8000-000000000001"

    # Bypass Stage 1 intentionally: this is a regression test for the Stage-2
    # future-schema safety barrier itself, not for current schema rejection.
    with pytest.raises(BusinessInvariantError, match="unregistered RecordRef path"):
        service.business_validator.validate_batch(records, store)
