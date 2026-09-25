from __future__ import annotations

from copy import deepcopy

import pytest
from sqlalchemy.exc import SQLAlchemyError

from ecom_backend.errors import BusinessInvariantError


class _FailingSession:
    def __init__(self, exc: Exception):
        self.exc = exc
        self.rolled_back = False

    def add(self, _obj):
        raise self.exc

    def commit(self):  # pragma: no cover - add() fails first
        raise AssertionError("commit should not be reached")

    def rollback(self):
        self.rolled_back = True


def _patch_validated_records(service, monkeypatch, example_dataset):
    record = deepcopy(example_dataset["records"][0])
    monkeypatch.setattr(service, "validate_records", lambda records, lookup: [record])
    return record


def test_sqlalchemy_errors_are_wrapped_as_business_invariant_error(
    service, monkeypatch, example_dataset
):
    _patch_validated_records(service, monkeypatch, example_dataset)
    session = _FailingSession(SQLAlchemyError("database failure"))

    with pytest.raises(BusinessInvariantError, match="Atomic append failed"):
        service.append_batch(session, [{}])

    assert session.rolled_back is True


def test_programming_errors_keep_original_exception_type(
    service, monkeypatch, example_dataset
):
    _patch_validated_records(service, monkeypatch, example_dataset)
    session = _FailingSession(TypeError("programming bug"))

    with pytest.raises(TypeError, match="programming bug"):
        service.append_batch(session, [{}])

    assert session.rolled_back is True
