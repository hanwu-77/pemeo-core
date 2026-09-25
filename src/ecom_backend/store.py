from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db_models import EcomRecordModel
from .invariants import RecordLookup


class RecordStore(RecordLookup, ABC):
    @abstractmethod
    def append_many(self, records: list[dict[str, Any]]) -> None:
        raise NotImplementedError


class InMemoryRecordStore(RecordStore):
    """Test/demo store with append-only semantics."""

    def __init__(self) -> None:
        self._records: dict[UUID, dict[str, Any]] = {}

    def get_many(self, record_ids: set[UUID]) -> dict[UUID, dict[str, Any]]:
        return {rid: deepcopy(self._records[rid]) for rid in record_ids if rid in self._records}

    def append_many(self, records: list[dict[str, Any]]) -> None:
        ids = [UUID(r["recordId"]) for r in records]
        collision = set(ids) & set(self._records)
        if collision:
            raise ValueError(f"recordId already exists: {collision}")
        for record in records:
            self._records[UUID(record["recordId"])] = deepcopy(record)

    def get(self, record_id: UUID) -> dict[str, Any] | None:
        value = self._records.get(record_id)
        return deepcopy(value) if value else None


class SqlAlchemyRecordLookup(RecordLookup):
    """Read-side lookup used by RecordService before an atomic append transaction."""

    def __init__(self, session: Session):
        self.session = session

    def get_many(self, record_ids: set[UUID]) -> dict[UUID, dict[str, Any]]:
        if not record_ids:
            return {}
        rows = self.session.execute(
            select(EcomRecordModel.record_id, EcomRecordModel.record_json).where(
                EcomRecordModel.record_id.in_(record_ids)
            )
        ).all()
        return {record_id: deepcopy(record_json) for record_id, record_json in rows}
