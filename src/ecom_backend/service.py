from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .db_models import EcomRecordModel
from .errors import BusinessInvariantError
from .invariants import BusinessInvariantValidator
from .schema_validation import ProtocolSchemaValidator
from .store import InMemoryRecordStore, SqlAlchemyRecordLookup


class RecordService:
    """Protocol-first append service.

    Important: canonical record_json is the validated raw JSON object. Pydantic
    views are never used to reconstruct the canonical representation.
    """

    def __init__(self, schema_path: str | Path):
        self.schema_validator = ProtocolSchemaValidator(schema_path)
        self.business_validator = BusinessInvariantValidator()

    def validate_records(self, records: Iterable[Mapping[str, Any]], lookup: Any) -> list[dict[str, Any]]:
        canonical_records = self.schema_validator.validate_records(records)
        self.business_validator.validate_batch(canonical_records, lookup)
        return canonical_records

    def append_to_memory(
        self,
        store: InMemoryRecordStore,
        records: Iterable[Mapping[str, Any]],
    ) -> list[UUID]:
        canonical_records = self.validate_records(records, store)
        store.append_many(canonical_records)
        return [UUID(r["recordId"]) for r in canonical_records]

    def _stage_records(self, session: Session, records: Iterable[Mapping[str, Any]]) -> list[UUID]:
        raw_records = [deepcopy(dict(r)) for r in records]
        canonical_records = self.validate_records(raw_records, SqlAlchemyRecordLookup(session))
        ordered = sorted(canonical_records, key=lambda r: 1 if r["kind"] == "relation" else 0)
        for record in ordered:
            metadata = record["metadata"]
            session.add(EcomRecordModel(
                record_id=UUID(record["recordId"]), record_json=deepcopy(record),
                kind=record["kind"], type=record["type"],
                source_kind=metadata["source"]["kind"], attestation=metadata["attestation"],
                created_at=self._parse_dt(record["createdAt"]),
                occurred_at=self._parse_dt(record["occurredAt"]) if record.get("occurredAt") else None,
            ))
        return [UUID(r["recordId"]) for r in canonical_records]

    def append_in_transaction(self, session: Session, records: Iterable[Mapping[str, Any]]) -> list[UUID]:
        """Stage/flush only. Caller must own a dedicated active outer transaction."""
        if not session.in_transaction():
            raise ValueError("An explicit caller-owned transaction is required")
        ids = self._stage_records(session, records)
        session.flush()
        return ids

    def append_batch(self, session: Session, records: Iterable[Mapping[str, Any]]) -> list[UUID]:
        """Legacy standalone append; do not use inside the ingestion transaction."""
        try:
            ids = self._stage_records(session, records)
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            raise BusinessInvariantError(f"Atomic append failed; transaction rolled back: {exc}") from exc
        except Exception:
            session.rollback()
            raise
        return ids

    @staticmethod
    def _parse_dt(value: str):
        from datetime import datetime

        return datetime.fromisoformat(value.replace("Z", "+00:00"))
