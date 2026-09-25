from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


RecordKind = Literal["entity", "activity", "agent", "event", "relation"]


class SourceView(BaseModel):
    """Typed read view only. Never used to serialize canonical records."""

    model_config = ConfigDict(extra="allow", frozen=True)
    kind: str
    agentRef: UUID | None = None


class MetadataView(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)
    source: SourceView
    attestation: str
    verification: str
    modelReportedConfidence: str | None = None


class RecordView(BaseModel):
    """Convenient read-only typed projection over a schema-validated raw record."""

    model_config = ConfigDict(extra="allow", frozen=True)
    recordId: UUID
    protocolVersion: str
    schemaVersion: str
    kind: RecordKind
    type: str
    createdAt: datetime
    occurredAt: datetime | None = None
    metadata: MetadataView
    payload: dict[str, Any]
