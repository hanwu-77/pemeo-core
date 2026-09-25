from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EcomRecordModel(Base):
    __tablename__ = "ecom_records"

    record_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    record_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    attestation: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EcomProvEdgeModel(Base):
    __tablename__ = "ecom_prov_edges"

    edge_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    relation_record_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ecom_records.record_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    predicate: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_ref: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("ecom_records.record_id", ondelete="RESTRICT"), nullable=False
    )
    object_ref: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("ecom_records.record_id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
