from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("ECOM_RUN_PG_TESTS") != "1",
    reason="Set ECOM_RUN_PG_TESTS=1 with a running PostgreSQL dev database",
)


def _engine():
    from sqlalchemy import create_engine

    url = os.environ.get(
        "ECOM_DATABASE_URL",
        "postgresql+psycopg://ecom_dev:ecom_dev_only@localhost:5432/ecom",
    )
    return create_engine(url, future=True)


def _load_example():
    root = Path(__file__).resolve().parents[1]
    return json.loads((root / "protocol" / "ecom_protocol_v0.1.example.json").read_text(encoding="utf-8"))


def test_atomic_append_and_relation_projection(service):
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    engine = _engine()
    example = _load_example()
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE ecom_prov_edges, ecom_records RESTART IDENTITY CASCADE"))

    with Session(engine) as session:
        service.append_batch(session, example["records"])

    relation_count = sum(r["kind"] == "relation" for r in example["records"])
    with engine.connect() as conn:
        stored = conn.execute(text("SELECT count(*) FROM ecom_records")).scalar_one()
        edges = conn.execute(text("SELECT count(*) FROM ecom_prov_edges")).scalar_one()
    assert stored == len(example["records"])
    assert edges == relation_count


def test_canonical_record_update_is_blocked(service):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.orm import Session

    engine = _engine()
    example = _load_example()
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE ecom_prov_edges, ecom_records RESTART IDENTITY CASCADE"))
    with Session(engine) as session:
        service.append_batch(session, example["records"][:1])

    rid = example["records"][0]["recordId"]
    with pytest.raises(DBAPIError):
        with engine.begin() as conn:
            conn.execute(text("UPDATE ecom_records SET type='tampered' WHERE record_id=:id"), {"id": rid})


def test_database_failure_rolls_back_whole_batch(service):
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    engine = _engine()
    example = _load_example()
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE ecom_prov_edges, ecom_records RESTART IDENTITY CASCADE"))

    existing = deepcopy(example["records"][0])
    with Session(engine) as session:
        service.append_batch(session, [existing])

    # Two schema-valid agent records: first is new, second collides with an existing PK.
    new_record = deepcopy(existing)
    new_record["recordId"] = str(uuid4())
    new_record["payload"]["label"] = "Should roll back"
    colliding = deepcopy(existing)

    with Session(engine) as session:
        with pytest.raises(Exception):
            service.append_batch(session, [new_record, colliding])

    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM ecom_records WHERE record_id=:id"),
            {"id": new_record["recordId"]},
        ).scalar_one()
    assert count == 0
