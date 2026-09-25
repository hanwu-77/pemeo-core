from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecom_backend.service import RecordService
from ecom_backend.store import InMemoryRecordStore


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "protocol" / "ecom_protocol_v0.1.schema.json"
EXAMPLE = ROOT / "protocol" / "ecom_protocol_v0.1.example.json"


@pytest.fixture
def example_dataset():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


@pytest.fixture
def service():
    return RecordService(SCHEMA)


@pytest.fixture
def store():
    return InMemoryRecordStore()
