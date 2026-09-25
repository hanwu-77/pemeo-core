from __future__ import annotations

import argparse
import json
from pathlib import Path

from .errors import EcomValidationError
from .schema_validation import ProtocolSchemaValidator
from .invariants import BusinessInvariantValidator
from .store import InMemoryRecordStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an ECOM Protocol v0.1 JSON dataset")
    parser.add_argument("json_file", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "protocol" / "ecom_protocol_v0.1.schema.json",
    )
    args = parser.parse_args()

    dataset = json.loads(args.json_file.read_text(encoding="utf-8"))
    schema_validator = ProtocolSchemaValidator(args.schema)
    try:
        canonical = schema_validator.validate_dataset(dataset)
        records = canonical["records"]
        BusinessInvariantValidator().validate_batch(records, InMemoryRecordStore())
    except EcomValidationError as exc:
        print(f"INVALID\n{exc}")
        return 1

    print(f"VALID: {len(records)} record(s) passed Protocol v0.1 schema + business invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
