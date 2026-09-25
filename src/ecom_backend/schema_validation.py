from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .errors import SchemaValidationError


class ProtocolSchemaValidator:
    """Authoritative Stage-1 validator for ECOM Protocol v0.1.

    The frozen JSON Schema is the source of truth. This class never normalizes,
    rewrites, or serializes a record for canonical storage.
    """

    def __init__(self, schema_path: str | Path):
        self.schema_path = Path(schema_path)
        with self.schema_path.open("r", encoding="utf-8") as fh:
            self.schema: dict[str, Any] = json.load(fh)
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(
            self.schema,
            format_checker=FormatChecker(),
        )

    def validate_dataset(self, dataset: Mapping[str, Any]) -> dict[str, Any]:
        errors = sorted(self.validator.iter_errors(dataset), key=self._sort_key)
        if errors:
            rendered = [self._render_error(error) for error in errors]
            raise SchemaValidationError(rendered)
        # Canonical storage receives a defensive copy of the original validated
        # JSON, not a Pydantic re-serialization.
        return deepcopy(dict(dataset))

    def validate_records(self, records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        dataset = {
            "protocolVersion": "0.1",
            "schemaVersion": "0.1.0",
            "records": [deepcopy(dict(record)) for record in records],
        }
        validated = self.validate_dataset(dataset)
        return validated["records"]

    @staticmethod
    def _sort_key(error: Any) -> list[str]:
        return [str(part) for part in error.absolute_path]

    @staticmethod
    def _render_error(error: Any) -> str:
        path = "$"
        for part in error.absolute_path:
            path += f"[{part}]" if isinstance(part, int) else f".{part}"
        return f"{path}: {error.message}"
