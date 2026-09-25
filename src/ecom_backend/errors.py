from __future__ import annotations


class EcomValidationError(Exception):
    """Base class for protocol validation failures."""


class SchemaValidationError(EcomValidationError):
    """Draft 2020-12 JSON Schema validation failed."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("Schema validation failed:\n" + "\n".join(errors))


class BusinessInvariantError(EcomValidationError):
    """Cross-record or protocol business invariant failed."""
