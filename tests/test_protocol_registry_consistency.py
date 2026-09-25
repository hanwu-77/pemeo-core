from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ecom_backend.registry import COMMON_REF_RULES, PREDICATE_RULES, TYPE_REF_RULES


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "protocol" / "ecom_protocol_v0.1.schema.json").read_text(encoding="utf-8"))


def _local_def_name(ref: str) -> str:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise AssertionError(f"Only local $defs refs are supported by this consistency test: {ref}")
    return ref[len(prefix) :]


def _find_record_type_const(node: Any, seen_defs: tuple[str, ...] = ()) -> str | None:
    if not isinstance(node, dict):
        return None

    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        name = _local_def_name(ref)
        if name in seen_defs:
            return None
        return _find_record_type_const(SCHEMA["$defs"][name], seen_defs + (name,))

    type_schema = node.get("properties", {}).get("type")
    if isinstance(type_schema, dict) and isinstance(type_schema.get("const"), str):
        return type_schema["const"]

    for combiner in ("allOf", "oneOf", "anyOf"):
        for child in node.get(combiner, []):
            result = _find_record_type_const(child, seen_defs)
            if result is not None:
                return result
    return None


def _collect_record_ref_paths(
    node: Any,
    path: str = "",
    seen_defs: tuple[str, ...] = (),
) -> set[str]:
    """Collect every cross-record Ref/Refs path declared by a record schema.

    Protocol v0.1 uses either $defs/recordRef or an explicit UUID-formatted
    nullable string for cross-record references (assignmentRef/commitmentRef).
    Arrays keep the logical field path rather than introducing item indices.
    """
    if not isinstance(node, dict):
        return set()

    ref = node.get("$ref")
    if isinstance(ref, str):
        if ref == "#/$defs/recordRef":
            return {path} if path else set()
        if ref.startswith("#/$defs/"):
            name = _local_def_name(ref)
            if name in seen_defs:
                return set()
            return _collect_record_ref_paths(SCHEMA["$defs"][name], path, seen_defs + (name,))

    found: set[str] = set()
    leaf_name = path.rsplit(".", 1)[-1] if path else ""
    if (
        path
        and (leaf_name.endswith("Ref") or leaf_name.endswith("Refs"))
        and node.get("format") == "uuid"
    ):
        found.add(path)

    for combiner in ("allOf", "oneOf", "anyOf"):
        for child in node.get(combiner, []):
            found |= _collect_record_ref_paths(child, path, seen_defs)

    for name, child in node.get("properties", {}).items():
        child_path = f"{path}.{name}" if path else name
        found |= _collect_record_ref_paths(child, child_path, seen_defs)

    items = node.get("items")
    if isinstance(items, dict):
        found |= _collect_record_ref_paths(items, path, seen_defs)

    return found


def test_predicate_registry_matches_frozen_relation_schema():
    relation_payload = None
    relation_def = SCHEMA["$defs"]["relationRecord"]
    for part in relation_def.get("allOf", []):
        if "properties" in part and "payload" in part["properties"]:
            relation_payload = part["properties"]["payload"]
            break
    assert relation_payload is not None

    schema_predicates: set[str] = set()
    for branch in relation_payload["oneOf"]:
        pred = branch["properties"]["predicate"]
        if "const" in pred:
            schema_predicates.add(pred["const"])
        else:
            schema_predicates.update(pred["enum"])

    assert schema_predicates == set(PREDICATE_RULES)


def test_all_protocol_record_refs_match_versioned_registry():
    """Every Protocol v0.1 record-reference path must be registry-covered.

    This traverses all 27 concrete record schemas, resolving nested $defs,
    allOf/oneOf branches, recallPayload, relationRecord branches, and the shared
    metadata definitions. It catches both new schema refs missing from the
    registry and stale registry paths no longer present in the frozen schema.
    """
    common_paths = {rule.path for rule in COMMON_REF_RULES}
    seen_types: set[str] = set()

    for branch in SCHEMA["$defs"]["record"]["oneOf"]:
        definition_name = _local_def_name(branch["$ref"])
        record_schema = SCHEMA["$defs"][definition_name]
        record_type = _find_record_type_const(record_schema)
        assert record_type is not None, f"Could not resolve record type for $defs/{definition_name}"
        assert record_type not in seen_types, f"Duplicate record type in schema union: {record_type}"
        seen_types.add(record_type)

        schema_paths = _collect_record_ref_paths(record_schema)
        registry_paths = common_paths | {
            rule.path for rule in TYPE_REF_RULES.get(record_type, ())
        }
        assert schema_paths == registry_paths, (
            f"Schema/registry RecordRef drift for type={record_type}: "
            f"schema_only={sorted(schema_paths - registry_paths)}, "
            f"registry_only={sorted(registry_paths - schema_paths)}"
        )

    # Guard against stale type-specific registry sections for types no longer in
    # the Protocol record union.
    assert set(TYPE_REF_RULES).issubset(seen_types)
