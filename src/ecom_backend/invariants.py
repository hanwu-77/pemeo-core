from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from uuid import UUID

from .errors import BusinessInvariantError
from .registry import COMMON_REF_RULES, PREDICATE_RULES, TYPE_REF_RULES, RefRule


class RecordLookup:
    """Minimal interface required by business invariants."""

    def get_many(self, record_ids: set[UUID]) -> dict[UUID, dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError


class BusinessInvariantValidator:
    """Stage-2 validator for cross-record semantics JSON Schema cannot express."""

    def validate_batch(
        self,
        records: list[dict[str, Any]],
        lookup: RecordLookup,
    ) -> None:
        if not records:
            return

        batch_map = self._build_batch_map(records)
        ref_rules_by_record = {UUID(r["recordId"]): self._rules_for(r) for r in records}
        referenced_ids = self._collect_registered_refs(records, ref_rules_by_record)
        self._fail_on_unregistered_ref_paths(records, ref_rules_by_record)

        external_ids = referenced_ids - set(batch_map)
        existing_map = lookup.get_many(external_ids) if external_ids else {}
        missing = external_ids - set(existing_map)
        if missing:
            raise BusinessInvariantError(
                "Referenced record IDs do not exist in store or current batch: "
                + ", ".join(sorted(str(x) for x in missing))
            )

        context: dict[UUID, dict[str, Any]] = {**existing_map, **batch_map}

        for record in records:
            self._validate_local_red_lines(record)
            self._validate_refs(record, context, ref_rules_by_record[UUID(record["recordId"])])
            self._validate_relation(record, context)
            self._validate_temporal_rules(record, context)
            self._validate_mrt_rules(record, context)
            self._validate_output_assignment_consistency(record, context)
            self._validate_activity_rules(record, context)

    @staticmethod
    def _build_batch_map(records: list[dict[str, Any]]) -> dict[UUID, dict[str, Any]]:
        result: dict[UUID, dict[str, Any]] = {}
        for record in records:
            rid = UUID(record["recordId"])
            if rid in result:
                raise BusinessInvariantError(f"Duplicate recordId in batch: {rid}")
            result[rid] = record
        return result

    @staticmethod
    def _rules_for(record: Mapping[str, Any]) -> tuple[RefRule, ...]:
        return COMMON_REF_RULES + TYPE_REF_RULES.get(str(record["type"]), ())

    @staticmethod
    def _get_path(record: Mapping[str, Any], path: str) -> Any:
        current: Any = record
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                return None
            current = current[part]
        return current

    def _collect_registered_refs(
        self,
        records: Iterable[dict[str, Any]],
        rules_by_record: Mapping[UUID, tuple[RefRule, ...]],
    ) -> set[UUID]:
        refs: set[UUID] = set()
        for record in records:
            rid = UUID(record["recordId"])
            for rule in rules_by_record[rid]:
                value = self._get_path(record, rule.path)
                if value is None:
                    continue
                values = value if rule.many else [value]
                for raw in values:
                    if raw is not None:
                        refs.add(UUID(str(raw)))
        return refs

    def _fail_on_unregistered_ref_paths(
        self,
        records: Iterable[dict[str, Any]],
        rules_by_record: Mapping[UUID, tuple[RefRule, ...]],
    ) -> None:
        """Guard against future schema refs silently bypassing Stage-2 validation.

        Protocol v0.1 naming consistently uses *Ref/*Refs for cross-record UUIDs.
        If a new such field appears without a registry rule, fail closed.
        """
        ignored_non_record_refs = {"externalRef", "optionRef"}

        def walk(value: Any, path: str, found: set[str]) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else key
                    if key not in ignored_non_record_refs and (key.endswith("Ref") or key.endswith("Refs")):
                        found.add(child_path)
                    walk(child, child_path, found)
            elif isinstance(value, list):
                for child in value:
                    walk(child, path, found)

        for record in records:
            rid = UUID(record["recordId"])
            discovered: set[str] = set()
            walk(record, "", discovered)
            registered = {rule.path for rule in rules_by_record[rid]}
            unknown = discovered - registered
            if unknown:
                raise BusinessInvariantError(
                    f"Record {rid} contains unregistered RecordRef path(s): {sorted(unknown)}. "
                    "Update the versioned reference registry before ingestion."
                )

    def _validate_refs(
        self,
        record: Mapping[str, Any],
        context: Mapping[UUID, dict[str, Any]],
        rules: tuple[RefRule, ...],
    ) -> None:
        for rule in rules:
            value = self._get_path(record, rule.path)
            if value is None:
                if not rule.optional:
                    raise BusinessInvariantError(
                        f"Record {record['recordId']} missing required reference path {rule.path}"
                    )
                continue
            values = value if rule.many else [value]
            for raw in values:
                if raw is None:
                    if not rule.optional:
                        raise BusinessInvariantError(
                            f"Record {record['recordId']} has null required reference at {rule.path}"
                        )
                    continue
                target = context[UUID(str(raw))]
                if rule.expected_kinds and target["kind"] not in rule.expected_kinds:
                    raise BusinessInvariantError(
                        f"Semantic reference violation at {record['recordId']}:{rule.path}: "
                        f"expected kind {sorted(rule.expected_kinds)}, got {target['kind']}"
                    )
                if rule.expected_types and target["type"] not in rule.expected_types:
                    raise BusinessInvariantError(
                        f"Semantic reference violation at {record['recordId']}:{rule.path}: "
                        f"expected type {sorted(rule.expected_types)}, got {target['type']}"
                    )
                if rule.agent_type_matches_source:
                    expected_agent_type = record["metadata"]["source"]["kind"]
                    actual_agent_type = target.get("payload", {}).get("agentType")
                    if actual_agent_type != expected_agent_type:
                        raise BusinessInvariantError(
                            f"Source agent mismatch at {record['recordId']}:{rule.path}: "
                            f"source kind={expected_agent_type}, referenced agentType={actual_agent_type}"
                        )

    @staticmethod
    def _validate_local_red_lines(record: Mapping[str, Any]) -> None:
        metadata = record["metadata"]
        source = metadata["source"]["kind"]
        attestation = metadata["attestation"]
        rtype = record["type"]

        human_direct = {
            "human_statement",
            "human_snapshot",
            "human_initial_choice",
            "human_confirmation",
            "final_decision",
            "outcome_commitment",
            "recall_pre_outcome",
            "recall_post_outcome",
        }
        if rtype in human_direct and (source != "human" or attestation != "direct"):
            raise BusinessInvariantError(
                f"{rtype} must have source.kind='human' and attestation='direct'"
            )

        if rtype == "inferred_framing":
            if source != "ecom" or attestation != "derived":
                raise BusinessInvariantError(
                    "inferred_framing must have source.kind='ecom' and attestation='derived'"
                )
            confidence = metadata.get("modelReportedConfidence")
            if confidence not in {"low", "medium", "high"}:
                raise BusinessInvariantError(
                    "inferred_framing requires metadata.modelReportedConfidence in low|medium|high"
                )

        if rtype == "intervention_assignment":
            if source != "ecom" or attestation != "assigned":
                raise BusinessInvariantError(
                    "intervention_assignment must have source.kind='ecom' and attestation='assigned'"
                )

    @staticmethod
    def _validate_relation(record: Mapping[str, Any], context: Mapping[UUID, dict[str, Any]]) -> None:
        if record["kind"] != "relation":
            return
        payload = record["payload"]
        pred = payload["predicate"]
        if pred not in PREDICATE_RULES:
            raise BusinessInvariantError(f"Unsupported Protocol v0.1 provenance predicate: {pred}")
        subject = context[UUID(payload["subjectRef"])]
        obj = context[UUID(payload["objectRef"])]
        allowed_subject, allowed_object = PREDICATE_RULES[pred]
        if subject["kind"] not in allowed_subject or obj["kind"] not in allowed_object:
            raise BusinessInvariantError(
                f"PROV domain/range violation for {pred}: {subject['kind']} -> {obj['kind']}"
            )
        # Never trust declared kinds if the referenced records disagree.
        if payload["subjectKind"] != subject["kind"] or payload["objectKind"] != obj["kind"]:
            raise BusinessInvariantError(
                f"Declared relation kinds disagree with referenced records for {record['recordId']}"
            )

    @staticmethod
    def _parse_dt(value: str) -> datetime:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    def _validate_temporal_rules(
        self,
        record: Mapping[str, Any],
        context: Mapping[UUID, dict[str, Any]],
    ) -> None:
        rtype = record["type"]
        payload = record["payload"]

        if rtype == "outcome_commitment":
            committed = self._parse_dt(payload["committedAt"])
            evaluation = self._parse_dt(payload["evaluationAt"])
            if evaluation < committed:
                raise BusinessInvariantError("outcome_commitment.evaluationAt must not precede committedAt")

        if rtype == "outcome_observation":
            commitment_ref = payload.get("commitmentRef")
            if commitment_ref is None:
                return
            target = context[UUID(commitment_ref)]
            committed_at = self._parse_dt(target["payload"]["committedAt"])
            occurred_raw = record.get("occurredAt")
            if not occurred_raw:
                raise BusinessInvariantError("outcome_observation with commitmentRef requires occurredAt")
            occurred = self._parse_dt(occurred_raw)
            if occurred <= committed_at:
                raise BusinessInvariantError(
                    "outcome_observation.occurredAt must be later than referenced outcome_commitment.committedAt"
                )
            committed_names = {c["name"] for c in target["payload"]["criteria"]}
            observed_names = {c["criterionName"] for c in payload.get("criterionResults", [])}
            unknown = observed_names - committed_names
            if unknown:
                raise BusinessInvariantError(
                    f"outcome_observation contains criterionResult(s) absent from commitment: {sorted(unknown)}"
                )

        if rtype in {"confirmation_activity", "decision_making_activity", "execution_activity"}:
            started = self._parse_dt(payload["startedAt"])
            ended_raw = payload.get("endedAt")
            if ended_raw is not None and self._parse_dt(ended_raw) < started:
                raise BusinessInvariantError(f"{rtype}.endedAt must not precede startedAt")

    def _validate_mrt_rules(
        self,
        record: Mapping[str, Any],
        context: Mapping[UUID, dict[str, Any]],
    ) -> None:
        if record["type"] != "intervention_assignment":
            return
        payload = record["payload"]
        if not payload["availability"] and payload["assignedIntervention"] != "control_none":
            raise BusinessInvariantError(
                "MRT invariant: availability=false requires assignedIntervention='control_none'"
            )

        dp = context[UUID(payload["decisionPointRef"])]
        ctx = context[UUID(dp["payload"]["contextRef"])]
        non_control = payload["assignedIntervention"] != "control_none"
        if non_control:
            if not payload["availability"]:
                raise BusinessInvariantError("Non-control intervention requires availability=true")
            if payload.get("userOptedIn") is not True:
                raise BusinessInvariantError("Non-control MRT intervention requires userOptedIn=true")
            if dp["payload"].get("eligibleForMrt") is not True:
                raise BusinessInvariantError("Non-control MRT intervention requires decision_point.eligibleForMrt=true")
            if ctx["payload"]["stakes"] != "low" or ctx["payload"]["timePressure"] != "low":
                raise BusinessInvariantError(
                    "Eligibility Mask v0.1 permits experimental intervention only for low stakes and low time pressure"
                )

    @staticmethod
    def _validate_output_assignment_consistency(
        record: Mapping[str, Any],
        context: Mapping[UUID, dict[str, Any]],
    ) -> None:
        if record["type"] != "ecom_output":
            return
        assignment_ref = record["payload"].get("assignmentRef")
        if not assignment_ref:
            return
        assignment = context[UUID(assignment_ref)]
        assigned_mode = assignment["payload"]["assignedIntervention"]
        output_mode = record["payload"]["outputMode"]
        if assigned_mode != output_mode:
            raise BusinessInvariantError(
                f"ecom_output.outputMode={output_mode} does not match assignedIntervention={assigned_mode}"
            )

    @staticmethod
    def _validate_activity_rules(record: Mapping[str, Any], context: Mapping[UUID, dict[str, Any]]) -> None:
        rtype = record["type"]
        payload = record["payload"]
        if rtype == "confirmation_activity":
            human_agent = context[UUID(payload["humanAgentRef"])]
            if human_agent.get("payload", {}).get("agentType") != "human":
                raise BusinessInvariantError("confirmation_activity.humanAgentRef must reference a human agent")
        if rtype == "decision_making_activity":
            human_agent = context[UUID(payload["humanAgentRef"])]
            if human_agent.get("payload", {}).get("agentType") != "human":
                raise BusinessInvariantError("decision_making_activity.humanAgentRef must reference a human agent")
