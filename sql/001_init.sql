-- ECOM Protocol v0.1 — PostgreSQL canonical append-only store
-- PostgreSQL >= 14. Canonical truth lives only in ecom_records.record_json.

BEGIN;

CREATE TABLE IF NOT EXISTS ecom_records (
    record_id       UUID PRIMARY KEY,
    record_json     JSONB NOT NULL,

    -- Indexed projections. They MUST agree with canonical record_json.
    kind            VARCHAR(32) NOT NULL,
    type            VARCHAR(64) NOT NULL,
    source_kind     VARCHAR(32) NOT NULL,
    attestation     VARCHAR(32) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    occurred_at     TIMESTAMPTZ NULL,

    CONSTRAINT chk_kind_projection
        CHECK (kind = record_json->>'kind'),
    CONSTRAINT chk_type_projection
        CHECK (type = record_json->>'type'),
    CONSTRAINT chk_source_projection
        CHECK (source_kind = record_json#>>'{metadata,source,kind}'),
    CONSTRAINT chk_attestation_projection
        CHECK (attestation = record_json#>>'{metadata,attestation}')
);

CREATE TABLE IF NOT EXISTS ecom_prov_edges (
    edge_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    relation_record_id  UUID NOT NULL UNIQUE
        REFERENCES ecom_records(record_id) ON DELETE RESTRICT,
    predicate           VARCHAR(64) NOT NULL,
    subject_ref         UUID NOT NULL
        REFERENCES ecom_records(record_id) ON DELETE RESTRICT,
    object_ref          UUID NOT NULL
        REFERENCES ecom_records(record_id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ecom_records_type_occurred
    ON ecom_records (type, occurred_at DESC)
    WHERE occurred_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ecom_records_kind_type_created
    ON ecom_records (kind, type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ecom_records_source_attestation
    ON ecom_records (source_kind, attestation);

CREATE INDEX IF NOT EXISTS idx_prov_edges_subject_pred
    ON ecom_prov_edges (subject_ref, predicate) INCLUDE (object_ref);

CREATE INDEX IF NOT EXISTS idx_prov_edges_object_pred
    ON ecom_prov_edges (object_ref, predicate) INCLUDE (subject_ref);

-- Canonical store is immutable at runtime.
CREATE OR REPLACE FUNCTION ecom_block_record_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ECOM Protocol violation: canonical records are append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ecom_records_immutable ON ecom_records;
CREATE TRIGGER trg_ecom_records_immutable
BEFORE UPDATE OR DELETE ON ecom_records
FOR EACH ROW EXECUTE FUNCTION ecom_block_record_mutation();

-- Read-model projection is derived only from canonical relation records.
CREATE OR REPLACE FUNCTION ecom_project_relation_edge()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.kind = 'relation' AND NEW.type = 'provenance_relation' THEN
        INSERT INTO ecom_prov_edges (
            relation_record_id,
            predicate,
            subject_ref,
            object_ref,
            created_at
        ) VALUES (
            NEW.record_id,
            NEW.record_json#>>'{payload,predicate}',
            (NEW.record_json#>>'{payload,subjectRef}')::uuid,
            (NEW.record_json#>>'{payload,objectRef}')::uuid,
            NEW.created_at
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ecom_project_relation ON ecom_records;
CREATE TRIGGER trg_ecom_project_relation
AFTER INSERT ON ecom_records
FOR EACH ROW EXECUTE FUNCTION ecom_project_relation_edge();

-- Runtime permissions should be provisioned with separate roles in deployment.
-- ecom_app_writer: SELECT, INSERT on ecom_records; no direct DML on ecom_prov_edges.
-- ecom_projection_admin: may rebuild ecom_prov_edges from canonical relation records.

COMMIT;
