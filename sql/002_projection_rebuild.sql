-- Run only with the projection-admin role during maintenance.
BEGIN;
TRUNCATE TABLE ecom_prov_edges RESTART IDENTITY;
INSERT INTO ecom_prov_edges (
    relation_record_id,
    predicate,
    subject_ref,
    object_ref,
    created_at
)
SELECT
    record_id,
    record_json#>>'{payload,predicate}',
    (record_json#>>'{payload,subjectRef}')::uuid,
    (record_json#>>'{payload,objectRef}')::uuid,
    created_at
FROM ecom_records
WHERE kind = 'relation' AND type = 'provenance_relation'
ORDER BY created_at, record_id;
COMMIT;
