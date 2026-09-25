-- Static maintenance entry point: no arbitrary SQL, IDs, paths or table arguments.
-- Original 002 SQL is retained unchanged; sequence restart needs owner rights.
BEGIN;
DO $guard$
BEGIN
    IF current_database() <> 'pemeo_core_test' OR current_user <> 'pemeo_core_test'
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        RAISE EXCEPTION 'F1 requires the guarded PeMeO synthetic database administrator';
    END IF;
END $guard$;
CREATE OR REPLACE FUNCTION public.pemeo_rebuild_prov_edges()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $body$
BEGIN
    -- Old transaction snapshots could rebuild from stale canonical data.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Projection rebuild requires READ COMMITTED';
    END IF;
    -- Serialize with canonical INSERT before locking/truncating its projection.
    LOCK TABLE public.ecom_records IN SHARE MODE;
    TRUNCATE TABLE public.ecom_prov_edges RESTART IDENTITY;
    INSERT INTO public.ecom_prov_edges (
        relation_record_id, predicate, subject_ref, object_ref, created_at
    )
    SELECT record_id, record_json#>>'{payload,predicate}',
           (record_json#>>'{payload,subjectRef}')::uuid,
           (record_json#>>'{payload,objectRef}')::uuid, created_at
    FROM public.ecom_records
    WHERE kind='relation' AND type='provenance_relation'
    ORDER BY created_at, record_id;
END $body$;
ALTER FUNCTION public.pemeo_rebuild_prov_edges() OWNER TO pemeo_core_f1_owner;
REVOKE ALL ON FUNCTION public.pemeo_rebuild_prov_edges() FROM PUBLIC,
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
GRANT EXECUTE ON FUNCTION public.pemeo_rebuild_prov_edges() TO pemeo_core_f1_rebuild;
COMMIT;
