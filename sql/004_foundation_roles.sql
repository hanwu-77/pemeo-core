-- F1 synthetic-test deployment only. Run through scripts/test_postgres.py.
-- No passwords in this file. Runtime login is temporary and managed by runner.
BEGIN;
DO $guard$
BEGIN
    IF current_database() <> 'pemeo_core_test' OR current_user <> 'pemeo_core_test'
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'F1 requires the guarded PeMeO synthetic database administrator';
    END IF;
END $guard$;

DO $roles$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['pemeo_core_f1_owner', 'pemeo_core_f1_writer',
                                    'pemeo_core_f1_reader', 'pemeo_core_f1_rebuild'] LOOP
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', role_name);
        END IF;
        EXECUTE format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL', role_name);
    END LOOP;
    IF EXISTS (
        SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid IN (m.roleid, m.member)
        WHERE r.rolname IN ('pemeo_core_f1_owner', 'pemeo_core_f1_writer',
                           'pemeo_core_f1_reader', 'pemeo_core_f1_rebuild')
    ) THEN
        RAISE EXCEPTION 'F1 roles must have no memberships in either direction';
    END IF;
END $roles$;

ALTER DATABASE pemeo_core_test OWNER TO pemeo_core_f1_owner;
REVOKE ALL ON DATABASE pemeo_core_test FROM PUBLIC,
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
GRANT CONNECT ON DATABASE pemeo_core_test TO
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
ALTER SCHEMA public OWNER TO pemeo_core_f1_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC,
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
GRANT USAGE ON SCHEMA public TO
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;

ALTER TABLE public.ecom_records OWNER TO pemeo_core_f1_owner;
ALTER TABLE public.ecom_prov_edges OWNER TO pemeo_core_f1_owner;
ALTER FUNCTION public.ecom_block_record_mutation() OWNER TO pemeo_core_f1_owner;
ALTER FUNCTION public.ecom_project_relation_edge() OWNER TO pemeo_core_f1_owner;
-- The frozen body is unchanged. Explicitly put pg_temp last to avoid shadowing.
ALTER FUNCTION public.ecom_project_relation_edge() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION public.ecom_block_record_mutation(), public.ecom_project_relation_edge()
    FROM PUBLIC, pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
REVOKE ALL ON TABLE public.ecom_records, public.ecom_prov_edges FROM PUBLIC,
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
REVOKE ALL ON SEQUENCE public.ecom_prov_edges_edge_id_seq FROM PUBLIC,
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;

GRANT SELECT ON public.ecom_records, public.ecom_prov_edges TO
    pemeo_core_f1_writer, pemeo_core_f1_reader, pemeo_core_f1_rebuild;
GRANT INSERT ON public.ecom_records TO pemeo_core_f1_writer;
-- Rebuild role receives only EXECUTE on a static function in 005; no direct DML.
COMMIT;
