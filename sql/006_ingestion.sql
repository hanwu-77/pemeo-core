-- I1: operational state only; frozen Protocol and SQL 001-005 are unchanged.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'pemeo_core_test' OR current_user<>'pemeo_core_test'
    OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
  RAISE EXCEPTION 'I1 requires the guarded synthetic database administrator';
 END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pemeo_core_i1_app') THEN
  CREATE ROLE pemeo_core_i1_app NOLOGIN;
 END IF;
 ALTER ROLE pemeo_core_i1_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;
 IF EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid IN (m.roleid,m.member)
            WHERE r.rolname='pemeo_core_i1_app') THEN
  RAISE EXCEPTION 'I1 app must have no role memberships';
 END IF;
END $guard$;
CREATE SCHEMA IF NOT EXISTS pemeo_ingest AUTHORIZATION pemeo_core_f1_owner;
SET LOCAL ROLE pemeo_core_f1_owner;
CREATE TABLE IF NOT EXISTS pemeo_ingest.spaces (id uuid PRIMARY KEY);
CREATE TABLE IF NOT EXISTS pemeo_ingest.principals (
 id uuid PRIMARY KEY, space_id uuid NOT NULL REFERENCES pemeo_ingest.spaces,
 kind text NOT NULL CHECK(kind IN ('human','service')),
 agent_id uuid NOT NULL UNIQUE REFERENCES public.ecom_records,
 active boolean NOT NULL DEFAULT true, auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.grants (
 principal_id uuid REFERENCES pemeo_ingest.principals, action text NOT NULL,
 PRIMARY KEY(principal_id,action)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.credentials (
 id uuid PRIMARY KEY, principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals,
 key_version bigint NOT NULL DEFAULT 1 CHECK(key_version>0), active boolean NOT NULL DEFAULT true,
 method text NOT NULL CHECK(method='test_adapter')
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.sessions (
 id uuid PRIMARY KEY, credential_id uuid NOT NULL REFERENCES pemeo_ingest.credentials,
 auth_epoch bigint NOT NULL, authenticated_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL, active boolean NOT NULL DEFAULT true,
 CHECK(expires_at>authenticated_at)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.record_scopes (
 record_id uuid PRIMARY KEY REFERENCES public.ecom_records,
 space_id uuid NOT NULL REFERENCES pemeo_ingest.spaces,
 principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.candidates (
 id uuid PRIMARY KEY, principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals,
 request_key text NOT NULL CHECK(length(request_key) BETWEEN 1 AND 128),
 request_digest text NOT NULL CHECK(length(request_digest)=64),
 content bytea NOT NULL CHECK(octet_length(content)<=1048576),
 digest text NOT NULL CHECK(length(digest)=64),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','committed','rejected','expired','superseded')),
 UNIQUE(principal_id,request_key), CHECK(expires_at>created_at)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.receipts (
 id uuid PRIMARY KEY, principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals,
 action text NOT NULL, request_key text NOT NULL CHECK(length(request_key) BETWEEN 1 AND 128),
 request_digest text NOT NULL CHECK(length(request_digest)=64),
 candidate_id uuid UNIQUE REFERENCES pemeo_ingest.candidates,
 evidence_class text NOT NULL CHECK(evidence_class='simulated'),
 verifier_version text NOT NULL, policy_version text NOT NULL, verified_at timestamptz,
 committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(principal_id,action,request_key)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.receipt_records (
 receipt_id uuid REFERENCES pemeo_ingest.receipts,
 record_id uuid NOT NULL UNIQUE REFERENCES public.ecom_records,
 ordinal integer NOT NULL CHECK(ordinal>=0), PRIMARY KEY(receipt_id,ordinal)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.challenges (
 id uuid PRIMARY KEY, candidate_id uuid NOT NULL UNIQUE REFERENCES pemeo_ingest.candidates,
 session_id uuid NOT NULL REFERENCES pemeo_ingest.sessions,
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 consumed_receipt uuid UNIQUE REFERENCES pemeo_ingest.receipts,
 CHECK(expires_at>created_at)
);

CREATE OR REPLACE FUNCTION pemeo_ingest.lock_principal(subject uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pemeo_ingest,pg_temp AS $$
BEGIN
 PERFORM 1 FROM pemeo_ingest.principals WHERE id=subject FOR UPDATE;
END $$;

CREATE OR REPLACE FUNCTION pemeo_ingest.guard_candidate() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Candidates are retained'; END IF;
 IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state') OR OLD.state<>'pending'
    OR NEW.state NOT IN ('committed','rejected','expired','superseded') THEN
  RAISE EXCEPTION 'Invalid candidate mutation';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION pemeo_ingest.guard_challenge() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Challenges are retained'; END IF;
 IF (to_jsonb(NEW)-'consumed_receipt') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_receipt')
    OR OLD.consumed_receipt IS NOT NULL OR NEW.consumed_receipt IS NULL THEN
  RAISE EXCEPTION 'Invalid challenge mutation';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS candidate_guard ON pemeo_ingest.candidates;
CREATE TRIGGER candidate_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.candidates
FOR EACH ROW EXECUTE FUNCTION pemeo_ingest.guard_candidate();
DROP TRIGGER IF EXISTS challenge_guard ON pemeo_ingest.challenges;
CREATE TRIGGER challenge_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.challenges
FOR EACH ROW EXECUTE FUNCTION pemeo_ingest.guard_challenge();
DROP TRIGGER IF EXISTS receipt_guard ON pemeo_ingest.receipts;
CREATE TRIGGER receipt_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.receipts
FOR EACH ROW EXECUTE FUNCTION public.ecom_block_record_mutation();
DROP TRIGGER IF EXISTS receipt_records_guard ON pemeo_ingest.receipt_records;
CREATE TRIGGER receipt_records_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.receipt_records
FOR EACH ROW EXECUTE FUNCTION public.ecom_block_record_mutation();
DROP TRIGGER IF EXISTS scope_guard ON pemeo_ingest.record_scopes;
CREATE TRIGGER scope_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.record_scopes
FOR EACH ROW EXECUTE FUNCTION public.ecom_block_record_mutation();
RESET ROLE;
REVOKE ALL ON DATABASE pemeo_core_test FROM pemeo_core_i1_app;
GRANT CONNECT ON DATABASE pemeo_core_test TO pemeo_core_i1_app;
REVOKE ALL ON SCHEMA public,pemeo_ingest FROM pemeo_core_i1_app;
REVOKE ALL ON SCHEMA pemeo_ingest FROM PUBLIC;
GRANT USAGE ON SCHEMA public,pemeo_ingest TO pemeo_core_i1_app;
REVOKE ALL ON ALL TABLES IN SCHEMA pemeo_ingest FROM PUBLIC,pemeo_core_i1_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pemeo_ingest FROM PUBLIC,pemeo_core_i1_app;
REVOKE ALL ON public.ecom_records,public.ecom_prov_edges FROM pemeo_core_i1_app;
GRANT SELECT,INSERT ON public.ecom_records TO pemeo_core_i1_app;
GRANT SELECT ON public.ecom_prov_edges TO pemeo_core_i1_app;
GRANT SELECT ON ALL TABLES IN SCHEMA pemeo_ingest TO pemeo_core_i1_app;
GRANT INSERT ON pemeo_ingest.candidates,pemeo_ingest.challenges,pemeo_ingest.receipts,
 pemeo_ingest.receipt_records,pemeo_ingest.record_scopes TO pemeo_core_i1_app;
GRANT UPDATE(state) ON pemeo_ingest.candidates TO pemeo_core_i1_app;
GRANT UPDATE(consumed_receipt) ON pemeo_ingest.challenges TO pemeo_core_i1_app;
GRANT EXECUTE ON FUNCTION pemeo_ingest.lock_principal(uuid) TO pemeo_core_i1_app;
COMMIT;
