-- I2 operational extension. SQL 001-006 remain historical and byte-frozen.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'pemeo_core_test' OR current_user<>'pemeo_core_test'
    OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
  RAISE EXCEPTION 'I2 requires an independently guarded PeMeO validation instance';
 END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pemeo_core_i2_app') THEN
  CREATE ROLE pemeo_core_i2_app NOLOGIN;
 END IF;
 ALTER ROLE pemeo_core_i2_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL;
 IF EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid IN(m.member,m.roleid)
   WHERE r.rolname='pemeo_core_i2_app') THEN RAISE EXCEPTION 'Unexpected I2 membership'; END IF;
END $$;
SET LOCAL ROLE pemeo_core_f1_owner;
ALTER TABLE pemeo_ingest.credentials DROP CONSTRAINT IF EXISTS credentials_method_check;
ALTER TABLE pemeo_ingest.credentials ADD CONSTRAINT credentials_method_check CHECK(method IN ('test_adapter','webauthn'));
ALTER TABLE pemeo_ingest.receipts DROP CONSTRAINT IF EXISTS receipts_evidence_class_check;
ALTER TABLE pemeo_ingest.receipts ADD CONSTRAINT receipts_evidence_class_check
 CHECK(evidence_class IN ('simulated','authenticated_session','verified_assertion'));
CREATE TABLE IF NOT EXISTS pemeo_ingest.installation (
 singleton integer PRIMARY KEY CHECK(singleton=1), realm uuid NOT NULL UNIQUE,
 principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals,
 bootstrap_hash bytea NOT NULL CHECK(octet_length(bootstrap_hash)=32),
 bootstrap_expires timestamptz NOT NULL, bootstrap_used boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.passkeys (
 credential_id uuid PRIMARY KEY REFERENCES pemeo_ingest.credentials,
 external_id bytea NOT NULL UNIQUE CHECK(octet_length(external_id) BETWEEN 1 AND 1024),
 public_key bytea NOT NULL CHECK(octet_length(public_key) BETWEEN 1 AND 4096),
 sign_count bigint NOT NULL CHECK(sign_count>=0),
 backup_eligible boolean NOT NULL, backed_up boolean NOT NULL,
 CHECK(NOT backed_up OR backup_eligible)
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.web_sessions (
 token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32),
 session_id uuid NOT NULL UNIQUE REFERENCES pemeo_ingest.sessions,
 csrf_hash bytea NOT NULL CHECK(octet_length(csrf_hash)=32),
 idle_expires timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.ceremonies (
 id uuid PRIMARY KEY, principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals,
 session_id uuid REFERENCES pemeo_ingest.sessions,
 action text NOT NULL CHECK(action IN ('register','login','add_authorize','add_register','revoke')),
 target_credential uuid REFERENCES pemeo_ingest.credentials,
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32),
 auth_epoch bigint NOT NULL, expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS pemeo_ingest.auth_receipts (
 id uuid PRIMARY KEY, principal_id uuid NOT NULL REFERENCES pemeo_ingest.principals,
 credential_id uuid NOT NULL REFERENCES pemeo_ingest.credentials,
 receipt_id uuid UNIQUE REFERENCES pemeo_ingest.receipts,
 action text NOT NULL, challenge_id uuid NOT NULL UNIQUE,
 candidate_digest text CHECK(candidate_digest IS NULL OR length(candidate_digest)=64),
 auth_epoch bigint NOT NULL, key_version bigint NOT NULL,
 method text NOT NULL CHECK(method='webauthn'),
 user_present boolean NOT NULL CHECK(user_present), user_verified boolean NOT NULL CHECK(user_verified),
 verified_at timestamptz NOT NULL, origin text NOT NULL, rp_id text NOT NULL,
 verifier_version text NOT NULL, policy_version text NOT NULL
);
CREATE OR REPLACE FUNCTION pemeo_ingest.guard_ceremony() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Ceremonies retained'; END IF;
 IF (to_jsonb(NEW)-'consumed') IS DISTINCT FROM (to_jsonb(OLD)-'consumed')
    OR OLD.consumed OR NOT NEW.consumed THEN RAISE EXCEPTION 'Invalid ceremony mutation'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS ceremony_guard ON pemeo_ingest.ceremonies;
CREATE TRIGGER ceremony_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.ceremonies
 FOR EACH ROW EXECUTE FUNCTION pemeo_ingest.guard_ceremony();
DROP TRIGGER IF EXISTS auth_receipt_guard ON pemeo_ingest.auth_receipts;
CREATE TRIGGER auth_receipt_guard BEFORE UPDATE OR DELETE ON pemeo_ingest.auth_receipts
 FOR EACH ROW EXECUTE FUNCTION public.ecom_block_record_mutation();
RESET ROLE;
REVOKE ALL ON DATABASE pemeo_core_test FROM pemeo_core_i2_app;
GRANT CONNECT ON DATABASE pemeo_core_test TO pemeo_core_i2_app;
REVOKE ALL ON SCHEMA public,pemeo_ingest FROM pemeo_core_i2_app;
GRANT USAGE ON SCHEMA public,pemeo_ingest TO pemeo_core_i2_app;
REVOKE ALL ON ALL TABLES IN SCHEMA pemeo_ingest FROM PUBLIC,pemeo_core_i2_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pemeo_ingest FROM PUBLIC,pemeo_core_i2_app;
GRANT SELECT ON ALL TABLES IN SCHEMA pemeo_ingest TO pemeo_core_i2_app;
GRANT SELECT,INSERT ON public.ecom_records TO pemeo_core_i2_app;
GRANT SELECT ON public.ecom_prov_edges TO pemeo_core_i2_app;
GRANT EXECUTE ON FUNCTION pemeo_ingest.lock_principal(uuid) TO pemeo_core_i2_app;
GRANT INSERT ON pemeo_ingest.credentials,pemeo_ingest.sessions,pemeo_ingest.passkeys,
 pemeo_ingest.web_sessions,pemeo_ingest.ceremonies,pemeo_ingest.auth_receipts,
 pemeo_ingest.candidates,pemeo_ingest.challenges,pemeo_ingest.receipts,
 pemeo_ingest.receipt_records,pemeo_ingest.record_scopes TO pemeo_core_i2_app;
GRANT UPDATE(auth_epoch) ON pemeo_ingest.principals TO pemeo_core_i2_app;
GRANT UPDATE(active) ON pemeo_ingest.credentials,pemeo_ingest.sessions TO pemeo_core_i2_app;
GRANT UPDATE(sign_count,backed_up) ON pemeo_ingest.passkeys TO pemeo_core_i2_app;
GRANT UPDATE(idle_expires) ON pemeo_ingest.web_sessions TO pemeo_core_i2_app;
GRANT UPDATE(bootstrap_used) ON pemeo_ingest.installation TO pemeo_core_i2_app;
GRANT UPDATE(consumed) ON pemeo_ingest.ceremonies TO pemeo_core_i2_app;
GRANT UPDATE(state) ON pemeo_ingest.candidates TO pemeo_core_i2_app;
GRANT UPDATE(consumed_receipt) ON pemeo_ingest.challenges TO pemeo_core_i2_app;
COMMIT;
