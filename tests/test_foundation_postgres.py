"""Real login-role tests; no SET ROLE substitute for runtime authentication.

The admin fixture cleans only the runner-verified synthetic database. No direct
test URL default exists. Negative attempts are rolled back even if a guard fails.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('PEMEO_RUN_F1') != '1', reason='Use guarded runner --foundation')
ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'pemeo_core_f1_'


@pytest.fixture
def db(service, example_dataset):
    import psycopg
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL
    from sqlalchemy.orm import Session

    # Credentials are ephemeral process environment, not source, artifacts or argv.
    config = json.loads(os.environ['PEMEO_F1_CONNECTIONS'])
    assert config['dbname'] == 'pemeo_core_test'
    assert config['host'] == '127.0.0.1'
    passwords = config.pop('passwords')

    def connect(role, **kwargs):
        user = 'pemeo_core_test' if role == 'admin' else PREFIX + role
        return psycopg.connect(**config, user=user, password=passwords[user], **kwargs)

    with connect('admin') as conn:
        conn.execute('TRUNCATE public.ecom_prov_edges, public.ecom_records RESTART IDENTITY CASCADE')
    engine = create_engine(URL.create('postgresql+psycopg', username=PREFIX+'writer',
        password=passwords[PREFIX+'writer'], host=config['host'], port=config['port'], database=config['dbname']))
    with Session(engine) as session:
        service.append_batch(session, example_dataset['records'])

    def canonical_digest():
        with connect('reader') as conn:
            rows = conn.execute('SELECT record_id::text, record_json FROM public.ecom_records ORDER BY record_id').fetchall()
        return hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    yield connect, engine, canonical_digest
    engine.dispose()


def test_runtime_role_identity_ownership_and_privileges(db):
    connect, _, _ = db
    for role in ('writer', 'reader', 'rebuild'):
        with connect(role) as conn:
            identity = conn.execute('SELECT session_user, current_user').fetchone()
            assert identity == (PREFIX+role, PREFIX+role)
            flags = conn.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls '
                                 'FROM pg_roles WHERE rolname=current_user').fetchone()
            assert flags == (False,)*6
            memberships = conn.execute('SELECT count(*) FROM pg_auth_members m JOIN pg_roles r '
                'ON r.oid IN (m.member,m.roleid) WHERE r.rolname=current_user').fetchone()[0]
            assert memberships == 0
            assert not conn.execute("SELECT has_database_privilege(current_database(),'TEMP'), "
                                    "has_schema_privilege('public','CREATE')").fetchone()[0]
            assert conn.execute("SELECT has_schema_privilege('public','CREATE')").fetchone()[0] is False
    with connect('admin') as conn:
        assert conn.execute('SELECT rolcanlogin FROM pg_roles WHERE rolname=%s',(PREFIX+'owner',)).fetchone() == (False,)
        owners = conn.execute("SELECT r.rolname FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner "
                              "WHERE c.oid IN ('public.ecom_records'::regclass,'public.ecom_prov_edges'::regclass)").fetchall()
        assert owners == [(PREFIX+'owner',), (PREFIX+'owner',)]
        assert conn.execute('SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()').fetchone() == (PREFIX+'owner',)


def test_writer_append_projects_relations_and_reader_reads(db, example_dataset):
    connect, _, _ = db
    expected = {r['recordId']:r for r in example_dataset['records']}
    with connect('reader') as conn:
        actual = dict(conn.execute('SELECT record_id::text,record_json FROM public.ecom_records').fetchall())
        edges = conn.execute('SELECT count(*) FROM public.ecom_prov_edges').fetchone()[0]
    assert actual == expected
    assert edges == sum(r['kind']=='relation' for r in expected.values())


DENIED = [
    ('update', "UPDATE public.ecom_records SET type='tampered'"),
    ('delete', 'DELETE FROM public.ecom_records'),
    ('truncate', 'TRUNCATE public.ecom_records CASCADE'),
    ('alter', 'ALTER TABLE public.ecom_records ADD COLUMN tampered text'),
    ('drop', 'DROP TABLE public.ecom_records CASCADE'),
    ('disable_trigger', 'ALTER TABLE public.ecom_records DISABLE TRIGGER ALL'),
    ('replica_mode', "SET session_replication_role='replica'"),
    ('public_shadow', 'CREATE TABLE public.shadow_table (value int)'),
    ('temp_shadow', 'CREATE TEMP TABLE ecom_prov_edges (value int)'),
    ('owner_role', 'SET ROLE pemeo_core_f1_owner'),
    ('admin_role', 'SET ROLE pemeo_core_test'),
    ('create_role', 'CREATE ROLE pemeo_core_f1_unauthorized NOLOGIN'),
    ('alter_function', "ALTER FUNCTION public.ecom_project_relation_edge() SET search_path=pg_temp"),
    ('alter_rebuild_function', "ALTER FUNCTION public.pemeo_rebuild_prov_edges() SET search_path=pg_temp"),
    ('grant_self', 'GRANT pemeo_core_f1_owner TO pemeo_core_f1_writer'),
]


@pytest.mark.parametrize('role', ['writer', 'reader', 'rebuild'])
@pytest.mark.parametrize('label,statement', DENIED, ids=[x[0] for x in DENIED])
def test_runtime_roles_reject_canonical_mutation_and_escalation(db, role, label, statement):
    import psycopg
    connect, _, digest = db
    before = digest()
    with connect(role) as conn:
        try:
            with pytest.raises(psycopg.Error) as exc:
                conn.execute(statement)
            assert exc.value.sqlstate == '42501'
        finally:
            conn.rollback()
    assert digest() == before


@pytest.mark.parametrize('role,statement', [
    ('writer','INSERT INTO public.ecom_prov_edges (relation_record_id,predicate,subject_ref,object_ref,created_at) SELECT relation_record_id,predicate,subject_ref,object_ref,created_at FROM public.ecom_prov_edges'),
    ('writer','UPDATE public.ecom_prov_edges SET predicate=predicate'),
    ('writer','DELETE FROM public.ecom_prov_edges'),
    ('writer','TRUNCATE public.ecom_prov_edges RESTART IDENTITY'),
    ('reader','INSERT INTO public.ecom_records SELECT * FROM public.ecom_records'),
    ('reader','INSERT INTO public.ecom_prov_edges (relation_record_id,predicate,subject_ref,object_ref,created_at) SELECT relation_record_id,predicate,subject_ref,object_ref,created_at FROM public.ecom_prov_edges'),
    ('reader','UPDATE public.ecom_prov_edges SET predicate=predicate'),
    ('reader','DELETE FROM public.ecom_prov_edges'),
    ('reader','TRUNCATE public.ecom_prov_edges RESTART IDENTITY'),
    ('rebuild','INSERT INTO public.ecom_records SELECT * FROM public.ecom_records'),
    ('rebuild','INSERT INTO public.ecom_prov_edges (relation_record_id,predicate,subject_ref,object_ref,created_at) SELECT relation_record_id,predicate,subject_ref,object_ref,created_at FROM public.ecom_prov_edges'),
    ('rebuild','UPDATE public.ecom_prov_edges SET predicate=predicate'),
    ('rebuild','DELETE FROM public.ecom_prov_edges'),
    ('rebuild','TRUNCATE public.ecom_prov_edges'),
    ('writer','SELECT public.pemeo_rebuild_prov_edges()'),
    ('reader','SELECT public.pemeo_rebuild_prov_edges()'),
], ids=['writer-edge-insert','writer-edge-update','writer-edge-delete','writer-edge-truncate',
        'reader-record-insert','reader-edge-insert','reader-edge-update','reader-edge-delete',
        'reader-edge-truncate','rebuild-record-insert','rebuild-edge-insert','rebuild-edge-update',
        'rebuild-edge-delete','rebuild-edge-truncate','writer-rebuild-function','reader-rebuild-function'])
def test_direct_projection_or_unauthorized_record_writes_rejected(db, role, statement):
    import psycopg
    connect, _, digest = db
    before = digest()
    with connect(role) as conn:
        try:
            with pytest.raises(psycopg.Error) as exc:
                conn.execute(statement)
            assert exc.value.sqlstate == '42501'
        finally:
            conn.rollback()
    assert digest() == before


def test_projection_rebuild_is_repeatable_and_canonical_unchanged(db):
    connect, _, digest = db
    def edges():
        with connect('reader') as conn:
            return conn.execute('SELECT relation_record_id,predicate,subject_ref,object_ref,created_at '
                                'FROM public.ecom_prov_edges ORDER BY relation_record_id').fetchall()
    expected, before = edges(), digest()
    assert expected
    # Verify the unchanged historical SQL as admin, not as a runtime privilege claim.
    with connect('admin', autocommit=True) as conn:
        conn.execute((ROOT/'sql/002_projection_rebuild.sql').read_text())
    assert edges() == expected
    assert digest() == before
    with connect('admin') as conn:
        conn.execute('TRUNCATE public.ecom_prov_edges')
    assert edges() == []
    for _ in range(2):
        with connect('rebuild') as conn:
            conn.execute('SELECT public.pemeo_rebuild_prov_edges()')
        assert edges() == expected
        assert digest() == before


def test_security_definer_search_path_and_no_public_execute(db):
    connect, _, _ = db
    with connect('admin') as conn:
        row = conn.execute("SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc "
                           "WHERE oid='public.ecom_project_relation_edge()'::regprocedure").fetchone()
        assert row == (PREFIX+'owner', True, ['search_path=pg_catalog, public, pg_temp'])
        for role in ('writer','reader','rebuild'):
            assert conn.execute("SELECT has_function_privilege(%s,'public.ecom_project_relation_edge()','EXECUTE')",
                                (PREFIX+role,)).fetchone() == (False,)
        row = conn.execute("SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc "
                           "WHERE oid='public.pemeo_rebuild_prov_edges()'::regprocedure").fetchone()
        assert row == (PREFIX+'owner', True, ['search_path=pg_catalog, public, pg_temp'])


def test_rebuild_rolls_back_projection_with_its_transaction(db):
    connect, _, digest = db
    before = digest()
    with connect('admin') as conn:
        conn.execute('TRUNCATE public.ecom_prov_edges')
    with connect('rebuild') as conn:
        conn.execute('SELECT public.pemeo_rebuild_prov_edges()')
        assert conn.execute('SELECT count(*) FROM public.ecom_prov_edges').fetchone()[0] > 0
        conn.rollback()
    with connect('reader') as conn:
        assert conn.execute('SELECT count(*) FROM public.ecom_prov_edges').fetchone()[0] == 0
    assert digest() == before


def test_rebuild_waits_for_uncommitted_canonical_writer(db):
    import psycopg
    connect, _, digest = db
    before = digest()
    added = str(uuid4())
    with connect('writer') as writer:
        writer.execute("INSERT INTO public.ecom_records "
            "SELECT %s::uuid,jsonb_set(record_json,'{recordId}',to_jsonb(%s::text)),"
            "kind,type,source_kind,attestation,created_at,occurred_at "
            "FROM public.ecom_records WHERE kind='agent' LIMIT 1", (added, added))
        with connect('rebuild') as maintenance:
            try:
                maintenance.execute("SET LOCAL lock_timeout='300ms'")
                with pytest.raises(psycopg.Error) as exc:
                    maintenance.execute('SELECT public.pemeo_rebuild_prov_edges()')
                assert exc.value.sqlstate == '55P03'
            finally:
                maintenance.rollback()
        writer.rollback()
    assert digest() == before


@pytest.mark.parametrize('isolation', ['REPEATABLE READ', 'SERIALIZABLE'])
def test_rebuild_rejects_stale_snapshot_isolation(db, isolation):
    import psycopg
    connect, _, digest = db
    before = digest()
    with connect('rebuild') as conn:
        try:
            conn.execute('SET TRANSACTION ISOLATION LEVEL ' + isolation)
            with pytest.raises(psycopg.Error) as exc:
                conn.execute('SELECT public.pemeo_rebuild_prov_edges()')
            assert exc.value.sqlstate == 'P0001'
            assert 'READ COMMITTED' in str(exc.value)
        finally:
            conn.rollback()
    assert digest() == before


@pytest.mark.parametrize('operation', ['UPDATE public.ecom_records SET type=type', 'DELETE FROM public.ecom_records'], ids=['update','delete'])
def test_owner_dml_still_hits_append_only_trigger(db, operation):
    import psycopg
    connect, _, digest = db
    before = digest()
    with connect('admin') as conn:
        try:
            conn.execute('SET LOCAL ROLE pemeo_core_f1_owner')
            with pytest.raises(psycopg.Error) as exc:
                conn.execute(operation)
            assert exc.value.sqlstate == 'P0001'
            assert 'canonical records are append-only' in str(exc.value)
        finally:
            conn.rollback()
    assert digest() == before


def test_writer_database_failure_rolls_back_batch(db, service, example_dataset):
    from sqlalchemy.orm import Session
    from ecom_backend.errors import BusinessInvariantError
    _, engine, digest = db
    before = digest()
    existing = example_dataset['records'][0]
    added = deepcopy(existing); added['recordId'] = str(uuid4())
    with Session(engine) as session:
        with pytest.raises(BusinessInvariantError):
            service.append_batch(session, [added,existing])
    assert digest() == before


def test_protocol_jsonb_semantic_roundtrip_with_null_missing_unicode_and_provenance(db, service, example_dataset):
    from sqlalchemy.orm import Session
    connect, engine, _ = db
    records = []
    template = next(r for r in example_dataset['records'] if r['type']=='human_statement')
    for null_language in (True, False):
        record = deepcopy(template);record['recordId'] = str(uuid4())
        record['payload']['content'] = '吴：中文 / Deutsch ä ß / 👨‍👩‍👧 / e\u0301 / é\n逐字保留'
        record['metadata']['tags'] = ['z','a','中文']
        record['metadata']['provenance'].update(modelVersion=None, policyVersion='f1-test', promptVersion='synthetic')
        if null_language: record['payload']['language'] = None
        else: record['payload'].pop('language',None)
        records.append(record)
    with Session(engine) as session: service.append_batch(session,records)
    with connect('reader') as conn:
        for record in records:
            actual = conn.execute('SELECT record_json FROM public.ecom_records WHERE record_id=%s', (record['recordId'],)).fetchone()[0]
            assert actual == record
            assert ('language' in actual['payload']) == ('language' in record['payload'])
