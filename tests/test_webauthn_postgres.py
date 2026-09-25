"""Real database and signatures; software authenticator, no human claim."""
from dataclasses import replace
from copy import deepcopy
from uuid import uuid4
import json,os,secrets
import pytest
from sqlalchemy import create_engine,text
from sqlalchemy.engine import URL
from test_ingestion_postgres import db,statement
from webauthn_fixtures import SoftwareAuthenticator
from ecom_backend.ingestion import IngestionError,AuthenticationContext,ActionEvidence
from ecom_backend.ingestion_json import canonical
from ecom_backend.webauthn_service import WebAuthnService,BrowserSession,secret_hash,csrf_for

pytestmark=pytest.mark.skipif(os.environ.get('PEMEO_RUN_I2')!='1',reason='Use guarded runner --webauthn')


@pytest.fixture
def real(db):
    config=json.loads(os.environ['PEMEO_F1_CONNECTIONS']);passwords=config.pop('passwords')
    engine=create_engine(URL.create('postgresql+psycopg',username='pemeo_core_i2_app',password=passwords['pemeo_core_i2_app'],host=config['host'],port=config['port'],database=config['dbname']),hide_parameters=True)
    realm=str(uuid4());bootstrap=secrets.token_hex(32);a=db['actors']['human']
    with db['connect'](True) as conn:
        conn.execute("INSERT INTO pemeo_ingest.installation VALUES (1,%s,%s,%s,clock_timestamp()+interval '10 minutes',false)",(realm,a['id'],secret_hash(bootstrap)))
        conn.execute("INSERT INTO pemeo_ingest.grants VALUES (%s,'credential.manage')",(a['id'],))
    app=WebAuthnService(engine,db['core'],origin='https://localhost:8443',realm=realm)
    db.update(real=app,real_engine=engine,bootstrap=bootstrap,realm=realm,authenticator=SoftwareAuthenticator())
    yield db
    engine.dispose()


def register(real,auth=None):
    a=auth or real['authenticator'];app=real['real'];start=app.begin_registration(real['bootstrap'])
    return app.finish_registration(real['bootstrap'],start['ceremony_id'],a.response(start['options'],register=True))


def login(real,auth=None):
    a=auth or real['authenticator'];app=real['real'];start=app.begin_login()
    result=app.finish_login(start['ceremony_id'],a.response(start['options']))
    return BrowserSession(result['token'],result['csrf'])


def prepared(real,ctx):
    app=real['real'];r=statement(real)
    app.submit(ctx,'statement.append',str(uuid4()),canonical([r]))
    return app.prepare_confirmation(ctx,str(uuid4()),r['recordId'],'我确认这段合成表达')


def approve(real,ctx,c,key='approve',auth=None):
    app=real['real'];options=app.confirmation_options(ctx,c['candidate_id'])
    raw=(auth or real['authenticator']).response(options)
    return app.approve(ctx,key,c['candidate_id'],c['candidate_digest'],raw)


def totals(real):
    with real['connect'](True) as c:
        return tuple(c.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in
                     ['ecom_records','ecom_prov_edges','pemeo_ingest.receipts','pemeo_ingest.auth_receipts'])


def test_registration_login_confirmation_are_real_signatures_but_software_authenticator(real):
    register(real);ctx=login(real);c=prepared(real,ctx);result=approve(real,ctx,c)
    assert result['evidence_class']=='verified_assertion'
    with real['connect'](True) as conn:
        record=conn.execute('SELECT record_json FROM ecom_records WHERE record_id=%s',(result['record_ids'][0],)).fetchone()[0]
        assert record==c['records'][0] and record['metadata']['verification']=='unverified'
        proof=conn.execute('SELECT method,user_present,user_verified,candidate_digest FROM pemeo_ingest.auth_receipts WHERE receipt_id=%s',(result['receipt_id'],)).fetchone()
        assert proof==('webauthn',True,True,c['candidate_digest'])
    assert real['real'].approve(ctx,'approve',c['candidate_id'],c['candidate_digest'],None)==result


def test_bootstrap_is_not_a_human_session_and_is_one_use(real):
    with pytest.raises(IngestionError):real['real'].account(BrowserSession(real['bootstrap'],csrf_for(real['bootstrap'])))
    with pytest.raises(IngestionError):real['real'].begin_registration('0'*64)
    register(real)
    with pytest.raises(IngestionError,match='registration_unavailable'):real['real'].begin_registration(real['bootstrap'])


def test_real_service_rejects_i1_simulated_context(real):
    with pytest.raises(IngestionError,match='authentication_required'):real['real'].account(real['actors']['human']['context'])


def test_missing_uv_does_not_create_credential(real):
    start=real['real'].begin_registration(real['bootstrap']);a=real['authenticator']
    with pytest.raises(IngestionError):real['real'].finish_registration(real['bootstrap'],start['ceremony_id'],a.response(start['options'],register=True,uv=False))
    with real['connect'](True) as c:
        assert c.execute('SELECT count(*) FROM pemeo_ingest.passkeys').fetchone()==(0,)
        assert c.execute('SELECT bootstrap_used FROM pemeo_ingest.installation').fetchone()==(False,)


@pytest.mark.parametrize('problem',['token','csrf','expired','revoked','realm'])
def test_sessions_are_server_side_and_current(real,problem):
    register(real);ctx=login(real)
    if problem=='token':ctx=replace(ctx,token='0'*64)
    if problem=='csrf':ctx=replace(ctx,csrf='0'*64)
    if problem=='realm':real['real'].realm=str(uuid4())
    if problem in {'expired','revoked'}:
        with real['connect'](True) as c:
            if problem=='expired':c.execute("UPDATE pemeo_ingest.web_sessions SET idle_expires=clock_timestamp()-interval '1 minute'")
            else:c.execute("UPDATE pemeo_ingest.credentials SET active=false WHERE method='webauthn'")
    with pytest.raises(IngestionError):real['real'].account(ctx)


def test_ordinary_session_and_forged_uv_are_not_confirmation(real):
    register(real);ctx=login(real);c=prepared(real,ctx);before=totals(real)
    for evidence in (None,{'user_verified':True},b'{"user_verified":true}'):
        with pytest.raises(IngestionError):real['real'].approve(ctx,'bad',c['candidate_id'],c['candidate_digest'],evidence)
    assert totals(real)==before


def test_candidate_signature_cannot_be_swapped_to_another_candidate(real):
    register(real);ctx=login(real);one=prepared(real,ctx);two=prepared(real,ctx)
    raw=real['authenticator'].response(real['real'].confirmation_options(ctx,one['candidate_id']))
    with pytest.raises(IngestionError):real['real'].approve(ctx,'x',two['candidate_id'],two['candidate_digest'],raw)


def test_auth_receipt_failure_rolls_back_confirmation_and_challenge(real):
    register(real);ctx=login(real);c=prepared(real,ctx);before=totals(real)
    with real['connect'](True) as conn:
        conn.execute("CREATE FUNCTION pemeo_ingest.fail_auth_receipt() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'I2 auth receipt fault'; END$$")
        conn.execute('CREATE TRIGGER fail_i2 BEFORE INSERT ON pemeo_ingest.auth_receipts FOR EACH ROW EXECUTE FUNCTION pemeo_ingest.fail_auth_receipt()')
    try:
        with pytest.raises(IngestionError,match='storage_operation_failed'):approve(real,ctx,c)
        assert totals(real)==before
        with real['connect'](True) as conn:assert conn.execute('SELECT consumed_receipt FROM pemeo_ingest.challenges WHERE id=%s',(c['challenge_id'],)).fetchone()==(None,)
    finally:
        with real['connect'](True) as conn:
            conn.execute('DROP TRIGGER fail_i2 ON pemeo_ingest.auth_receipts');conn.execute('DROP FUNCTION pemeo_ingest.fail_auth_receipt()')
    approve(real,ctx,c)


def test_add_requires_existing_credential_fresh_action_and_invalidates_sessions(real):
    register(real);ctx=login(real);app=real['real'];other=SoftwareAuthenticator(backup=True)
    with pytest.raises(IngestionError):app.finish_add(ctx,str(uuid4()),b'{}')
    first=app.begin_management(ctx,'add_authorize')
    second=app.finish_management(ctx,'add_authorize',first['ceremony_id'],real['authenticator'].response(first['options']))
    app.finish_add(ctx,second['ceremony_id'],other.response(second['options'],register=True))
    with pytest.raises(IngestionError):app.account(ctx)
    new_ctx=login(real,other)
    assert len(app.account(new_ctx)['credentials'])==2


def test_revoking_last_credential_freezes_human_write_no_recovery(real):
    register(real);ctx=login(real);app=real['real'];account=app.account(ctx)
    start=app.begin_management(ctx,'revoke',account['credentials'][0]['id'])
    app.finish_management(ctx,'revoke',start['ceremony_id'],real['authenticator'].response(start['options']))
    with pytest.raises(IngestionError):app.account(ctx)
    with pytest.raises(IngestionError,match='no_active_credential_no_recovery'):app.begin_login()
    with pytest.raises(IngestionError):app.begin_registration(real['bootstrap'])


def test_login_challenge_is_single_use(real):
    register(real);app=real['real'];start=app.begin_login();raw=real['authenticator'].response(start['options'])
    app.finish_login(start['ceremony_id'],raw)
    with pytest.raises(IngestionError,match='ceremony_unavailable'):app.finish_login(start['ceremony_id'],raw)


@pytest.mark.parametrize('sql',["UPDATE ecom_records SET type=type",'TRUNCATE pemeo_ingest.auth_receipts',
    'DELETE FROM pemeo_ingest.auth_receipts','UPDATE pemeo_ingest.passkeys SET public_key=public_key',
    "INSERT INTO pemeo_ingest.grants SELECT * FROM pemeo_ingest.grants",'SET ROLE pemeo_core_f1_owner'])
def test_i2_role_cannot_edit_history_or_grant_ownership(real,sql):
    from sqlalchemy.exc import DBAPIError
    with real['real_engine'].connect() as c:
        with pytest.raises(DBAPIError) as e:c.execute(text(sql))
        assert e.value.orig.sqlstate=='42501'
        c.rollback()


def test_browser_statement_retry_and_confirmation_replay(real):
    register(real);ctx=login(real);app=real['real']
    one=app.create_statement(ctx,'browser','合成页面测试文本')
    assert app.create_statement(ctx,'browser','合成页面测试文本')==one
    with pytest.raises(IngestionError,match='idempotency_conflict'):app.create_statement(ctx,'browser','改过的文字')
    c=app.prepare_confirmation(ctx,'browser:confirm',one['record_ids'][0],'确认这份合成表达')
    assert app.replay_confirmation(ctx,'yes',c['candidate_id'],c['candidate_digest'])=={'committed':False}
    result=approve(real,ctx,c,key='yes')
    assert app.replay_confirmation(ctx,'yes',c['candidate_id'],c['candidate_digest'])=={**result,'committed':True}


def test_rejected_candidate_cannot_gain_authentication_receipt(real):
    register(real);ctx=login(real);c=prepared(real,ctx);before=totals(real)
    real['real'].reject(ctx,c['candidate_id'])
    with pytest.raises(IngestionError):approve(real,ctx,c)
    assert totals(real)==before



def test_concurrent_registration_consumes_bootstrap_once(real):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    app=real['real'];start=app.begin_registration(real['bootstrap'])
    raw=real['authenticator'].response(start['options'],register=True);gate=Barrier(2)
    def run():
        gate.wait(timeout=5)
        try:return app.finish_registration(real['bootstrap'],start['ceremony_id'],raw)['registered']
        except IngestionError as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:run(),range(2)))
    assert results.count(True)==1 and results.count('registration_unavailable')==1
    with real['connect'](True) as c:
        assert c.execute('SELECT count(*) FROM pemeo_ingest.passkeys').fetchone()==(1,)
        assert c.execute("SELECT count(*) FROM pemeo_ingest.auth_receipts WHERE action='register'").fetchone()==(1,)


def test_concurrent_same_key_confirmation_returns_one_receipt(real):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    register(real);ctx=login(real);candidate=prepared(real,ctx);app=real['real']
    raw=real['authenticator'].response(app.confirmation_options(ctx,candidate['candidate_id']))
    gate=Barrier(2);before=totals(real)
    def run():
        gate.wait(timeout=5)
        return app.approve(ctx,'concurrent-same',candidate['candidate_id'],candidate['candidate_digest'],raw)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:run(),range(2)))
    assert results[0]==results[1]
    after=totals(real)
    assert after[2]==before[2]+1 and after[3]==before[3]+1


@pytest.mark.parametrize('management',['revoke','add'])
def test_confirmation_racing_credential_change_respects_serial_order(real,management):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    current=SoftwareAuthenticator(backup=True);register(real,current);ctx=login(real,current);app=real['real']
    candidate=prepared(real,ctx)
    approval=current.response(app.confirmation_options(ctx,candidate['candidate_id']))
    if management=='revoke':
        target=app.account(ctx)['credentials'][0]['id']
        start=app.begin_management(ctx,'revoke',target);proof=current.response(start['options'])
        change=lambda:app.finish_management(ctx,'revoke',start['ceremony_id'],proof)
    else:
        start=app.begin_management(ctx,'add_authorize')
        second=app.finish_management(ctx,'add_authorize',start['ceremony_id'],current.response(start['options']))
        proof=SoftwareAuthenticator().response(second['options'],register=True)
        change=lambda:app.finish_add(ctx,second['ceremony_id'],proof)
    gate=Barrier(2)
    def confirm():
        gate.wait(timeout=5)
        try:return app.approve(ctx,'racing',candidate['candidate_id'],candidate['candidate_digest'],approval)
        except IngestionError as exc:
            assert exc.code=='authentication_required'
            return None
    def manage():gate.wait(timeout=5);return change()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f=pool.submit(confirm);g=pool.submit(manage);result=f.result();g.result()
    with pytest.raises(IngestionError):app.account(ctx)
    with real['connect'](True) as c:
        expected=1 if result else 0
        assert c.execute("SELECT count(*) FROM pemeo_ingest.receipts WHERE action='confirm.approve'").fetchone()==(expected,)
        assert c.execute("SELECT count(*) FROM pemeo_ingest.auth_receipts WHERE action='confirm.approve'").fetchone()==(expected,)
        consumed=c.execute('SELECT consumed_receipt FROM pemeo_ingest.challenges WHERE candidate_id=%s',(candidate['candidate_id'],)).fetchone()[0]
        assert (consumed is not None)==bool(result)
