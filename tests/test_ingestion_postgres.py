"""I1 real PostgreSQL transactions, with explicitly SIMULATED human identities."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import datetime,timedelta,timezone
import json
import os
import threading
import time
from uuid import uuid4

import pytest
from sqlalchemy import create_engine,text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from ecom_backend.ingestion import (ActionEvidence,AuthenticationContext,CommitOutcomeUnknown,
                                   IngestionError,IngestionService)
from ecom_backend.ingestion_json import canonical

pytestmark=pytest.mark.skipif(os.environ.get('PEMEO_RUN_I1')!='1',reason='Use guarded runner --ingestion')


@pytest.fixture
def db(service,example_dataset):
    import psycopg
    config=json.loads(os.environ['PEMEO_F1_CONNECTIONS'])
    assert config['host']=='127.0.0.1' and config['dbname']=='pemeo_core_test'
    passwords=config.pop('passwords')
    def connect(admin=False,**kwargs):
        user='pemeo_core_test' if admin else 'pemeo_core_i1_app'
        return psycopg.connect(**config,user=user,password=passwords[user],**kwargs)
    def engine_for(user):
        return create_engine(URL.create('postgresql+psycopg',username=user,password=passwords[user],
            host=config['host'],port=config['port'],database=config['dbname']),hide_parameters=True)
    engine=engine_for('pemeo_core_i1_app');admin_engine=engine_for('pemeo_core_test')
    with connect(True) as conn:
        conn.execute('TRUNCATE pemeo_ingest.spaces CASCADE')
        conn.execute('TRUNCATE public.ecom_prov_edges,public.ecom_records RESTART IDENTITY CASCADE')
    actors={};agents=[];space1,space2=uuid4(),uuid4()
    for name,kind,space in [('human','human',space1),('model','service',space1),('other','human',space2)]:
        record=deepcopy(example_dataset['records'][0 if kind=='human' else 1])
        record['recordId']=str(uuid4());agents.append(record)
        actors[name]={'id':str(uuid4()),'space':space,'agent':record['recordId'],
                      'credential':str(uuid4()),'session':str(uuid4()),'kind':kind}
    with Session(admin_engine) as session: service.append_batch(session,agents)
    with connect(True) as conn:
        for space in (space1,space2):conn.execute('INSERT INTO pemeo_ingest.spaces VALUES (%s)',(space,))
        for actor in actors.values():
            conn.execute('INSERT INTO pemeo_ingest.principals(id,space_id,kind,agent_id) VALUES (%s,%s,%s,%s)',
                         (actor['id'],actor['space'],actor['kind'],actor['agent']))
            conn.execute("INSERT INTO pemeo_ingest.credentials(id,principal_id,method) VALUES (%s,%s,'test_adapter')",(actor['credential'],actor['id']))
            conn.execute("INSERT INTO pemeo_ingest.sessions(id,credential_id,auth_epoch,authenticated_at,expires_at) VALUES (%s,%s,1,clock_timestamp(),clock_timestamp()+interval '1 hour')",(actor['session'],actor['credential']))
            conn.execute('INSERT INTO pemeo_ingest.record_scopes VALUES (%s,%s,%s)',(actor['agent'],actor['space'],actor['id']))
            actions=['receipt.read','statement.append','confirm.prepare','confirm.approve'] if actor['kind']=='human' else ['receipt.read','inference.append','relation.derive']
            for action in actions:conn.execute('INSERT INTO pemeo_ingest.grants VALUES (%s,%s)',(actor['id'],action))
            actor['context']=AuthenticationContext(actor['id'],actor['credential'],actor['session'])
    app=IngestionService(engine,service,allow_simulated=True)
    yield {'app':app,'engine':engine,'connect':connect,'actors':actors,'core':service,'example':example_dataset}
    engine.dispose();admin_engine.dispose()


def statement(db,actor='human'):
    r=deepcopy(next(r for r in db['example']['records'] if r['type']=='human_statement'))
    r['recordId']=str(uuid4());r['metadata']['source']['agentRef']=db['actors'][actor]['agent']
    r['metadata']['provenance']['evidenceRefs']=[];r['metadata']['provenance']['relationRefs']=[]
    r['payload']['content']='合成原话：今天先做一小步。'
    return r


def submit_statement(db,actor='human',key='statement'):
    r=statement(db,actor)
    receipt=db['app'].submit(db['actors'][actor]['context'],'statement.append',key,canonical([r]))
    return r,receipt


def candidate(db):
    r,_=submit_statement(db)
    return db['app'].prepare_confirmation(db['actors']['human']['context'],'prepare',r['recordId'],'我确认这是我的表达')


def proof(db,candidate):
    a=db['actors']['human']
    with db['connect']() as conn:now=conn.execute('SELECT clock_timestamp()').fetchone()[0]
    return ActionEvidence(a['id'],a['credential'],a['session'],1,candidate['candidate_id'],candidate['candidate_digest'],
                          candidate['challenge_id'],candidate['nonce'],now)


def counts(db):
    with db['connect']() as conn:
        return tuple(conn.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in
                     ['public.ecom_records','public.ecom_prov_edges','pemeo_ingest.receipts','pemeo_ingest.receipt_records','pemeo_ingest.record_scopes'])


def status(db,c):
    with db['connect']() as conn:
        return conn.execute('SELECT c.state,h.consumed_receipt FROM pemeo_ingest.candidates c JOIN pemeo_ingest.challenges h ON h.candidate_id=c.id WHERE c.id=%s',(c['candidate_id'],)).fetchone()


def approve(db,c,**kwargs):
    return db['app'].approve(db['actors']['human']['context'],kwargs.get('key','approve'),c['candidate_id'],
                             c['candidate_digest'],kwargs.get('evidence',proof(db,c)))


def test_default_service_rejects_simulated_context(db):
    app=IngestionService(db['engine'],db['core'])
    with pytest.raises(IngestionError,match='authentication_required'):
        app.submit(db['actors']['human']['context'],'statement.append','key',canonical([statement(db)]))


def test_full_statement_inference_confirmation_flow(db):
    s,receipt=submit_statement(db)
    a=db['actors']['model']
    r=deepcopy(next(r for r in db['example']['records'] if r['type']=='inferred_framing'))
    r['recordId']=str(uuid4());r['metadata']['source']['agentRef']=a['agent']
    r['metadata']['provenance']['evidenceRefs']=[s['recordId']];r['metadata']['provenance']['relationRefs']=[]
    relation={'recordId':str(uuid4()),'protocolVersion':'0.1','schemaVersion':'0.1.0','kind':'relation','type':'provenance_relation',
        'createdAt':r['createdAt'],'metadata':deepcopy(r['metadata']),
        'payload':{'subjectRef':r['recordId'],'subjectKind':'entity','predicate':'prov:wasDerivedFrom','objectRef':s['recordId'],'objectKind':'entity'}}
    db['app'].submit(a['context'],'inference.append','inference',canonical([r,relation]))
    c=db['app'].prepare_confirmation(db['actors']['human']['context'],'prepare',r['recordId'],'只确认这条描述',scope='本次测试')
    result=approve(db,c)
    assert result['evidence_class']=='simulated'
    assert status(db,c)[0]=='committed'
    assert db['app'].get_receipt(db['actors']['human']['context'],result['receipt_id'])==result
    with db['connect']() as conn:
        stored=conn.execute('SELECT record_json FROM public.ecom_records WHERE record_id=%s',(result['record_ids'][0],)).fetchone()[0]
        assert stored==c['records'][0]
        assert conn.execute('SELECT count(*) FROM public.ecom_prov_edges').fetchone()==(1,)
        assert conn.execute('SELECT session_user,current_user').fetchone()==('pemeo_core_i1_app',)*2


def test_request_idempotency_and_mismatched_retry(db):
    r,first=submit_statement(db)
    ctx=db['actors']['human']['context']
    assert db['app'].submit(ctx,'statement.append','statement',canonical([r]))==first
    r['payload']['content']='不同的原文'
    with pytest.raises(IngestionError,match='idempotency_conflict'):
        db['app'].submit(ctx,'statement.append','statement',canonical([r]))


def test_prepare_retry_uses_same_candidate_and_nonce(db):
    r,_=submit_statement(db);ctx=db['actors']['human']['context']
    a=db['app'].prepare_confirmation(ctx,'p',r['recordId'],'确认')
    b=db['app'].prepare_confirmation(ctx,'p',r['recordId'],'确认')
    assert a==b
    with pytest.raises(IngestionError,match='idempotency_conflict'):
        db['app'].prepare_confirmation(ctx,'p',r['recordId'],'另一段')


@pytest.mark.parametrize('field,value',[('principal_id',str(uuid4())),('credential_id',str(uuid4())),
    ('session_id',str(uuid4())),('auth_epoch',2),('key_version',2),('evidence_class','verified_assertion')])
def test_forged_or_stale_auth_context_rejected(db,field,value):
    ctx=replace(db['actors']['human']['context'],**{field:value})
    with pytest.raises(IngestionError,match='authentication_required'):
        db['app'].submit(ctx,'statement.append','x',canonical([statement(db)]))


def test_model_cannot_claim_human_even_if_grant_misconfigured(db):
    m=db['actors']['model']
    with db['connect'](True) as conn:conn.execute('INSERT INTO pemeo_ingest.grants VALUES (%s,%s)',(m['id'],'statement.append'))
    with pytest.raises(IngestionError,match='permission_denied'):
        db['app'].submit(m['context'],'statement.append','x',canonical([statement(db)]))


@pytest.mark.parametrize('agent',[None,'other'])
def test_client_source_agent_is_not_silently_rewritten(db,agent):
    r=statement(db)
    if agent is None:r['metadata']['source'].pop('agentRef')
    else:r['metadata']['source']['agentRef']=db['actors'][agent]['agent']
    with pytest.raises(IngestionError,match='source_identity_mismatch'):
        db['app'].submit(db['actors']['human']['context'],'statement.append','x',canonical([r]))


def test_cross_space_target_and_receipt_are_denied(db):
    r,rec=submit_statement(db,'other')
    ctx=db['actors']['human']['context']
    with pytest.raises(IngestionError,match='permission_denied'):db['app'].prepare_confirmation(ctx,'p',r['recordId'],'确认')
    with pytest.raises(IngestionError,match='permission_denied'):db['app'].get_receipt(ctx,rec['receipt_id'])


@pytest.mark.parametrize('field,value',[('user_present',False),('user_verified',False),('principal_id',str(uuid4())),
    ('candidate_digest','0'*64),('challenge_id',str(uuid4())),('nonce','incorrect'),('action','statement.append'),
    ('evidence_class','verified_assertion'),('key_version',2),('session_id',str(uuid4()))])
def test_action_evidence_must_bind_exact_candidate(db,field,value):
    c=candidate(db);e=replace(proof(db,c),**{field:value});before=counts(db)
    with pytest.raises(IngestionError):approve(db,c,evidence=e)
    assert counts(db)==before and status(db,c)==('pending',None)


def test_plain_login_is_not_confirmation(db):
    c=candidate(db)
    with pytest.raises(IngestionError,match='action_verification_required'):approve(db,c,evidence=None)


def test_content_digest_tamper_rejected(db):
    c=candidate(db);e=proof(db,c);c['candidate_digest']='0'*64
    with pytest.raises(IngestionError,match='candidate_content_mismatch'):approve(db,c,evidence=e)


def test_expired_challenge_rejected(db):
    c=candidate(db)
    # Wait-free expiry fixture: modify before the client operation as owner by
    # recreating the row through controlled TRUNCATE, not bypassing its trigger.
    with db['connect'](True) as conn:
        row=conn.execute('SELECT id,candidate_id,session_id,nonce FROM pemeo_ingest.challenges WHERE candidate_id=%s',(c['candidate_id'],)).fetchone()
        conn.execute('TRUNCATE pemeo_ingest.challenges')
        conn.execute("INSERT INTO pemeo_ingest.challenges(id,candidate_id,session_id,nonce,created_at,expires_at) VALUES (%s,%s,%s,%s,clock_timestamp()-interval '2 minute',clock_timestamp()-interval '1 minute')",row)
    with pytest.raises(IngestionError,match='challenge_unavailable'):approve(db,c)


def test_supersede_and_reject_never_create_confirmation(db):
    c=candidate(db);before=counts(db);ctx=db['actors']['human']['context']
    replacement=db['app'].prepare_confirmation(ctx,'replacement',c['records'][0]['payload']['targetRef'],'新内容',replaces_id=c['candidate_id'])
    assert status(db,c)==('superseded',None)
    with pytest.raises(IngestionError,match='candidate_not_pending'):approve(db,c)
    db['app'].reject(ctx,replacement['candidate_id'])
    assert counts(db)==before and status(db,replacement)==('rejected',None)


def test_committed_replay_does_not_reconsume_challenge(db):
    c=candidate(db);first=approve(db,c);before=counts(db)
    assert approve(db,c,evidence=None)==first
    assert counts(db)==before
    with pytest.raises(IngestionError,match='candidate_not_pending'):approve(db,c,key='another-key')


def test_revocation_blocks_even_receipt_replay(db):
    c=candidate(db);approve(db,c)
    with db['connect'](True) as conn:
        conn.execute('SELECT pemeo_ingest.lock_principal(%s)',(db['actors']['human']['id'],))
        conn.execute('UPDATE pemeo_ingest.principals SET auth_epoch=auth_epoch+1 WHERE id=%s',(db['actors']['human']['id'],))
    with pytest.raises(IngestionError,match='authentication_required'):approve(db,c,evidence=None)


@pytest.mark.parametrize('phase',['after_append','before_receipt','after_receipt','after_consumption','before_commit'])
def test_fault_at_each_write_boundary_rolls_back_all_state(db,phase):
    c=candidate(db);before=counts(db)
    def fault(current,session):
        if current==phase:session.execute(text('SELECT 1/0'))
    db['app']._fault=fault
    with pytest.raises(IngestionError,match='storage_operation_failed'):approve(db,c)
    assert counts(db)==before and status(db,c)==('pending',None)
    db['app']._fault=lambda *args:None
    approve(db,c)


def test_programming_bug_is_not_protocol_error(db):
    c=candidate(db);before=counts(db)
    def fault(phase,session):
        if phase=='after_append':raise TypeError('synthetic programming fault')
    db['app']._fault=fault
    with pytest.raises(TypeError):approve(db,c)
    assert counts(db)==before and status(db,c)==('pending',None)


def test_lost_response_after_real_commit_reuses_receipt(db):
    c=candidate(db);enabled=True
    def fault(phase,session):
        nonlocal enabled
        if phase=='after_commit' and enabled:
            enabled=False
            raise CommitOutcomeUnknown()
    db['app']._fault=fault
    with pytest.raises(CommitOutcomeUnknown):approve(db,c)
    before=counts(db);assert status(db,c)[0]=='committed'
    result=approve(db,c,evidence=None)
    assert counts(db)==before and result['receipt_id']==str(status(db,c)[1])


def test_real_connection_terminated_before_commit_can_retry_safely(db):
    c=candidate(db);before=counts(db);enabled=True
    def fault(phase,session):
        nonlocal enabled
        if phase=='before_commit' and enabled:
            enabled=False
            pid=session.execute(text('SELECT pg_backend_pid()')).scalar_one()
            with db['connect'](True,autocommit=True) as admin:
                assert admin.execute('SELECT pg_terminate_backend(%s)',(pid,)).fetchone()==(True,)
    db['app']._fault=fault
    with pytest.raises(CommitOutcomeUnknown):approve(db,c)
    assert counts(db)==before and status(db,c)==('pending',None)
    approve(db,c)


def test_two_concurrent_same_key_requests_commit_once(db):
    c=candidate(db);e=proof(db,c);barrier=threading.Barrier(2)
    def run():
        barrier.wait(timeout=5)
        return approve(db,c,evidence=e)
    with ThreadPoolExecutor(2) as pool:
        futures=[pool.submit(run) for _ in range(2)];results=[f.result(timeout=10) for f in futures]
    assert results[0]==results[1]


def test_concurrent_different_keys_cannot_consume_one_challenge_twice(db):
    c=candidate(db);e=proof(db,c);barrier=threading.Barrier(2)
    def run(key):
        barrier.wait(timeout=5)
        try:return approve(db,c,key=key,evidence=e)['receipt_id']
        except IngestionError as exc:return exc.code
    with ThreadPoolExecutor(2) as pool:
        fs=[pool.submit(run,k) for k in ('a','b')];results=[f.result(timeout=10) for f in fs]
    assert results.count('candidate_not_pending')==1


def test_approve_reject_race_has_one_terminal_winner(db):
    c=candidate(db);e=proof(db,c);barrier=threading.Barrier(2)
    def run(yes):
        barrier.wait(timeout=5)
        try:
            if yes:return approve(db,c,evidence=e)['receipt_id']
            return db['app'].reject(db['actors']['human']['context'],c['candidate_id'])['state']
        except IngestionError as exc:return exc.code
    with ThreadPoolExecutor(2) as pool:
        fs=[pool.submit(run,b) for b in (True,False)];results=[f.result(timeout=10) for f in fs]
    assert results.count('candidate_not_pending')==1
    assert status(db,c)[0] in {'committed','rejected'}


def test_revocation_lock_serializes_before_approval(db):
    c=candidate(db);e=proof(db,c);pid=db['actors']['human']['id'];started=threading.Event()
    def run():
        started.set()
        try:return approve(db,c,evidence=e)
        except IngestionError as exc:return exc.code
    with ThreadPoolExecutor(1) as pool:
        with db['connect'](True) as admin:
            admin.execute('SELECT pemeo_ingest.lock_principal(%s)',(pid,))
            f=pool.submit(run);assert started.wait(5)
            admin.execute('UPDATE pemeo_ingest.credentials SET active=false WHERE principal_id=%s',(pid,))
        assert f.result(timeout=10)=='authentication_required'
    assert status(db,c)==('pending',None)


@pytest.mark.parametrize('sql',[
    'UPDATE pemeo_ingest.principals SET auth_epoch=auth_epoch+1',
    'INSERT INTO pemeo_ingest.grants SELECT principal_id,action FROM pemeo_ingest.grants',
    'UPDATE pemeo_ingest.credentials SET active=false',
    'UPDATE pemeo_ingest.sessions SET active=false',
    "UPDATE pemeo_ingest.candidates SET digest=repeat('0',64)",
    'DELETE FROM pemeo_ingest.receipts',
    'TRUNCATE pemeo_ingest.receipts CASCADE',
    'UPDATE public.ecom_records SET type=type',
    'TRUNCATE public.ecom_records CASCADE',
    'SET ROLE pemeo_core_f1_owner',
    'SELECT public.pemeo_rebuild_prov_edges()',
])
def test_ingestion_role_cannot_change_identity_or_canonical_permissions(db,sql):
    import psycopg
    candidate(db)
    with db['connect']() as conn:
        try:
            with pytest.raises(psycopg.Error) as exc:conn.execute(sql)
            assert exc.value.sqlstate=='42501'
        finally:conn.rollback()


def test_candidate_and_challenge_terminal_state_triggers(db):
    import psycopg
    c=candidate(db);approve(db,c)
    for query in ["UPDATE pemeo_ingest.candidates SET state='pending'",'UPDATE pemeo_ingest.challenges SET consumed_receipt=NULL']:
        with db['connect']() as conn:
            try:
                with pytest.raises(psycopg.Error) as exc:conn.execute(query)
                assert exc.value.sqlstate=='P0001'
            finally:conn.rollback()


def test_caller_owned_append_neither_commits_nor_owns_rollback(db):
    r=statement(db);before=counts(db)
    with Session(db['engine']) as session:
        with pytest.raises(ValueError,match='caller-owned'):db['core'].append_in_transaction(session,[r])
        with session.begin():
            db['core'].append_in_transaction(session,[r])
            assert counts(db)==before
            session.rollback()
    assert counts(db)==before


def test_schema_and_business_failure_leave_no_partial_receipt(db):
    from ecom_backend.errors import EcomValidationError
    r=statement(db);bad=deepcopy(r)
    with pytest.raises(EcomValidationError):
        db['app'].submit(db['actors']['human']['context'],'statement.append','duplicate',canonical([r,bad]))
    assert counts(db)==(3,0,0,0,3)


@pytest.mark.parametrize('change', ['session_expired','session_revoked','grant_revoked','key_rotated','principal_revoked'])
def test_current_authorization_is_rechecked(db,change):
    c=candidate(db);actor=db['actors']['human'];before=counts(db)
    queries={
        'session_expired': "UPDATE pemeo_ingest.sessions SET authenticated_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=%s",
        'session_revoked': 'UPDATE pemeo_ingest.sessions SET active=false WHERE id=%s',
        'grant_revoked': "DELETE FROM pemeo_ingest.grants WHERE principal_id=%s AND action='confirm.approve'",
        'key_rotated': 'UPDATE pemeo_ingest.credentials SET key_version=key_version+1 WHERE principal_id=%s',
        'principal_revoked': 'UPDATE pemeo_ingest.principals SET active=false WHERE id=%s'}
    with db['connect'](True) as conn:
        conn.execute('SELECT pemeo_ingest.lock_principal(%s)',(actor['id'],))
        conn.execute(queries[change],(actor['session'] if change.startswith('session_') else actor['id'],))
    with pytest.raises(IngestionError):approve(db,c)
    assert counts(db)==before and status(db,c)==('pending',None)


@pytest.mark.parametrize('timestamp',[None,datetime(2000,1,1,tzinfo=timezone.utc),datetime(2100,1,1,tzinfo=timezone.utc),datetime(2000,1,1)])
def test_action_time_is_fresh_and_aware(db,timestamp):
    c=candidate(db)
    with pytest.raises(IngestionError,match='action_time_invalid'):
        approve(db,c,evidence=replace(proof(db,c),verified_at=timestamp))


def test_snapshot_isolation_is_rejected(db):
    app=IngestionService(db['engine'].execution_options(isolation_level='REPEATABLE READ'),db['core'],allow_simulated=True)
    with pytest.raises(IngestionError,match='read_committed_required'):
        app.submit(db['actors']['human']['context'],'statement.append','x',canonical([statement(db)]))


def inference_batch(db,source):
    a=db['actors']['model']
    r=deepcopy(next(r for r in db['example']['records'] if r['type']=='inferred_framing'))
    r['recordId']=str(uuid4());r['metadata']['source']['agentRef']=a['agent']
    r['metadata']['provenance']['evidenceRefs']=[source['recordId']];r['metadata']['provenance']['relationRefs']=[]
    rel={'recordId':str(uuid4()),'protocolVersion':'0.1','schemaVersion':'0.1.0','kind':'relation','type':'provenance_relation',
         'createdAt':r['createdAt'],'metadata':deepcopy(r['metadata']),
         'payload':{'subjectRef':r['recordId'],'subjectKind':'entity','predicate':'prov:wasDerivedFrom','objectRef':source['recordId'],'objectKind':'entity'}}
    return [r,rel]


def test_model_cross_space_evidence_is_denied(db):
    source,_=submit_statement(db,'other')
    with pytest.raises(IngestionError,match='permission_denied'):
        db['app'].submit(db['actors']['model']['context'],'inference.append','x',canonical(inference_batch(db,source)))


@pytest.mark.parametrize('mutation',['predicate','subject','grant'])
def test_relation_policy_does_not_grant_arbitrary_links(db,mutation):
    source,_=submit_statement(db);batch=inference_batch(db,source)
    if mutation=='predicate':
        batch[1]['payload']['predicate']='prov:wasGeneratedBy'
        batch[1]['payload']['objectKind']='activity'
    if mutation=='subject':batch[1]['payload']['subjectRef']=source['recordId']
    if mutation=='grant':
        with db['connect'](True) as conn:
            conn.execute("DELETE FROM pemeo_ingest.grants WHERE principal_id=%s AND action='relation.derive'",(db['actors']['model']['id'],))
    with pytest.raises(IngestionError,match='permission_denied'):
        db['app'].submit(db['actors']['model']['context'],'inference.append','x',canonical(batch))


def test_projection_failure_rolls_back_entire_batch(db):
    source,_=submit_statement(db);batch=inference_batch(db,source);before=counts(db)
    # Admin injects failure only on the disposable projection. Core SQL unchanged.
    with db['connect'](True) as conn:
        conn.execute("CREATE FUNCTION pemeo_ingest.test_projection_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'I1 synthetic projection failure'; END$$")
        conn.execute('CREATE TRIGGER i1_test_failure BEFORE INSERT ON public.ecom_prov_edges FOR EACH ROW EXECUTE FUNCTION pemeo_ingest.test_projection_failure()')
    try:
        with pytest.raises(IngestionError,match='storage_operation_failed'):
            db['app'].submit(db['actors']['model']['context'],'inference.append','x',canonical(batch))
        assert counts(db)==before
    finally:
        with db['connect'](True) as conn:
            conn.execute('DROP TRIGGER i1_test_failure ON public.ecom_prov_edges')
            conn.execute('DROP FUNCTION pemeo_ingest.test_projection_failure()')
    db['app'].submit(db['actors']['model']['context'],'inference.append','x',canonical(batch))



def test_expired_candidate_cannot_use_still_live_challenge(db):
    c=candidate(db);new_id=str(uuid4());challenge_id=str(uuid4())
    # Fixture creates a separate already expired immutable candidate. No clocks
    # are mocked and no existing row or canonical content is mutated.
    with db['connect'](True) as conn:
        conn.execute("INSERT INTO pemeo_ingest.candidates(id,principal_id,request_key,request_digest,content,digest,created_at,expires_at) SELECT %s,principal_id,'expired-fixture',request_digest,content,digest,clock_timestamp()-interval '11 minutes',clock_timestamp()-interval '1 minute' FROM pemeo_ingest.candidates WHERE id=%s",(new_id,c['candidate_id']))
        conn.execute("INSERT INTO pemeo_ingest.challenges(id,candidate_id,session_id,nonce,created_at,expires_at) SELECT %s,%s,session_id,nonce,created_at,expires_at FROM pemeo_ingest.challenges WHERE id=%s",(challenge_id,new_id,c['challenge_id']))
    c['candidate_id']=new_id;c['challenge_id']=challenge_id;before=counts(db)
    with pytest.raises(IngestionError,match='candidate_expired'):approve(db,c)
    assert counts(db)==before and status(db,c)==('pending',None)



def test_autocommit_engine_is_rejected_before_any_write(db):
    before=counts(db)
    app=IngestionService(db['engine'].execution_options(isolation_level='AUTOCOMMIT'),db['core'],allow_simulated=True)
    with pytest.raises(IngestionError,match='autocommit_not_allowed'):
        app.submit(db['actors']['human']['context'],'statement.append','x',canonical([statement(db)]))
    assert counts(db)==before
