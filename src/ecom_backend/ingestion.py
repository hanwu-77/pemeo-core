"""I1 internal ingestion service. Authentication is SIMULATED only.

No HTTP endpoint, real authenticator, arbitrary SQL, or machine-to-human upgrade.
The app DB credential and in-process caller are part of the trusted boundary.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
import secrets
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .ingestion_json import InputRejected, canonical, digest, parse, records as parse_records
from .store import SqlAlchemyRecordLookup

POLICY_VERSION = 'i1-policy-v1'
VERIFIER_VERSION = 'i1-simulated-adapter-v1'


class IngestionError(Exception):
    """Stable code only; never echo private input or database errors."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class CommitOutcomeUnknown(IngestionError):
    def __init__(self):
        super().__init__('commit_outcome_unknown_retry_same_key')


@dataclass(frozen=True)
class AuthenticationContext:
    principal_id: str
    credential_id: str
    session_id: str
    auth_epoch: int = 1
    key_version: int = 1
    evidence_class: str = 'simulated'


@dataclass(frozen=True)
class ActionEvidence:
    principal_id: str
    credential_id: str
    session_id: str
    key_version: int
    candidate_id: str
    candidate_digest: str
    challenge_id: str
    nonce: str
    verified_at: datetime
    user_present: bool = True
    user_verified: bool = True
    action: str = 'confirm.approve'
    evidence_class: str = 'simulated'
    verifier_version: str = VERIFIER_VERSION


def _uuid(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise InputRejected('Invalid identifier') from exc


def _key(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise InputRejected('Invalid request key')
    return value


def _refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in {'externalRef','optionRef'} and key.endswith('Ref'):
                if child is not None:
                    yield _uuid(child)
            elif key.endswith('Refs'):
                for ref in child:
                    yield _uuid(ref)
            else:
                yield from _refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _refs(child)


class IngestionService:
    def __init__(self, engine, record_service, *, allow_simulated=False, fault_injector=None):
        if fault_injector is not None and not allow_simulated:
            raise ValueError('Fault injection is test-only')
        self.engine = engine
        self.core = record_service
        self.allow_simulated = allow_simulated
        self._fault = fault_injector or (lambda phase, session: None)

    def _run(self, operation):
        commit_started = False
        try:
            with Session(self.engine) as session:
                with session.begin():
                    if session.connection().connection.driver_connection.autocommit:
                        raise IngestionError('autocommit_not_allowed')
                    if session.execute(text('SHOW transaction_isolation')).scalar_one() != 'read committed':
                        raise IngestionError('read_committed_required')
                    session.execute(text("SET LOCAL lock_timeout='5s'"))
                    session.execute(text("SET LOCAL statement_timeout='15s'"))
                    result = operation(session)
                    self._fault('before_commit', session)
                    commit_started = True
                self._fault('after_commit', session)
            return result
        except SQLAlchemyError as exc:
            if commit_started:
                raise CommitOutcomeUnknown() from exc
            raise IngestionError('storage_operation_failed') from exc

    @staticmethod
    def _now(session):
        return session.execute(text('SELECT clock_timestamp()')).scalar_one()

    def _authenticate(self, session, context, action):
        if not self.allow_simulated or not isinstance(context, AuthenticationContext) or context.evidence_class != 'simulated':
            raise IngestionError('authentication_required')
        pid, cid, sid = map(_uuid, (context.principal_id, context.credential_id, context.session_id))
        # SELECT FOR UPDATE requires UPDATE privilege: use a narrow definer lock,
        # NOT UPDATE grants on identities. All trusted revocation paths lock here.
        session.execute(text('SELECT pemeo_ingest.lock_principal(:id)'), {'id':pid})
        row = session.execute(text('''SELECT p.id,p.space_id,p.kind,p.agent_id,p.auth_epoch,
            c.key_version,s.authenticated_at,s.expires_at
            FROM pemeo_ingest.principals p
            JOIN pemeo_ingest.credentials c ON c.principal_id=p.id
            JOIN pemeo_ingest.sessions s ON s.credential_id=c.id
            WHERE p.id=:p AND c.id=:c AND s.id=:s AND p.active AND c.active AND s.active
              AND c.method='test_adapter' AND s.auth_epoch=p.auth_epoch
              AND s.authenticated_at<=clock_timestamp() AND s.expires_at>clock_timestamp()'''),
            {'p':pid,'c':cid,'s':sid}).mappings().one_or_none()
        if row is None or row['auth_epoch'] != context.auth_epoch or row['key_version'] != context.key_version:
            raise IngestionError('authentication_required')
        actor = dict(row)
        actor['credential_id'], actor['session_id'] = cid, sid
        self._grant(session, actor, action)
        return actor

    @staticmethod
    def _grant(session, actor, action):
        permitted = session.execute(text('SELECT 1 FROM pemeo_ingest.grants WHERE principal_id=:p AND action=:a'),
                                    {'p':actor['id'],'a':action}).first()
        if permitted is None:
            raise IngestionError('permission_denied')

    @staticmethod
    def _owned_record(session, actor, rid):
        row = session.execute(text('''SELECT r.record_json,m.principal_id FROM public.ecom_records r
            JOIN pemeo_ingest.record_scopes m ON m.record_id=r.record_id
            WHERE r.record_id=:id AND m.space_id=:space'''),
            {'id':rid,'space':actor['space_id']}).mappings().one_or_none()
        if row is None:
            raise IngestionError('permission_denied')
        return row

    def _authorize_records(self, session, actor, action, records):
        validated = self.core.schema_validator.validate_records(records)
        batch = {_uuid(r['recordId']): r for r in validated}
        human = action in {'statement.append','confirm.approve'}
        if actor['kind'] != ('human' if human else 'service'):
            raise IngestionError('permission_denied')
        for record in validated:
            source = record['metadata']['source']
            if source.get('kind') != ('human' if human else 'ecom') or source.get('agentRef') is None or _uuid(source['agentRef']) != str(actor['agent_id']):
                raise IngestionError('source_identity_mismatch')
            allowed = {'human_statement'} if action=='statement.append' else {'human_confirmation'} if action=='confirm.approve' else {'inferred_framing','provenance_relation'}
            if record['type'] not in allowed:
                raise IngestionError('permission_denied')
            for rid in _refs(record):
                if rid not in batch:
                    self._owned_record(session, actor, rid)
            if record['type']=='provenance_relation':
                self._grant(session, actor, 'relation.derive')
                payload = record['payload']
                if payload['predicate'] != 'prov:wasDerivedFrom':
                    raise IngestionError('permission_denied')
                subject_id, object_id = _uuid(payload['subjectRef']), _uuid(payload['objectRef'])
                if subject_id in batch:
                    subject, owner = batch[subject_id], actor['id']
                else:
                    found=self._owned_record(session,actor,subject_id)
                    subject,owner=found['record_json'],found['principal_id']
                obj=batch.get(object_id)
                if obj is None:
                    obj=self._owned_record(session,actor,object_id)['record_json']
                if subject['type']!='inferred_framing' or owner!=actor['id'] or obj['type']!='human_statement':
                    raise IngestionError('permission_denied')
        return validated

    @staticmethod
    def _receipt(session, row):
        ids=session.execute(text('SELECT record_id FROM pemeo_ingest.receipt_records WHERE receipt_id=:id ORDER BY ordinal'),
                            {'id':row['id']}).scalars().all()
        return {'receipt_id':str(row['id']), 'record_ids':[str(x) for x in ids],
                'action':row['action'], 'committed_at':row['committed_at'].isoformat(),
                'evidence_class':row['evidence_class'], 'policy_version':row['policy_version'],
                'verified_at':row['verified_at'].isoformat() if row['verified_at'] else None}

    def _replay(self, session, actor, action, key, request_digest):
        row=session.execute(text('SELECT * FROM pemeo_ingest.receipts WHERE principal_id=:p AND action=:a AND request_key=:k'),
                            {'p':actor['id'],'a':action,'k':key}).mappings().one_or_none()
        if row is None:
            return None
        self._grant(session,actor,'receipt.read')
        if not hmac.compare_digest(row['request_digest'],request_digest):
            raise IngestionError('idempotency_conflict')
        return self._receipt(session,row)

    def _receipt_values(self, actor, action):
        return {'evidence_class': 'simulated', 'verifier': VERIFIER_VERSION, 'policy': POLICY_VERSION}

    def _save(self, session, actor, action, key, request_digest, records, candidate_id=None, verified_at=None):
        ids=self.core.append_in_transaction(session,records)
        self._fault('after_append',session)
        for rid in ids:
            session.execute(text('INSERT INTO pemeo_ingest.record_scopes(record_id,space_id,principal_id) VALUES (:r,:s,:p)'),
                            {'r':rid,'s':actor['space_id'],'p':actor['id']})
        self._fault('before_receipt',session)
        receipt_id=uuid4()
        values=self._receipt_values(actor,action)
        row=session.execute(text('''INSERT INTO pemeo_ingest.receipts
            (id,principal_id,action,request_key,request_digest,candidate_id,evidence_class,verifier_version,policy_version,verified_at)
            VALUES (:id,:p,:a,:k,:d,:c,:evidence,:v,:policy,:verified) RETURNING *'''),
            {'id':receipt_id,'p':actor['id'],'a':action,'k':key,'d':request_digest,'c':candidate_id,
             'evidence':values['evidence_class'],'v':values['verifier'],'policy':values['policy'],'verified':verified_at}).mappings().one()
        for i,rid in enumerate(ids):
            session.execute(text('INSERT INTO pemeo_ingest.receipt_records(receipt_id,record_id,ordinal) VALUES (:x,:r,:i)'),
                            {'x':receipt_id,'r':rid,'i':i})
        self._fault('after_receipt',session)
        return self._receipt(session,row)

    def submit(self, context, action, request_key, raw_records: bytes):
        if action not in {'statement.append','inference.append'}:
            raise IngestionError('permission_denied')
        key=_key(request_key)
        records=parse_records(raw_records)
        def operation(session):
            actor=self._authenticate(session,context,action)
            rd=digest('request',{'action':action,'space_id':str(actor['space_id']),'records':records})
            replay=self._replay(session,actor,action,key,rd)
            if replay is not None:
                return replay
            checked=self._authorize_records(session,actor,action,records)
            return self._save(session,actor,action,key,rd,checked)
        return self._run(operation)

    def _candidate(self, session, actor, candidate_id):
        row=session.execute(text('SELECT * FROM pemeo_ingest.candidates WHERE id=:id AND principal_id=:p FOR UPDATE'),
                            {'id':_uuid(candidate_id),'p':actor['id']}).mappings().one_or_none()
        if row is None:
            raise IngestionError('permission_denied')
        return row

    def _pending(self, session, candidate):
        if candidate['state']!='pending':
            raise IngestionError('candidate_not_pending')
        if candidate['expires_at']<=self._now(session):
            raise IngestionError('candidate_expired')

    @staticmethod
    def _candidate_view(session,candidate):
        challenge=session.execute(text('SELECT * FROM pemeo_ingest.challenges WHERE candidate_id=:id'),
                                  {'id':candidate['id']}).mappings().one()
        body=parse(bytes(candidate['content']))
        return {'candidate_id':str(candidate['id']),'candidate_digest':candidate['digest'],
                'records':body['records'],'state':candidate['state'],
                'challenge_id':str(challenge['id']),
                'nonce':base64.urlsafe_b64encode(bytes(challenge['nonce'])).decode().rstrip('='),
                'challenge_expires_at':challenge['expires_at'].isoformat()}

    def prepare_confirmation(self,context,request_key,target_ref,confirmation_text,scope=None,*,replaces_id=None):
        key=_key(request_key);target=_uuid(target_ref)
        if not isinstance(confirmation_text,str) or not confirmation_text or (scope is not None and not isinstance(scope,str)):
            raise InputRejected('Invalid confirmation text or scope')
        replaces=_uuid(replaces_id) if replaces_id is not None else None
        payload={'targetRef':target,'confirmationText':confirmation_text,'scope':scope}
        canonical(payload)
        def operation(session):
            actor=self._authenticate(session,context,'confirm.prepare')
            if actor['kind']!='human':
                raise IngestionError('permission_denied')
            self._grant(session,actor,'confirm.approve')
            rd=digest('prepare',{'space_id':str(actor['space_id']),'payload':payload,'replaces_id':replaces})
            existing=session.execute(text('SELECT * FROM pemeo_ingest.candidates WHERE principal_id=:p AND request_key=:k'),
                                     {'p':actor['id'],'k':key}).mappings().one_or_none()
            if existing is not None:
                if existing['request_digest']!=rd:
                    raise IngestionError('idempotency_conflict')
                return self._candidate_view(session,existing)
            old=None
            if replaces is not None:
                old=self._candidate(session,actor,replaces);self._pending(session,old)
            self._owned_record(session,actor,target)
            now=self._now(session)
            record={'recordId':str(uuid4()),'protocolVersion':'0.1','schemaVersion':'0.1.0',
                'kind':'entity','type':'human_confirmation','createdAt':now.isoformat(),
                'metadata':{'source':{'kind':'human','agentRef':str(actor['agent_id'])},
                    'attestation':'direct','verification':'unverified',
                    'provenance':{'protocolSourceVersion':'0.1','evidenceRefs':[target],'relationRefs':[]}},
                'payload':payload}
            checked=self._authorize_records(session,actor,'confirm.approve',[record])
            self.core.validate_records(checked,SqlAlchemyRecordLookup(session))
            body={'action':'confirm.approve','space_id':str(actor['space_id']),'records':checked}
            content=canonical(body);cd=digest('candidate',body);candidate_id=uuid4()
            candidate=session.execute(text('''INSERT INTO pemeo_ingest.candidates
                (id,principal_id,request_key,request_digest,content,digest,created_at,expires_at)
                VALUES (:id,:p,:k,:rd,:content,:d,:now,:expires) RETURNING *'''),
                {'id':candidate_id,'p':actor['id'],'k':key,'rd':rd,'content':content,'d':cd,
                 'now':now,'expires':now+timedelta(minutes=10)}).mappings().one()
            session.execute(text('''INSERT INTO pemeo_ingest.challenges(id,candidate_id,session_id,nonce,created_at,expires_at)
                VALUES (:id,:c,:s,:nonce,:now,:expires)'''),
                {'id':uuid4(),'c':candidate_id,'s':actor['session_id'],'nonce':secrets.token_bytes(32),
                 'now':now,'expires':now+timedelta(minutes=5)})
            if old is not None:
                session.execute(text("UPDATE pemeo_ingest.candidates SET state='superseded' WHERE id=:id"),{'id':old['id']})
            return self._candidate_view(session,candidate)
        return self._run(operation)

    def _verify_action(self,session,actor,candidate,challenge,evidence):
        cid=str(candidate['id']);candidate_digest=candidate['digest'];now=self._now(session)
        expected_nonce=base64.urlsafe_b64encode(bytes(challenge['nonce'])).decode().rstrip('=')
        if not isinstance(evidence,ActionEvidence) or evidence.evidence_class!='simulated' or evidence.verifier_version!=VERIFIER_VERSION:
            raise IngestionError('action_verification_required')
        actual=(evidence.principal_id,evidence.credential_id,evidence.session_id,evidence.key_version,
                evidence.candidate_id,evidence.candidate_digest,evidence.challenge_id,evidence.action)
        expected=(str(actor['id']),actor['credential_id'],actor['session_id'],actor['key_version'],
                  cid,candidate_digest,str(challenge['id']),'confirm.approve')
        if actual!=expected or str(challenge['session_id'])!=actor['session_id'] or not isinstance(evidence.nonce,str) or not hmac.compare_digest(evidence.nonce,expected_nonce):
            raise IngestionError('action_binding_mismatch')
        if evidence.user_present is not True or evidence.user_verified is not True:
            raise IngestionError('user_verification_required')
        if not isinstance(evidence.verified_at,datetime) or evidence.verified_at.tzinfo is None or not challenge['created_at']<=evidence.verified_at<=now:
            raise IngestionError('action_time_invalid')
        return evidence.verified_at

    def approve(self,context,request_key,candidate_id,candidate_digest,evidence: ActionEvidence | None):
        key=_key(request_key);cid=_uuid(candidate_id)
        if not isinstance(candidate_digest,str) or len(candidate_digest)!=64:
            raise InputRejected('Invalid candidate digest')
        def operation(session):
            actor=self._authenticate(session,context,'confirm.approve')
            if actor['kind']!='human':
                raise IngestionError('permission_denied')
            rd=digest('request',{'action':'confirm.approve','space_id':str(actor['space_id']),
                                'candidate_id':cid,'candidate_digest':candidate_digest})
            replay=self._replay(session,actor,'confirm.approve',key,rd)
            if replay is not None:
                return replay
            candidate=self._candidate(session,actor,cid);self._pending(session,candidate)
            body=parse(bytes(candidate['content']))
            if not hmac.compare_digest(candidate['digest'],candidate_digest) or digest('candidate',body)!=candidate_digest:
                raise IngestionError('candidate_content_mismatch')
            challenge=session.execute(text('SELECT * FROM pemeo_ingest.challenges WHERE candidate_id=:id FOR UPDATE'),
                                      {'id':cid}).mappings().one()
            now=self._now(session)
            if challenge['consumed_receipt'] is not None or challenge['expires_at']<=now:
                raise IngestionError('challenge_unavailable')
            verified_at=self._verify_action(session,actor,candidate,challenge,evidence)
            checked=self._authorize_records(session,actor,'confirm.approve',body['records'])
            result=self._save(session,actor,'confirm.approve',key,rd,checked,cid,verified_at)
            changed=session.execute(text('UPDATE pemeo_ingest.challenges SET consumed_receipt=:r WHERE id=:id AND expires_at>clock_timestamp()'),
                            {'r':result['receipt_id'],'id':challenge['id']}).rowcount
            if changed!=1 or candidate['expires_at']<=self._now(session):
                raise IngestionError('challenge_unavailable')
            session.execute(text("UPDATE pemeo_ingest.candidates SET state='committed' WHERE id=:id"),{'id':cid})
            self._fault('after_consumption',session)
            return result
        return self._run(operation)

    def reject(self,context,candidate_id):
        def operation(session):
            actor=self._authenticate(session,context,'confirm.prepare')
            if actor['kind']!='human':
                raise IngestionError('permission_denied')
            candidate=self._candidate(session,actor,candidate_id);self._pending(session,candidate)
            session.execute(text("UPDATE pemeo_ingest.candidates SET state='rejected' WHERE id=:id"),{'id':candidate['id']})
            return {'candidate_id':str(candidate['id']),'state':'rejected'}
        return self._run(operation)

    def get_receipt(self,context,receipt_id):
        def operation(session):
            actor=self._authenticate(session,context,'receipt.read')
            row=session.execute(text('SELECT * FROM pemeo_ingest.receipts WHERE id=:id AND principal_id=:p'),
                                {'id':_uuid(receipt_id),'p':actor['id']}).mappings().one_or_none()
            if row is None:
                raise IngestionError('permission_denied')
            return self._receipt(session,row)
        return self._run(operation)
