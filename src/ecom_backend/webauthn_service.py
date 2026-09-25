"""I2 trusted service. Raw assertions are verified, never persisted or logged."""
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import hmac
import secrets
from uuid import UUID, uuid4
from sqlalchemy import text
from .ingestion import IngestionService,IngestionError,_uuid
from .webauthn_adapter import WebAuthnVerifier,Credential,VERSION,decode
from .ingestion_json import parse

POLICY='i2-webauthn-policy-v2'
CSRF_PROFILE=b'pemeo-csrf-v2'


def secret_hash(value):
    if not isinstance(value,str) or len(value)!=64:
        raise IngestionError('authentication_required')
    try:bytes.fromhex(value)
    except ValueError:raise IngestionError('authentication_required') from None
    return hashlib.sha256(value.encode()).digest()


def csrf_for(token):
    secret_hash(token)
    return hmac.new(bytes.fromhex(token),CSRF_PROFILE,hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class BrowserSession:
    token: str
    csrf: str


class WebAuthnService(IngestionService):
    def __init__(self,engine,record_service,*,origin,realm):
        super().__init__(engine,record_service)
        self.verifier=WebAuthnVerifier(origin)
        self.realm=_uuid(realm)

    def _installation(self,session):
        row=session.execute(text('SELECT * FROM pemeo_ingest.installation WHERE singleton=1 AND realm=:r'),{'r':self.realm}).mappings().one_or_none()
        if row is None:raise IngestionError('installation_unavailable')
        return row

    def _principal(self,session):
        install=self._installation(session)
        session.execute(text('SELECT pemeo_ingest.lock_principal(:p)'),{'p':install['principal_id']})
        actor=session.execute(text('SELECT * FROM pemeo_ingest.principals WHERE id=:p AND active AND kind=\'human\''),{'p':install['principal_id']}).mappings().one_or_none()
        if actor is None:raise IngestionError('authentication_required')
        return dict(actor)

    def _authenticate(self,session,context,action):
        if not isinstance(context,BrowserSession):raise IngestionError('authentication_required')
        # Require the current derivation even if a legacy row still exists.
        # Old sessions fail closed and must log in again; historical rows stay.
        if not isinstance(context.csrf,str) or not hmac.compare_digest(context.csrf,csrf_for(context.token)):
            raise IngestionError('authentication_required')
        actor=self._principal(session)
        row=session.execute(text('''SELECT s.id,s.credential_id,c.key_version FROM pemeo_ingest.web_sessions w
          JOIN pemeo_ingest.sessions s ON s.id=w.session_id
          JOIN pemeo_ingest.credentials c ON c.id=s.credential_id
          JOIN pemeo_ingest.passkeys k ON k.credential_id=c.id
          WHERE w.token_hash=:t AND w.csrf_hash=:csrf AND w.idle_expires>clock_timestamp()
          AND s.active AND c.active AND c.method='webauthn' AND c.principal_id=:p
          AND s.auth_epoch=:epoch AND s.authenticated_at<=clock_timestamp() AND s.expires_at>clock_timestamp()'''),
          {'t':secret_hash(context.token),'csrf':secret_hash(context.csrf),'p':actor['id'],'epoch':actor['auth_epoch']}).mappings().one_or_none()
        if row is None:raise IngestionError('authentication_required')
        actor.update(session_id=str(row['id']),credential_id=str(row['credential_id']),key_version=row['key_version'])
        self._grant(session,actor,action)
        session.execute(text("UPDATE pemeo_ingest.web_sessions SET idle_expires=clock_timestamp()+interval '15 minutes' WHERE token_hash=:t"),{'t':secret_hash(context.token)})
        return actor

    def _key(self,session,actor,cid):
        row=session.execute(text('''SELECT k.*,c.key_version FROM pemeo_ingest.passkeys k JOIN pemeo_ingest.credentials c ON c.id=k.credential_id
           WHERE c.id=:c AND c.principal_id=:p AND c.active AND c.method='webauthn' '''),{'c':cid,'p':actor['id']}).mappings().one_or_none()
        if row is None:raise IngestionError('authentication_required')
        return row

    def _verify(self,session,actor,cid,raw,nonce):
        key=self._key(session,actor,cid)
        credential=Credential(bytes(key['external_id']),bytes(key['public_key']),key['sign_count'],key['backup_eligible'],key['backed_up'])
        verified=self.verifier.authenticate(raw,bytes(nonce),credential,UUID(str(actor['id'])).bytes)
        session.execute(text('UPDATE pemeo_ingest.passkeys SET sign_count=:n,backed_up=:bs WHERE credential_id=:c'),
                        {'n':verified.sign_count,'bs':verified.backed_up,'c':cid})
        return self._now(session)

    def _verify_action(self,session,actor,candidate,challenge,evidence):
        if str(challenge['session_id'])!=actor['session_id']:raise IngestionError('action_binding_mismatch')
        when=self._verify(session,actor,actor['credential_id'],evidence,challenge['nonce'])
        actor['_verified_challenge']=str(challenge['id'])
        actor['_candidate_digest']=candidate['digest']
        return when

    def _receipt_values(self,actor,action):
        if action=='confirm.approve' and '_verified_challenge' not in actor:
            raise IngestionError('action_verification_required')
        return {'evidence_class':'verified_assertion' if action=='confirm.approve' else 'authenticated_session',
                'verifier':VERSION,'policy':POLICY}

    def _auth_receipt(self,session,actor,action,challenge,when,receipt=None,digest=None,cid=None):
        cid=cid or actor['credential_id'];key=self._key(session,actor,cid)
        session.execute(text('''INSERT INTO pemeo_ingest.auth_receipts
          (id,principal_id,credential_id,receipt_id,action,challenge_id,candidate_digest,auth_epoch,key_version,
           method,user_present,user_verified,verified_at,origin,rp_id,verifier_version,policy_version)
          VALUES (:id,:p,:c,:r,:a,:h,:d,:e,:v,'webauthn',true,true,:time,:origin,'localhost',:verifier,:policy)'''),
          {'id':uuid4(),'p':actor['id'],'c':cid,'r':receipt,'a':action,'h':challenge,'d':digest,'e':actor['auth_epoch'],
           'v':key['key_version'],'time':when,'origin':self.verifier.origin,'verifier':VERSION,'policy':POLICY})

    def _save(self,session,actor,action,key,request_digest,records,candidate_id=None,verified_at=None):
        result=super()._save(session,actor,action,key,request_digest,records,candidate_id,verified_at)
        if action=='confirm.approve':
            self._auth_receipt(session,actor,action,actor['_verified_challenge'],verified_at,result['receipt_id'],actor['_candidate_digest'])
        return result

    def _new_ceremony(self,session,actor,action,*,sid=None,target=None):
        pending=session.execute(text('SELECT count(*) FROM pemeo_ingest.ceremonies WHERE principal_id=:p AND NOT consumed AND expires_at>clock_timestamp()'),{'p':actor['id']}).scalar_one()
        if pending>=12:raise IngestionError('too_many_pending_ceremonies')
        return session.execute(text('''INSERT INTO pemeo_ingest.ceremonies(id,principal_id,session_id,action,target_credential,nonce,auth_epoch,expires_at)
          VALUES (:id,:p,:s,:a,:t,:n,:e,clock_timestamp()+interval '5 minutes') RETURNING *'''),
          {'id':uuid4(),'p':actor['id'],'s':sid,'a':action,'t':target,'n':secrets.token_bytes(32),'e':actor['auth_epoch']}).mappings().one()

    def _ceremony(self,session,actor,identifier,action,sid=None):
        c=session.execute(text('SELECT * FROM pemeo_ingest.ceremonies WHERE id=:id AND principal_id=:p FOR UPDATE'),{'id':_uuid(identifier),'p':actor['id']}).mappings().one_or_none()
        if c is None or c['action']!=action or c['consumed'] or c['auth_epoch']!=actor['auth_epoch'] or c['expires_at']<=self._now(session) or (str(c['session_id']) if c['session_id'] else None)!=sid:
            raise IngestionError('ceremony_unavailable')
        return c

    def _consume(self,session,c):
        n=session.execute(text('UPDATE pemeo_ingest.ceremonies SET consumed=true WHERE id=:id AND NOT consumed AND expires_at>clock_timestamp()'),{'id':c['id']}).rowcount
        if n!=1:raise IngestionError('ceremony_unavailable')

    def _registration_options(self,session,actor,c):
        keys=session.execute(text('SELECT k.external_id FROM pemeo_ingest.passkeys k JOIN pemeo_ingest.credentials c ON c.id=k.credential_id WHERE c.principal_id=:p'),{'p':actor['id']}).scalars().all()
        return {'ceremony_id':str(c['id']),'options':self.verifier.registration_options(bytes(c['nonce']),UUID(str(actor['id'])).bytes,[bytes(k) for k in keys])}

    def _bootstrap(self,session,token):
        i=self._installation(session)
        if i['bootstrap_used'] or i['bootstrap_expires']<=self._now(session) or not hmac.compare_digest(bytes(i['bootstrap_hash']),secret_hash(token)):
            raise IngestionError('registration_unavailable')

    def begin_registration(self,bootstrap):
        def op(s):
            actor=self._principal(s);self._bootstrap(s,bootstrap)
            return self._registration_options(s,actor,self._new_ceremony(s,actor,'register'))
        return self._run(op)

    def _insert_key(self,s,actor,credential):
        cid=uuid4()
        s.execute(text("INSERT INTO pemeo_ingest.credentials(id,principal_id,method) VALUES (:c,:p,'webauthn')"),{'c':cid,'p':actor['id']})
        s.execute(text('INSERT INTO pemeo_ingest.passkeys VALUES (:c,:id,:key,:n,:be,:bs)'),{'c':cid,'id':credential.external_id,'key':credential.public_key,'n':credential.sign_count,'be':credential.backup_eligible,'bs':credential.backed_up})
        return str(cid)

    def finish_registration(self,bootstrap,identifier,raw):
        def op(s):
            actor=self._principal(s);self._bootstrap(s,bootstrap);c=self._ceremony(s,actor,identifier,'register')
            key=self.verifier.register(raw,bytes(c['nonce']));cid=self._insert_key(s,actor,key)
            self._consume(s,c)
            s.execute(text('UPDATE pemeo_ingest.installation SET bootstrap_used=true WHERE singleton=1'))
            self._auth_receipt(s,actor,'register',c['id'],self._now(s),cid=cid)
            return {'registered':True,'authentication':'webauthn','content_verified':False}
        return self._run(op)

    def begin_login(self):
        def op(s):
            actor=self._principal(s)
            ids=s.execute(text("SELECT k.external_id FROM pemeo_ingest.passkeys k JOIN pemeo_ingest.credentials c ON c.id=k.credential_id WHERE c.principal_id=:p AND c.active AND c.method='webauthn'"),{'p':actor['id']}).scalars().all()
            if not ids:raise IngestionError('no_active_credential_no_recovery')
            c=self._new_ceremony(s,actor,'login')
            return {'ceremony_id':str(c['id']),'options':self.verifier.authentication_options(bytes(c['nonce']),[bytes(i) for i in ids])}
        return self._run(op)

    def finish_login(self,identifier,raw):
        def op(s):
            actor=self._principal(s);c=self._ceremony(s,actor,identifier,'login')
            try:external=decode(parse(raw)['rawId'])
            except (ValueError, KeyError, TypeError):raise IngestionError('authentication_required') from None
            cid=s.execute(text('SELECT credential_id FROM pemeo_ingest.passkeys WHERE external_id=:id'),{'id':external}).scalar_one_or_none()
            if cid is None:raise IngestionError('authentication_required')
            when=self._verify(s,actor,str(cid),raw,c['nonce']);self._consume(s,c)
            token=secrets.token_hex(32);csrf=csrf_for(token);sid=uuid4()
            s.execute(text("INSERT INTO pemeo_ingest.sessions(id,credential_id,auth_epoch,authenticated_at,expires_at) VALUES (:s,:c,:e,:t,:expires)"),{'s':sid,'c':cid,'e':actor['auth_epoch'],'t':when,'expires':when+timedelta(hours=8)})
            s.execute(text("INSERT INTO pemeo_ingest.web_sessions VALUES (:t,:s,:c,clock_timestamp()+interval '15 minutes')"),{'t':secret_hash(token),'s':sid,'c':secret_hash(csrf)})
            self._auth_receipt(s,actor,'login',c['id'],when,cid=cid)
            return {'token':token,'csrf':csrf}
        return self._run(op)

    def account(self,context):
        def op(s):
            a=self._authenticate(s,context,'receipt.read')
            rows=s.execute(text('SELECT c.id,k.backup_eligible,k.backed_up FROM pemeo_ingest.credentials c JOIN pemeo_ingest.passkeys k ON k.credential_id=c.id WHERE c.principal_id=:p AND c.active'),{'p':a['id']}).mappings().all()
            return {'authenticated':True,'csrf':context.csrf,'credentials':[{'id':str(k['id']),'current':str(k['id'])==a['credential_id'],'backup_eligible':k['backup_eligible'],'backed_up':k['backed_up']} for k in rows]}
        return self._run(op)

    def confirmation_options(self,context,candidate_id):
        def op(s):
            a=self._authenticate(s,context,'confirm.approve');c=self._candidate(s,a,candidate_id);self._pending(s,c)
            h=s.execute(text('SELECT * FROM pemeo_ingest.challenges WHERE candidate_id=:id'),{'id':c['id']}).mappings().one()
            if str(h['session_id'])!=a['session_id'] or h['consumed_receipt'] or h['expires_at']<=self._now(s):raise IngestionError('challenge_unavailable')
            k=self._key(s,a,a['credential_id'])
            return self.verifier.authentication_options(bytes(h['nonce']),[bytes(k['external_id'])])
        return self._run(op)

    def begin_management(self,context,action,target=None):
        if action not in {'add_authorize','revoke'}:raise IngestionError('permission_denied')
        def op(s):
            a=self._authenticate(s,context,'credential.manage')
            if action=='revoke':self._key(s,a,_uuid(target))
            elif target is not None:raise IngestionError('permission_denied')
            c=self._new_ceremony(s,a,action,sid=a['session_id'],target=target)
            key=self._key(s,a,a['credential_id'])
            return {'ceremony_id':str(c['id']),'options':self.verifier.authentication_options(bytes(c['nonce']),[bytes(key['external_id'])])}
        return self._run(op)

    def _invalidate_sessions(self,s,actor):
        s.execute(text('UPDATE pemeo_ingest.principals SET auth_epoch=auth_epoch+1 WHERE id=:p'),{'p':actor['id']})
        s.execute(text('UPDATE pemeo_ingest.sessions SET active=false WHERE credential_id IN (SELECT id FROM pemeo_ingest.credentials WHERE principal_id=:p)'),{'p':actor['id']})

    def finish_management(self,context,action,identifier,raw):
        if action not in {'add_authorize','revoke'}:raise IngestionError('permission_denied')
        def op(s):
            a=self._authenticate(s,context,'credential.manage');c=self._ceremony(s,a,identifier,action,a['session_id'])
            when=self._verify(s,a,a['credential_id'],raw,c['nonce']);self._consume(s,c)
            self._auth_receipt(s,a,action,c['id'],when)
            if action=='add_authorize':
                nxt=self._new_ceremony(s,a,'add_register',sid=a['session_id'])
                return self._registration_options(s,a,nxt)
            s.execute(text('UPDATE pemeo_ingest.credentials SET active=false WHERE id=:id'),{'id':c['target_credential']})
            self._invalidate_sessions(s,a)
            return {'revoked':True,'login_required':True}
        return self._run(op)

    def finish_add(self,context,identifier,raw):
        def op(s):
            a=self._authenticate(s,context,'credential.manage');c=self._ceremony(s,a,identifier,'add_register',a['session_id'])
            key=self.verifier.register(raw,bytes(c['nonce']));cid=self._insert_key(s,a,key)
            self._consume(s,c);self._auth_receipt(s,a,'add_register',c['id'],self._now(s),cid=cid)
            self._invalidate_sessions(s,a)
            return {'registered':True,'login_required':True}
        return self._run(op)

    def logout(self,context):
        def op(s):
            a=self._authenticate(s,context,'receipt.read')
            s.execute(text('UPDATE pemeo_ingest.sessions SET active=false WHERE id=:id'),{'id':a['session_id']})
            return {'logged_out':True}
        return self._run(op)

    def create_statement(self,context,key,content):
        from .ingestion import _key
        from .ingestion_json import digest
        key=_key(key)
        if not isinstance(content,str) or not 1<=len(content)<=4000:raise IngestionError('invalid_statement')
        def op(s):
            a=self._authenticate(s,context,'statement.append')
            rd=digest('browser-statement',{'space_id':str(a['space_id']),'content':content})
            replay=self._replay(s,a,'statement.append',key,rd)
            if replay is not None:return replay
            record={'recordId':str(uuid4()),'protocolVersion':'0.1','schemaVersion':'0.1.0','kind':'entity','type':'human_statement',
              'createdAt':self._now(s).isoformat(),'metadata':{'source':{'kind':'human','agentRef':str(a['agent_id'])},
               'attestation':'direct','verification':'unverified','provenance':{'protocolSourceVersion':'0.1','evidenceRefs':[],'relationRefs':[]}},
              'payload':{'content':content,'modality':'text'}}
            checked=self._authorize_records(s,a,'statement.append',[record])
            return self._save(s,a,'statement.append',key,rd,checked)
        return self._run(op)

    def replay_confirmation(self,context,key,candidate_id,candidate_digest):
        from .ingestion import _key
        from .ingestion_json import digest
        key=_key(key);cid=_uuid(candidate_id)
        if not isinstance(candidate_digest,str) or len(candidate_digest)!=64:raise IngestionError('invalid_digest')
        def op(s):
            a=self._authenticate(s,context,'confirm.approve')
            rd=digest('request',{'action':'confirm.approve','space_id':str(a['space_id']),'candidate_id':cid,'candidate_digest':candidate_digest})
            result=self._replay(s,a,'confirm.approve',key,rd)
            return {'committed':False} if result is None else {**result,'committed':True}
        return self._run(op)

    def view_confirmation(self,context,candidate_id):
        def op(s):
            a=self._authenticate(s,context,'confirm.prepare');c=self._candidate(s,a,candidate_id)
            view=self._candidate_view(s,c)
            target=view['records'][0]['payload']['targetRef']
            view['target_record']=self._owned_record(s,a,target)['record_json']
            return view
        return self._run(op)
