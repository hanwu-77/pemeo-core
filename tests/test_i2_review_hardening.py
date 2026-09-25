"""I2 review fixes: standard derivation and HTTP fault metadata; synthetic only."""
import hashlib,hmac,json,logging,threading,http.client
from types import SimpleNamespace
from pathlib import Path
import pytest
from ecom_backend.webauthn_service import csrf_for,CSRF_PROFILE
from ecom_backend.identity_http import BoundedServer,make_handler,report_unexpected_error


def test_csrf_matches_rfc4231_hmac_library_and_versioned_profile():
    # RFC4231 case 1 independently anchors the standard HMAC primitive.
    assert hmac.new(bytes.fromhex('0b'*20),b'Hi There',hashlib.sha256).hexdigest()=='b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    token='ab'*32
    assert CSRF_PROFILE==b'pemeo-csrf-v2'
    assert csrf_for(token)==hmac.new(bytes.fromhex(token),b'pemeo-csrf-v2',hashlib.sha256).hexdigest()
    assert csrf_for(token)!=hashlib.sha256(('pemeo-csrf-v1:'+token).encode()).hexdigest()
    assert csrf_for(token)!=csrf_for('ac'*32)


@pytest.mark.parametrize('error',[RuntimeError,TypeError,AttributeError])
def test_http_500_logs_correlated_metadata_without_request_secrets(caplog,error):
    token='12'*32;csrf=csrf_for(token);bootstrap='BOOTSTRAP_CANARY';assertion='ASSERTION_CANARY'
    def fail(value):raise error('PRIVATE_EXCEPTION_CANARY '+value+' '+assertion)
    app=SimpleNamespace(verifier=SimpleNamespace(origin='https://localhost:8443'),begin_registration=fail)
    server=BoundedServer(('127.0.0.1',0),make_handler(app,Path('.')))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    caplog.set_level(logging.ERROR,logger='pemeo.http')
    try:
        conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
        body=json.dumps({'bootstrap':bootstrap,'credential':{'secret':assertion}})
        conn.request('POST','/api/register/begin',body=body,headers={'Host':'localhost:8443',
            'Origin':'https://localhost:8443','Content-Type':'application/json',
            'Cookie':'__Host-pemeo-preauth='+token,'X-PeMeO-CSRF':csrf})
        response=conn.getresponse();result=json.loads(response.read());conn.close()
        assert response.status==500 and result['error']=='internal_error'
        records=[r for r in caplog.records if r.name=='pemeo.http'];assert len(records)==1
        event=json.loads(records[0].getMessage());assert event['request_id']==result['request_id']
        assert len(event['request_id'])==32 and event['event']=='unexpected_http_error'
        assert event['route']=='/api/register/begin' and event['error_type']==error.__name__
        assert records[0].exc_info in (None,False) and records[0].stack_info is None
        for secret in [token,csrf,bootstrap,assertion,'PRIVATE_EXCEPTION_CANARY']:
            assert secret not in caplog.text and secret not in json.dumps(result)
    finally:server.shutdown();server.server_close();thread.join(timeout=5)


def test_logging_does_not_copy_untrusted_route_method_or_exception_name(caplog):
    caplog.set_level(logging.ERROR,logger='pemeo.http')
    error=type('SECRET_CLASS_CANARY',(Exception,),{})('SECRET_MESSAGE_CANARY')
    report_unexpected_error(error,'SECRET_METHOD_CANARY','/SECRET_PATH_CANARY')
    event=json.loads(caplog.records[-1].getMessage())
    assert event['route']=='unrecognized' and event['method']=='OTHER' and event['error_type']=='UnexpectedError'
    assert 'SECRET_' not in caplog.text
