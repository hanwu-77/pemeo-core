import json,secrets
from dataclasses import replace
import pytest
from ecom_backend.ingestion import IngestionError
from ecom_backend.webauthn_adapter import WebAuthnVerifier,encode,decode
from webauthn_fixtures import SoftwareAuthenticator


def enrolled(backup=False):
    v=WebAuthnVerifier('https://localhost:8443');a=SoftwareAuthenticator(backup=backup);handle=secrets.token_bytes(16)
    nonce=secrets.token_bytes(32);options=v.registration_options(nonce,handle)
    key=v.register(a.response(options,register=True),nonce)
    return v,a,key,handle


def test_real_library_registration_and_signature_verification():
    v,a,k,h=enrolled();nonce=secrets.token_bytes(32)
    result=v.authenticate(a.response(v.authentication_options(nonce,[k.external_id])),nonce,k,h)
    assert result.sign_count==2 and result.external_id==k.external_id


@pytest.mark.parametrize('field,value',[('uv',False),('up',False),('origin','https://evil.invalid'),('rp','evil.invalid'),('cross',True),('handle',encode(bytes(16)))])
def test_signature_does_not_override_rp_origin_uv_or_handle(field,value):
    v,a,k,h=enrolled();nonce=secrets.token_bytes(32)
    raw=a.response(v.authentication_options(nonce,[k.external_id]),**{field:value})
    with pytest.raises(IngestionError,match='assertion_verification_failed'):v.authenticate(raw,nonce,k,h)


@pytest.mark.parametrize('field,value',[('uv',False),('up',False),('origin','https://evil.invalid'),('rp','evil.invalid'),('cross',True)])
def test_registration_requires_correct_origin_rp_and_uv(field,value):
    v=WebAuthnVerifier('https://localhost:8443');a=SoftwareAuthenticator();nonce=secrets.token_bytes(32)
    raw=a.response(v.registration_options(nonce,bytes(16)),register=True,**{field:value})
    with pytest.raises(IngestionError,match='registration_verification_failed'):v.register(raw,nonce)


@pytest.mark.parametrize('case',['signature','challenge','duplicate_client_key','top_origin','rawid','key','be_change'])
def test_tampering_or_binding_mismatch_fails(case):
    v,a,k,h=enrolled();nonce=secrets.token_bytes(32)
    if case=='be_change':a.backup=True
    raw=a.response(v.authentication_options(nonce,[k.external_id]));body=json.loads(raw)
    if case=='signature':body['response']['signature']=encode(bytes(64))
    if case=='challenge':nonce=secrets.token_bytes(32)
    if case=='duplicate_client_key':
        c=decode(body['response']['clientDataJSON']);body['response']['clientDataJSON']=encode(c[:-1]+b',"origin":"https://localhost:8443"}')
    if case=='top_origin':
        c=json.loads(decode(body['response']['clientDataJSON']));c['topOrigin']='https://localhost:8443';body['response']['clientDataJSON']=encode(json.dumps(c).encode())
    if case=='rawid':body['rawId']=encode(bytes(32))
    if case=='key':k=replace(k,public_key=bytes(32))
    with pytest.raises(IngestionError):v.authenticate(json.dumps(body).encode(),nonce,k,h)


def test_backup_eligible_counter_is_not_a_strict_clone_detector():
    v,a,k,h=enrolled(True);nonce=secrets.token_bytes(32)
    k=replace(k,sign_count=20)
    for count in (0,5,20):
        out=v.authenticate(a.response(v.authentication_options(nonce,[k.external_id]),count=count,backed_up=True),nonce,k,h)
        assert out.sign_count==20 and out.backed_up


def test_single_device_counter_regression_rejected():
    v,a,k,h=enrolled();nonce=secrets.token_bytes(32)
    with pytest.raises(IngestionError):v.authenticate(a.response(v.authentication_options(nonce,[k.external_id]),count=0),nonce,k,h)


@pytest.mark.parametrize('origin',['http://localhost:8443','https://127.0.0.1:8443','https://localhost:8443/','https://evil.invalid','https://localhost:8443?x=1'])
def test_origin_configuration_is_exact(origin):
    with pytest.raises(ValueError):WebAuthnVerifier(origin)


@pytest.mark.parametrize('phase',['registration','authentication'])
def test_unexpected_verifier_bug_is_not_classified_as_bad_credentials(monkeypatch,phase):
    import ecom_backend.webauthn_adapter as module
    v,a,k,h=enrolled();nonce=secrets.token_bytes(32)
    def broken(**kwargs):raise RuntimeError('synthetic implementation bug')
    if phase=='registration':
        raw=a.response(v.registration_options(nonce,h),register=True)
        monkeypatch.setattr(module,'verify_registration_response',broken)
        with pytest.raises(RuntimeError,match='implementation bug'):v.register(raw,nonce)
    else:
        raw=a.response(v.authentication_options(nonce,[k.external_id]))
        monkeypatch.setattr(module,'verify_authentication_response',broken)
        with pytest.raises(RuntimeError,match='implementation bug'):v.authenticate(raw,nonce,k,h)


@pytest.mark.parametrize('body',[[],{'type':'public-key','response':[]},
    {'type':'public-key','rawId':'YQ','response':{'clientDataJSON':'W10'}}])
def test_malformed_json_shapes_are_rejected(body):
    v=WebAuthnVerifier('https://localhost:8443')
    with pytest.raises(IngestionError):v.register(json.dumps(body).encode(),bytes(32))
