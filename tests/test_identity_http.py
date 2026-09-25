from email.message import Message
from pathlib import Path
import importlib.util
import pytest
from ecom_backend.identity_http import validate_request,cookie_value
from ecom_backend.ingestion import IngestionError


def headers():
    h=Message();h['Host']='localhost:8443';h['Origin']='https://localhost:8443';h['Content-Type']='application/json';h['Content-Length']='2';return h


def test_exact_origin_json_post_is_allowed():validate_request('POST','/api/login/begin',headers(),'https://localhost:8443')


@pytest.mark.parametrize('name,value',[('Host','evil.invalid'),('Origin','https://localhost:9443'),('Origin','null'),
    ('Sec-Fetch-Site','cross-site'),('Content-Type','text/plain'),('Content-Length','65537'),('Content-Length','-1'),
    ('Transfer-Encoding','chunked')])
def test_foreign_or_ambiguous_requests_are_denied(name,value):
    h=headers();del h[name];h[name]=value
    with pytest.raises(IngestionError):validate_request('POST','/api/login/begin',h,'https://localhost:8443')


@pytest.mark.parametrize('name',['Host','Origin','Content-Type','Content-Length'])
def test_duplicate_security_headers_are_denied(name):
    h=headers();h[name]=h[name]
    with pytest.raises(IngestionError):validate_request('POST','/api/login/begin',h,'https://localhost:8443')


def test_missing_origin_is_not_accepted_for_post():
    h=headers();del h['Origin']
    with pytest.raises(IngestionError):validate_request('POST','/api/login/begin',h,'https://localhost:8443')


def test_duplicate_cookie_names_are_not_silently_overridden():
    h=headers();h['Cookie']='__Host-pemeo-session=a; __Host-pemeo-session=b'
    with pytest.raises(IngestionError):cookie_value(h,'__Host-pemeo-session')


def test_demo_guard_rejects_automated_test_container():
    p=Path(__file__).resolve().parents[1]/'scripts/i2_demo.py';spec=importlib.util.spec_from_file_location('i2_demo_guard',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    info={'Config':{'Labels':{'com.docker.compose.project':'pemeo-core-test'}},'State':{'Status':'running'}}
    with pytest.raises(ValueError,match='Wrong demo container'):m.validate_demo(info,p.parents[1])
