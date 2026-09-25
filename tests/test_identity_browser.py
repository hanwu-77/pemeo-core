import datetime as dt,json,os,ssl,subprocess,threading
from pathlib import Path
import pytest
from test_webauthn_postgres import real
from test_ingestion_postgres import db
from ecom_backend.identity_http import BoundedServer,make_handler
from ecom_backend.webauthn_adapter import WebAuthnVerifier

pytestmark=pytest.mark.skipif(os.environ.get('PEMEO_RUN_I2_BROWSER')!='1',reason='Requires explicit virtual-browser test environment')


def test_https_browser_virtual_authenticator_roundtrip(real,tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    r=Path(__file__).resolve().parents[1]
    key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=dt.datetime.now(dt.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256()))
    (tmp_path/'tls.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM));(tmp_path/'tls.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server=BoundedServer(('127.0.0.1',0),make_handler(real['real'],r/'web'))
    origin='https://localhost:'+str(server.server_port);real['real'].verifier=WebAuthnVerifier(origin)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(tmp_path/'tls.crt',tmp_path/'tls.key');server.socket=tls.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    output=Path(os.environ['PEMEO_BROWSER_EVIDENCE']);output.mkdir(exist_ok=True)
    try:
        tool_env=os.environ.copy();browser_tmp=r/'.cache/i2-browser';browser_tmp.mkdir(exist_ok=True)
        tool_env['TMPDIR']=str(browser_tmp)
        result=subprocess.run([os.environ['PEMEO_NODE'],str(r/'tests/browser_i2.cjs')],input=json.dumps({'origin':origin,'bootstrap':real['bootstrap'],'screenshot':str(output/'virtual-confirmation.png')}),text=True,capture_output=True,timeout=90,env=tool_env)
        (output/'browser.log').write_text(result.stderr)
        assert result.returncode==0,result.stderr
        info=json.loads(result.stdout);assert info['virtual_authenticator'] and not info['human_acceptance']
        (output/'browser.json').write_text(json.dumps(info,indent=2)+'\n')
        with real['connect'](True) as c:
            assert c.execute("SELECT count(*) FROM ecom_records WHERE type='human_confirmation'").fetchone()==(1,)
            assert c.execute('SELECT count(*) FROM pemeo_ingest.auth_receipts WHERE receipt_id=%s',(info['receipt_id'],)).fetchone()==(1,)
    finally:
        server.shutdown();server.server_close();worker.join(timeout=5)
