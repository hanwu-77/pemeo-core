"""Real isolated DB tests of migration without deleting credentials/history."""
import hashlib,os
from dataclasses import replace
import pytest
from test_ingestion_postgres import db
from test_webauthn_postgres import real,register,login
from ecom_backend.webauthn_service import secret_hash
from ecom_backend.ingestion import IngestionError

pytestmark=pytest.mark.skipif(os.environ.get('PEMEO_RUN_I2')!='1',reason='Use guarded runner --browser')


def test_legacy_csrf_session_requires_relogin_without_removing_keys(real):
    register(real);ctx=login(real);app=real['real']
    legacy=hashlib.sha256(('pemeo-csrf-v1:'+ctx.token).encode()).hexdigest()
    with real['connect'](True) as conn:
        conn.execute('UPDATE pemeo_ingest.web_sessions SET csrf_hash=%s WHERE token_hash=%s',(secret_hash(legacy),secret_hash(ctx.token)))
    # Neither the old header nor a newly derived header can revive this row.
    for old_context in (replace(ctx,csrf=legacy),ctx):
        with pytest.raises(IngestionError,match='authentication_required'):app.account(old_context)
    new=login(real);assert app.account(new)['authenticated']
    with real['connect'](True) as conn:
        assert conn.execute('SELECT count(*) FROM pemeo_ingest.passkeys').fetchone()==(1,)
        assert conn.execute("SELECT count(*) FROM pemeo_ingest.auth_receipts WHERE action='register'").fetchone()==(1,)
        assert conn.execute('SELECT count(*) FROM pemeo_ingest.web_sessions').fetchone()==(2,)
