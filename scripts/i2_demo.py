"""Isolated local I2 validation instance; never invokes the destructive test runner."""
from pathlib import Path
import argparse,datetime as dt,hashlib,json,os,secrets,signal,socket,subprocess,sys,uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
STATE=ROOT/'.local/i2-demo'
PROJECT='pemeo-core-i2-demo'


def save_private(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:f.write(data)


def validate_demo(info,root):
    if info['Config']['Labels'].get('com.docker.compose.project')!=PROJECT or info['State']['Status']!='running':raise ValueError('Wrong demo container')
    if set(info['NetworkSettings']['Networks'])!={PROJECT+'-network'}:raise ValueError('Wrong demo network')
    volumes=[m for m in info['Mounts'] if m['Type']=='volume']
    if len(volumes)!=1 or volumes[0]['Name']!=PROJECT+'-data' or volumes[0]['Destination']!='/var/lib/postgresql/data':raise ValueError('Wrong demo volume')
    binds=[m for m in info['Mounts'] if m['Type']=='bind'];expected=str((root/'sql/001_init.sql').resolve())
    if len(binds)!=1 or binds[0]['Source'] not in {expected,'/host_mnt'+expected} or binds[0]['RW'] or binds[0]['Destination']!='/docker-entrypoint-initdb.d/001_init.sql':raise ValueError('Wrong demo DDL mount')
    ports=info['NetworkSettings']['Ports'].get('5432/tcp')
    if not ports or len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1':raise ValueError('Demo must bind IPv4 loopback')
    port=int(ports[0]['HostPort'])
    if not 1<=port<=65535:raise ValueError('Invalid demo port')
    return port


def port():
    info=json.loads(subprocess.check_output(['docker','inspect',PROJECT+'-postgres'],text=True))[0]
    return validate_demo(info,ROOT)


def certificates():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    now=dt.datetime.now(dt.timezone.utc);ca_key=ec.generate_private_key(ec.SECP256R1());key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'PeMeO I2 Local Validation CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True).sign(ca_key,hashes.SHA256()))
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256()))
    save_private(STATE/'ca.key',ca_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    save_private(STATE/'localhost.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    save_private(STATE/'localhost.crt',leaf.public_bytes(serialization.Encoding.PEM).decode()+ca.public_bytes(serialization.Encoding.PEM).decode())
    save_private(STATE/'PeMeO-Local-CA.crt',ca.public_bytes(serialization.Encoding.PEM).decode())


def initialize():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL
    from sqlalchemy.orm import Session
    from psycopg import connect
    from ecom_backend.service import RecordService
    from ecom_backend.webauthn_service import secret_hash
    if (STATE/'config.json').exists():print('I2 demo already initialized; nothing reset.');return
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not (STATE/'admin.env').exists():save_private(STATE/'admin.env','PEMEO_I2_ADMIN_PASSWORD='+secrets.token_hex(24)+'\n')
    admin_password=(STATE/'admin.env').read_text().strip().split('=',1)[1]
    subprocess.run(['docker','compose','-f',str(ROOT/'docker-compose.i2.yml'),'--env-file',str(STATE/'admin.env'),'up','-d','--wait','--wait-timeout','50'],cwd=ROOT,check=True)
    dbport=port();evidence=STATE/'initialization';evidence.mkdir(exist_ok=True)
    app_password=secrets.token_hex(24)
    with connect(host='127.0.0.1',port=dbport,dbname='pemeo_core_test',user='pemeo_core_test',password=admin_password,autocommit=True) as c:
        identity=c.execute('SELECT current_database(),current_user').fetchone()
        if identity!=('pemeo_core_test','pemeo_core_test'):raise ValueError('Wrong identity')
        if c.execute("SELECT to_regclass('pemeo_ingest.installation')").fetchone()[0] is not None:
            raise ValueError('Existing/partial installation: do not overwrite or reset automatically')
        from foundation import prepare as f1
        from ingestion_setup import prepare as i1,disable as disable_i1
        from webauthn_setup import prepare as i2
        f1(c,ROOT,evidence,{})
        i1(c,ROOT,evidence,secrets.token_hex(24));disable_i1(c)
        i2(c,ROOT,evidence,app_password)
    engine=create_engine(URL.create('postgresql+psycopg',username='pemeo_core_test',password=admin_password,host='127.0.0.1',port=dbport,database='pemeo_core_test'),hide_parameters=True)
    agent=json.loads((ROOT/'protocol/ecom_protocol_v0.1.example.json').read_text())['records'][0]
    agent['recordId']=str(uuid.uuid4());agent['createdAt']=dt.datetime.now(dt.timezone.utc).isoformat();agent['payload']['label']='PeMeO I2 local validation owner'
    actor,space,realm=[str(uuid.uuid4()) for _ in range(3)];bootstrap=secrets.token_hex(32)
    with Session(engine) as s:RecordService(ROOT/'protocol/ecom_protocol_v0.1.schema.json').append_batch(s,[agent])
    with connect(host='127.0.0.1',port=dbport,dbname='pemeo_core_test',user='pemeo_core_test',password=admin_password) as c:
        c.execute('INSERT INTO pemeo_ingest.spaces VALUES (%s)',(space,))
        c.execute("INSERT INTO pemeo_ingest.principals(id,space_id,kind,agent_id) VALUES (%s,%s,'human',%s)",(actor,space,agent['recordId']))
        c.execute('INSERT INTO pemeo_ingest.record_scopes VALUES (%s,%s,%s)',(agent['recordId'],space,actor))
        for action in ['receipt.read','statement.append','confirm.prepare','confirm.approve','credential.manage']:c.execute('INSERT INTO pemeo_ingest.grants VALUES (%s,%s)',(actor,action))
        c.execute("INSERT INTO pemeo_ingest.installation VALUES (1,%s,%s,%s,clock_timestamp()+interval '15 minutes',false)",(realm,actor,secret_hash(bootstrap)))
    engine.dispose();certificates()
    # Opening a real registration window should be explicit, not automatic
    # during environment setup. Disable it until `registration-window`.
    with connect(host='127.0.0.1',port=dbport,dbname='pemeo_core_test',user='pemeo_core_test',password=admin_password) as c:
        c.execute("UPDATE pemeo_ingest.installation SET bootstrap_expires=clock_timestamp()-interval '1 second'")
    save_private(STATE/'config.json',json.dumps({'origin':'https://localhost:8443','port':8443,'realm':realm,'app_password':app_password},indent=2)+'\n')
    print('Initialized isolated I2 demo. No registration window is open. Certificate is not trusted automatically.')


def registration_window():
    import psycopg
    from ecom_backend.webauthn_service import secret_hash
    p=port();password=(STATE/'admin.env').read_text().strip().split('=',1)[1];token=secrets.token_hex(32)
    with psycopg.connect(host='127.0.0.1',port=p,dbname='pemeo_core_test',user='pemeo_core_test',password=password) as c:
        actor=c.execute('SELECT principal_id FROM pemeo_ingest.installation WHERE singleton=1').fetchone()[0]
        c.execute('SELECT pemeo_ingest.lock_principal(%s)',(actor,))
        row=c.execute('SELECT bootstrap_used FROM pemeo_ingest.installation WHERE singleton=1 FOR UPDATE').fetchone()
        if row[0] or c.execute('SELECT count(*) FROM pemeo_ingest.passkeys').fetchone()[0]:raise ValueError('Registration already completed; no reset path')
        c.execute("UPDATE pemeo_ingest.installation SET bootstrap_hash=%s,bootstrap_expires=clock_timestamp()+interval '10 minutes' WHERE singleton=1",(secret_hash(token),))
    # Local file only: never print bootstrap secrets to logs or assistant output.
    path=STATE/'registration-token.txt'
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),'w') as f:f.write(token+'\n')
    print('Ten-minute registration window opened; token saved locally in .local/i2-demo/registration-token.txt')


def app():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL
    from ecom_backend.service import RecordService
    from ecom_backend.webauthn_service import WebAuthnService
    cfg=json.loads((STATE/'config.json').read_text());dbport=port()
    engine=create_engine(URL.create('postgresql+psycopg',username='pemeo_core_i2_app',password=cfg['app_password'],host='127.0.0.1',port=dbport,database='pemeo_core_test'),hide_parameters=True,pool_size=4,max_overflow=4)
    return WebAuthnService(engine,RecordService(ROOT/'protocol/ecom_protocol_v0.1.schema.json'),origin=cfg['origin'],realm=cfg['realm']),cfg


def start():
    cfg=json.loads((STATE/'config.json').read_text());port() # validate DB before starting
    with socket.socket() as sock:
        if sock.connect_ex(('127.0.0.1',cfg['port']))==0:raise ValueError('Requested port already in use; no other service changed')
    log=open(STATE/'server.log','a');os.chmod(STATE/'server.log',0o600)
    env=os.environ.copy()
    for k in ['PYTHONPATH','PYTHONHOME','ECOM_DATABASE_URL','PEMEO_RUN_I1','PEMEO_RUN_I2']:env.pop(k,None)
    env['PYTHONDONTWRITEBYTECODE']='1'
    process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'serve'],cwd=ROOT,env=env,stdout=log,stderr=log,start_new_session=True)
    (STATE/'server.pid').write_text(str(process.pid)+'\n');print('Started local I2 HTTPS listener at '+cfg['origin'])


def stop():
    p=STATE/'server.pid'
    if not p.exists():print('No recorded I2 server');return
    pid=int(p.read_text());result=subprocess.run(['ps','-p',str(pid),'-o','command='],text=True,capture_output=True)
    if result.returncode:print('Recorded server has already stopped');return
    if str(Path(__file__).resolve())+' serve' not in result.stdout:raise ValueError('PID is not this I2 service; not stopped')
    os.kill(pid,signal.SIGTERM);print('Stopped this I2 listener')


def main():
    if Path(sys.prefix).resolve()!=(ROOT/'.venv').resolve():raise ValueError('Use this project .venv')
    p=argparse.ArgumentParser();p.add_argument('action',choices=['init','start','stop','serve','registration-window']);a=p.parse_args()
    if a.action=='init':initialize()
    elif a.action=='start':start()
    elif a.action=='stop':stop()
    elif a.action=='registration-window':registration_window()
    else:
        from ecom_backend.identity_http import serve
        service,cfg=app();serve(service,ROOT/'web',STATE/'localhost.crt',STATE/'localhost.key',cfg['port'])


if __name__=='__main__':main()
