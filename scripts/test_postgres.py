"""Run the original suite only against this repository's synthetic PostgreSQL."""
from __future__ import annotations

import argparse
import secrets
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROJECT = 'pemeo-core-test'
CONTAINER = PROJECT + '-postgres'
DATABASE = 'pemeo_core_test'


def validate_container(info: dict, root: Path) -> int:
    """Fail closed before opening a database connection. No credentials returned."""
    if info['Config']['Labels'].get('com.docker.compose.project') != PROJECT:
        raise ValueError('Wrong Compose project')
    if info['State']['Status'] != 'running':
        raise ValueError('Test container is not running')
    if set(info['NetworkSettings']['Networks']) != {PROJECT + '-network'}:
        raise ValueError('Wrong test network')
    volumes = [m for m in info['Mounts'] if m['Type'] == 'volume']
    if len(volumes) != 1 or volumes[0]['Name'] != PROJECT + '-data' or volumes[0]['Destination'] != '/var/lib/postgresql/data':
        raise ValueError('Wrong test volume')
    binds = [m for m in info['Mounts'] if m['Type'] == 'bind']
    expected_ddl = str((root / 'sql/001_init.sql').resolve())
    allowed_sources = {expected_ddl}
    if sys.platform == 'darwin':
        # Docker Desktop exposes this exact host path under its VM prefix.
        allowed_sources.add('/host_mnt' + expected_ddl)
    if len(binds) != 1 or binds[0]['Source'] not in allowed_sources or binds[0]['Destination'] != '/docker-entrypoint-initdb.d/001_init.sql' or binds[0]['RW']:
        raise ValueError('Wrong DDL mount')
    ports = info['NetworkSettings']['Ports'].get('5432/tcp')
    if not ports or len(ports) != 1 or ports[0]['HostIp'] != '127.0.0.1':
        raise ValueError('Test database must bind only IPv4 loopback')
    port = int(ports[0]['HostPort'])
    if not 1 <= port <= 65535:
        raise ValueError('Invalid test port')
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--foundation', action='store_true', help='Deploy temporary F1 roles and run real-role tests')
    parser.add_argument('--ingestion', action='store_true', help='Run F1 plus I1 synthetic-authentication tests')
    parser.add_argument('--webauthn', action='store_true', help='Include I2 real signature tests using software keys')
    parser.add_argument('--browser', action='store_true', help='Run isolated virtual-authenticator browser test; requires PEMEO_NODE and PEMEO_PLAYWRIGHT_MODULE')
    options = parser.parse_args()
    if options.browser:
        options.webauthn = True
        if not os.environ.get('PEMEO_NODE') or not os.environ.get('PEMEO_PLAYWRIGHT_MODULE'):
            raise ValueError('Explicit browser tool paths required')
    if options.webauthn:
        options.ingestion = True
    if options.ingestion:
        options.foundation = True
    if Path(sys.prefix).resolve() != (ROOT / '.venv').resolve():
        raise ValueError('Run with this project .venv/bin/python')
    info = json.loads(subprocess.check_output(['docker', 'inspect', CONTAINER], text=True))[0]
    port = validate_container(info, ROOT)
    secret_lines = [line for line in (ROOT / '.env').read_text().splitlines() if line.startswith('PEMEO_CORE_TEST_PASSWORD=')]
    if len(secret_lines) != 1:
        raise ValueError('Expected one project-local test password')
    password = secret_lines[0].split('=', 1)[1]
    if not re.fullmatch('[0-9a-f]{48}', password):
        raise ValueError('Generate a fresh 48-character hexadecimal test password')
    import importlib.metadata as metadata
    import psycopg

    connect = dict(host='127.0.0.1', port=port, dbname=DATABASE, user=DATABASE, password=password)
    with psycopg.connect(**connect) as connection:
        with connection.cursor() as cursor:
            cursor.execute('select current_database(), current_user, version()')
            database, role, version = cursor.fetchone()
            if database != DATABASE or role != DATABASE:
                raise ValueError('Unexpected database identity')
            cursor.execute('select (select count(*) from ecom_records), (select count(*) from ecom_prov_edges)')
            before = cursor.fetchone()
            cursor.execute('select system_identifier::text from pg_control_system()')
            system_id = cursor.fetchone()[0]
            cursor.execute('select rolsuper from pg_roles where rolname=current_user')
            superuser = cursor.fetchone()[0]
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    output = ROOT / 'artifacts/validation' / stamp
    output.mkdir(parents=True, exist_ok=False)
    import zipfile
    source_paths = sorted(p for folder in ('src','tests','scripts','sql','protocol','web')
                          for p in (ROOT/folder).rglob('*')
                          if p.is_file() and '__pycache__' not in p.parts
                          and not any(part.endswith('.egg-info') for part in p.parts)
                          and p.suffix in {'.py','.sql','.json','.html','.css','.js','.cjs'})
    source_paths += [ROOT/'pyproject.toml', ROOT/'requirements.lock', ROOT/'docker-compose.yml', ROOT/'docker-compose.i2.yml']
    source_manifest = ''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(ROOT).as_posix()+'\n'
                              for p in sorted(source_paths))
    (output/'executed-source.sha256').write_text(source_manifest)
    with zipfile.ZipFile(output/'executed-source.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for p in sorted(source_paths): archive.write(p,p.relative_to(ROOT).as_posix())
        archive.writestr('MANIFEST.sha256',source_manifest)
    (output/'requirements-tested.txt').write_text(subprocess.check_output(
        [sys.executable,'-m','pip','--isolated','freeze','--all'],text=True))
    environment = os.environ.copy()
    for key in ['PYTHONPATH', 'PYTHONHOME', 'ECOM_DATABASE_URL', 'ECOM_RUN_PG_TESTS', 'PEMEO_RUN_F1', 'PEMEO_F1_CONNECTIONS', 'PEMEO_RUN_I1', 'PEMEO_RUN_I2','PEMEO_RUN_I2_BROWSER','PEMEO_BROWSER_EVIDENCE']:
        environment.pop(key, None)
    environment.update(ECOM_RUN_PG_TESTS='1', ECOM_DATABASE_URL=f'postgresql+psycopg://{DATABASE}:{password}@127.0.0.1:{port}/{DATABASE}', PYTHONDONTWRITEBYTECODE='1')
    command = [sys.executable, '-m', 'pytest', '-vv', '-p', 'no:cacheprovider', '--junitxml=' + str(output / 'pytest.xml')]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    role_passwords = {}
    cleanup_error = None
    if options.foundation:
        from foundation import ROLES
        role_passwords = {role: secrets.token_hex(24) for role in ROLES[1:]}
    if options.ingestion:
        from ingestion_setup import ROLE as I1_ROLE
        role_passwords[I1_ROLE] = secrets.token_hex(24)
    if options.webauthn:
        from webauthn_setup import ROLE as I2_ROLE
        role_passwords[I2_ROLE] = secrets.token_hex(24)
    all_secrets = [password, *role_passwords.values()]

    def redact(value):
        for secret in all_secrets:
            value = value.replace(secret, '[REDACTED]')
        return value

    returncode = 1
    log = ''
    try:
        if options.foundation:
            from foundation import prepare, write_snapshot
            with psycopg.connect(**connect, autocommit=True) as admin:
                prepare(admin, ROOT, output, {r:p for r,p in role_passwords.items() if r in ROLES})
                write_snapshot(admin, output / 'roles-during-tests.json')
                if options.ingestion:
                    from ingestion_setup import prepare as prepare_i1, snapshot as snapshot_i1
                    prepare_i1(admin, ROOT, output, role_passwords[I1_ROLE])
                    snapshot_i1(admin, output/'i1-role-during-tests.json')
                if options.webauthn:
                    from webauthn_setup import prepare as prepare_i2, snapshot as snapshot_i2
                    prepare_i2(admin, ROOT, output, role_passwords[I2_ROLE])
                    snapshot_i2(admin, output/'i2-role-during-tests.json')
            environment.update(PEMEO_RUN_F1='1', PEMEO_F1_CONNECTIONS=json.dumps(dict(
                host='127.0.0.1', port=port, dbname=DATABASE,
                passwords={DATABASE: password, **role_passwords})))
        if options.ingestion:
            environment['PEMEO_RUN_I1'] = '1'
        if options.webauthn:
            environment['PEMEO_RUN_I2'] = '1'
        if options.browser:
            environment['PEMEO_RUN_I2_BROWSER']='1'
            environment['PEMEO_BROWSER_EVIDENCE']=str(output/'browser')
        result = subprocess.run(command, cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        returncode = result.returncode
        log = redact(result.stdout)
    except Exception as exc:
        # Persist a useful, redacted failure, still revoke all temporary logins.
        log = redact(f'Runner failed: {type(exc).__name__}: {exc}\n')
    finally:
        if options.foundation:
            from foundation import disable_logins, write_snapshot
            cleanup_actions = [(disable_logins, write_snapshot, 'roles-after-tests.json')]
            if options.ingestion:
                from ingestion_setup import disable as disable_i1, snapshot as snapshot_i1
                cleanup_actions.append((disable_i1, snapshot_i1, 'i1-role-after-tests.json'))
            if options.webauthn:
                from webauthn_setup import disable as disable_i2, snapshot as snapshot_i2
                cleanup_actions.append((disable_i2, snapshot_i2, 'i2-role-after-tests.json'))
            errors = []
            for disable, snapshot, filename in cleanup_actions:
                try:
                    with psycopg.connect(**connect, autocommit=True) as admin:
                        disable(admin)
                        snapshot(admin, output / filename)
                except Exception as exc:
                    errors.append(redact(f'{filename}: {type(exc).__name__}: {exc}'))
            if errors:
                cleanup_error = '; '.join(errors)
                returncode = 1
        finished = dt.datetime.now(dt.timezone.utc).isoformat()
        server = subprocess.run(['docker', 'logs', '--timestamps', '--since', started, CONTAINER],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / 'postgres-server.log').write_text(redact(server.stdout))
        if server.returncode:
            log += '\nFailed to capture database logs.\n'
            returncode = 1
    if cleanup_error:
        log += '\nTemporary login cleanup failed: ' + cleanup_error + '\n'
    (output / 'pytest.log').write_text(log)
    xml = output / 'pytest.xml'
    redacted = False
    if xml.exists():
        original_xml = xml.read_text()
        safe_xml = redact(original_xml)
        redacted = original_xml != safe_xml
        xml.write_text(safe_xml)
    facts = dict(started_utc=started, finished_utc=finished, command=command, exit_code=returncode, container_id=info['Id'], container_created=info['Created'], image_id=info['Image'], project=PROJECT, network=PROJECT+'-network', volume=PROJECT+'-data', database=database, role=role, role_is_superuser=superuser, server_version=version, system_identifier=system_id, host='127.0.0.1', port=port, initial_record_edge_counts=before, python=sys.version, python_executable=sys.executable, venv_prefix=sys.prefix, schema_sha256=hashlib.sha256((ROOT/'protocol/ecom_protocol_v0.1.schema.json').read_bytes()).hexdigest(), ddl_sha256=hashlib.sha256((ROOT/'sql/001_init.sql').read_bytes()).hexdigest(), dependencies={p: metadata.version(p) for p in ['pytest','SQLAlchemy','psycopg','psycopg-binary','jsonschema','pydantic','rfc8785','webauthn','cryptography','cbor2']}, junit_secret_redacted=redacted, foundation_enabled=options.foundation, ingestion_enabled=options.ingestion, webauthn_enabled=options.webauthn, virtual_browser_enabled=options.browser, temporary_login_cleanup_error=cleanup_error, limitations=['Synthetic database; administrator performs setup and original regression tests', 'F1 tests use separate real login roles when --foundation is selected', 'No trusted human identity API; database owner/admin remain trusted', 'Docker metadata guards protect against accidental misrouting, not a hostile Docker administrator'])
    (output / 'environment.json').write_text(json.dumps(facts, ensure_ascii=False, indent=2) + '\n')
    print(log)
    print('Evidence:', output)
    return returncode


if __name__ == '__main__':
    raise SystemExit(main())
