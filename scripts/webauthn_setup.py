"""Provision I2 role only after the caller verifies the isolated instance."""
import hashlib,json
from psycopg import sql
ROLE='pemeo_core_i2_app'


def prepare(connection,root,output,password):
    ddl=(root/'sql/007_webauthn.sql').read_bytes()
    connection.execute(ddl.decode())
    (output/'007_webauthn.sql').write_bytes(ddl)
    with (output/'ddl.sha256').open('a') as f:f.write(hashlib.sha256(ddl).hexdigest()+'  007_webauthn.sql\n')
    with connection.transaction():
        connection.execute("SET LOCAL password_encryption='scram-sha-256'")
        connection.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(ROLE),sql.Literal(password)))


def disable(connection):
    if connection.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(ROLE,)).fetchone():
        connection.execute(sql.SQL('ALTER ROLE {} NOLOGIN PASSWORD NULL').format(sql.Identifier(ROLE)))


def snapshot(connection,path):
    row=connection.execute('SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname=%s',(ROLE,)).fetchall()
    path.write_text(json.dumps({'role':row,'identity_evidence':'software authenticator tests only unless separate manual receipt exists'},indent=2)+'\n')
