"""I1 test-only provisioning, called after the existing container guard and F1."""
import hashlib
import json

ROLE = 'pemeo_core_i1_app'


def prepare(connection, root, output, password):
    from psycopg import sql
    name='006_ingestion.sql'
    ddl=(root/'sql'/name).read_text()
    connection.execute(ddl)
    (output/name).write_text(ddl)
    with (output/'ddl.sha256').open('a') as out:
        out.write(hashlib.sha256(ddl.encode()).hexdigest()+'  '+name+'\n')
    with connection.transaction():
        connection.execute("SET LOCAL password_encryption='scram-sha-256'")
        connection.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(ROLE),sql.Literal(password)))


def disable(connection):
    from psycopg import sql
    if connection.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(ROLE,)).fetchone():
        connection.execute(sql.SQL('ALTER ROLE {} NOLOGIN PASSWORD NULL').format(sql.Identifier(ROLE)))


def snapshot(connection,path):
    facts={
        'role': connection.execute('SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname=%s',(ROLE,)).fetchall(),
        'table_grants': connection.execute("SELECT table_schema,table_name,privilege_type FROM information_schema.table_privileges WHERE grantee=%s ORDER BY 1,2,3",(ROLE,)).fetchall(),
        'column_grants': connection.execute("SELECT table_schema,table_name,column_name,privilege_type FROM information_schema.column_privileges WHERE grantee=%s ORDER BY 1,2,3,4",(ROLE,)).fetchall(),
        'human_authentication':'simulated only; no actual WebAuthn verifier installed',
    }
    path.write_text(json.dumps(facts,indent=2)+'\n')
