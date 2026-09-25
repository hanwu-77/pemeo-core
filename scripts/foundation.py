"""F1 provisioning/evidence helpers. Called only after the existing Docker guard."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROLES = ('pemeo_core_f1_owner', 'pemeo_core_f1_writer',
         'pemeo_core_f1_reader', 'pemeo_core_f1_rebuild')


def prepare(connection, root: Path, output: Path, passwords: dict[str, str]) -> None:
    from psycopg import sql

    ddl_names = ['004_foundation_roles.sql', '005_guarded_projection_rebuild.sql']
    hashes = []
    for name in ddl_names:
        ddl = (root / 'sql' / name).read_text()
        connection.execute(ddl)
        (output / name).write_text(ddl)
        hashes.append(hashlib.sha256(ddl.encode()).hexdigest() + '  ' + name)
    (output / 'ddl.sha256').write_text('\n'.join(hashes) + '\n')
    with connection.transaction():
        connection.execute("SET LOCAL password_encryption = 'scram-sha-256'")
        for role, password in passwords.items():
            connection.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(
                sql.Identifier(role), sql.Literal(password)))


def disable_logins(connection) -> None:
    from psycopg import sql

    with connection.transaction():
        existing = {row[0] for row in connection.execute('SELECT rolname FROM pg_roles WHERE rolname=ANY(%s)', (list(ROLES[1:]),)).fetchall()}
        for role in sorted(existing):
            connection.execute(sql.SQL('ALTER ROLE {} NOLOGIN PASSWORD NULL').format(sql.Identifier(role)))


def snapshot(connection) -> dict:
    # pg_roles deliberately excludes password hashes. Never query pg_authid here.
    roles = connection.execute(
        'SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolinherit, '
        'rolreplication, rolbypassrls, rolcanlogin FROM pg_roles '
        'WHERE rolname = ANY(%s) ORDER BY rolname', (list(ROLES),)).fetchall()
    grants = connection.execute(
        "SELECT grantee, table_name, privilege_type FROM information_schema.table_privileges "
        "WHERE table_schema='public' AND grantee=ANY(%s) ORDER BY 1,2,3", (list(ROLES),)).fetchall()
    functions = connection.execute(
        "SELECT p.proname, r.rolname, p.prosecdef, p.proconfig FROM pg_proc p "
        "JOIN pg_roles r ON r.oid=p.proowner JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='public' AND p.proname IN ('ecom_project_relation_edge','ecom_block_record_mutation','pemeo_rebuild_prov_edges') "
        "ORDER BY p.proname").fetchall()
    owners = connection.execute(
        "SELECT c.relname, r.rolname FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' "
        "AND c.relname IN ('ecom_records','ecom_prov_edges','ecom_prov_edges_edge_id_seq') ORDER BY 1").fetchall()
    return dict(role_columns=['name', 'superuser', 'createdb', 'createrole', 'inherit',
                              'replication', 'bypassrls', 'login'],
                roles=roles, grants=grants, functions=functions, owners=owners)


def write_snapshot(connection, destination: Path) -> None:
    destination.write_text(json.dumps(snapshot(connection), ensure_ascii=False, indent=2) + '\n')
