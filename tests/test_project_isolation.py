"""Project-only guard regressions; original 19 core tests remain unchanged."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('core_pg_runner', ROOT / 'scripts/test_postgres.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def info():
    return {
        'Config': {'Labels': {'com.docker.compose.project': 'pemeo-core-test'}},
        'State': {'Status': 'running'},
        'NetworkSettings': {'Networks': {'pemeo-core-test-network': {}}, 'Ports': {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '55000'}]}},
        'Mounts': [
            {'Type': 'volume', 'Name': 'pemeo-core-test-data', 'Destination': '/var/lib/postgresql/data'},
            {'Type': 'bind', 'Source': str(ROOT / 'sql/001_init.sql'), 'Destination': '/docker-entrypoint-initdb.d/001_init.sql', 'RW': False},
        ],
    }


def test_owned_synthetic_database_is_accepted():
    assert runner.validate_container(info(), ROOT) == 55000


def test_other_compose_project_is_rejected():
    data = info(); data['Config']['Labels']['com.docker.compose.project'] = 'unrelated'
    with pytest.raises(ValueError, match='Wrong Compose project'):
        runner.validate_container(data, ROOT)


def test_other_data_volume_is_rejected():
    data = info(); data['Mounts'][0]['Name'] = 'unrelated-data'
    with pytest.raises(ValueError, match='Wrong test volume'):
        runner.validate_container(data, ROOT)


def test_non_loopback_database_is_rejected():
    data = info(); data['NetworkSettings']['Ports']['5432/tcp'][0]['HostIp'] = '0.0.0.0'
    with pytest.raises(ValueError, match='loopback'):
        runner.validate_container(data, ROOT)


def test_other_network_is_rejected():
    data = info(); data['NetworkSettings']['Networks'] = {'unrelated-network': {}}
    with pytest.raises(ValueError, match='Wrong test network'):
        runner.validate_container(data, ROOT)


def test_writable_ddl_mount_is_rejected():
    data = info(); data['Mounts'][1]['RW'] = True
    with pytest.raises(ValueError, match='Wrong DDL mount'):
        runner.validate_container(data, ROOT)


def test_docker_desktop_exact_host_mapping_is_accepted(monkeypatch):
    monkeypatch.setattr(runner.sys, 'platform', 'darwin')
    data = info(); data['Mounts'][1]['Source'] = '/host_mnt' + str(ROOT / 'sql/001_init.sql')
    assert runner.validate_container(data, ROOT) == 55000


def test_docker_desktop_other_project_mount_is_rejected(monkeypatch):
    monkeypatch.setattr(runner.sys, 'platform', 'darwin')
    data = info(); data['Mounts'][1]['Source'] = '/host_mnt' + str(ROOT.parent / 'unrelated/sql/001_init.sql')
    with pytest.raises(ValueError, match='Wrong DDL mount'):
        runner.validate_container(data, ROOT)
