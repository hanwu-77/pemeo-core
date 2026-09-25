"""Real pip refusal checks and supported-platform dependency closure checks."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import zipfile

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def wheel(folder, name, requires=None):
    path = folder / (name + '-1.0-py3-none-any.whl')
    prefix = name + '-1.0.dist-info/'
    metadata = 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n'
    if requires:
        metadata += 'Requires-Dist: ' + requires + '\n'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(prefix + 'METADATA', metadata)
        archive.writestr(prefix + 'WHEEL', 'Wheel-Version: 1.0\nGenerator: synthetic-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
        archive.writestr(prefix + 'RECORD', '')
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize('fault,expected', [
    ('none', None),
    ('tampered', 'DO NOT MATCH THE HASHES'),
    ('missing-hash', 'Hashes are required'),
    ('missing-transitive', 'must have their versions pinned'),
    ('missing-transitive-hash', 'Hashes are required'),
])
def test_pip_enforces_hashes_and_transitive_pins_without_network(tmp_path, fault, expected):
    a = wheel(tmp_path, 'synthetic_parent', 'synthetic-child>=1' if 'transitive' in fault else None)
    wheel(tmp_path, 'synthetic_child')
    if fault == 'tampered':
        with (tmp_path / 'synthetic_parent-1.0-py3-none-any.whl').open('ab') as stream:
            stream.write(b'tamper')
    line = 'synthetic-parent==1.0'
    if fault != 'missing-hash':
        line += ' --hash=sha256:' + a
    if fault == 'missing-transitive-hash':
        line += '\nsynthetic-child==1.0'
    lock = tmp_path / 'requirements.lock'
    lock.write_text(line + '\n')
    command = [sys.executable, '-I', '-m', 'pip', '--isolated', 'install', '--dry-run',
               '--ignore-installed', '--no-cache-dir', '--no-index', '--find-links', str(tmp_path),
               '--only-binary=:all:', '--require-hashes', '-r', str(lock)]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env={**os.environ, 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}, timeout=60)
    print(result.stdout)
    if expected is None:
        assert result.returncode == 0, result.stdout
    else:
        assert result.returncode != 0 and expected in result.stdout, result.stdout


def read_locks():
    result = {}
    for filename in ['requirements.lock', 'requirements-build.lock', 'requirements-bootstrap.lock']:
        for line in (ROOT / filename).read_text().replace('\\\n', ' ').splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            bits = line.split('--hash=sha256:')
            req = Requirement(bits[0].strip())
            name = canonicalize_name(req.name)
            hashes = {x.strip() for x in bits[1:]}
            assert hashes and all(len(h) == 64 for h in hashes)
            value = (req, hashes)
            if name in result:
                assert str(result[name][0]) == str(req) and result[name][1] == hashes
            result[name] = value
    return result


def test_selected_wheel_inventory_exactly_matches_all_hash_locks():
    locks = read_locks()
    inventory = json.loads((ROOT / 'release/python-artifacts.json').read_text())
    assert set(locks) == {canonicalize_name(p['name']) for p in inventory['packages']}
    for package in inventory['packages']:
        req, hashes = locks[canonicalize_name(package['name'])]
        assert str(req.specifier) == '==' + package['version']
        assert hashes == {w['sha256'] for w in package['wheels']}


@pytest.mark.parametrize('target,system,machine', [
    ('macos14-arm64', 'Darwin', 'arm64'), ('linux-x86_64', 'Linux', 'x86_64'),
])
def test_selected_wheel_dependency_closure_for_supported_target(target, system, machine):
    env = default_environment()
    env.update(python_version='3.12', python_full_version='3.12.14', platform_system=system,
               platform_machine=machine, sys_platform='darwin' if system == 'Darwin' else 'linux',
               implementation_name='cpython', implementation_version='3.12.14', extra='')
    locks = {name: value for name, value in read_locks().items()
             if value[0].marker is None or value[0].marker.evaluate(env)}
    packages = {canonicalize_name(p['name']): p
                for p in json.loads((ROOT / 'release/python-artifacts.json').read_text())['packages']}
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    roots = project['project']['dependencies'] + project['project']['optional-dependencies']['test'] + project['build-system']['requires']
    pending = [Requirement(r) for r in roots] + [Requirement(str(x[0]).split(';')[0]) for x in locks.values()]
    visited = set()
    while pending:
        req = pending.pop()
        name = canonicalize_name(req.name)
        assert name in locks, 'Missing pin: ' + name
        package = packages[name]
        assert package['version'] in req.specifier, str(req)
        extras = frozenset(req.extras)
        if (name, extras) in visited:
            continue
        visited.add((name, extras))
        wheels = [w for w in package['wheels'] if target in w['targets']]
        assert wheels, (name, target)
        for w in wheels:
            for raw in w['requires_dist']:
                child = Requirement(raw)
                if child.marker is None or any(child.marker.evaluate({**env, 'extra': e}) for e in extras | {''}):
                    pending.append(child)
