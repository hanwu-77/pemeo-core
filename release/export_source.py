"""Build a source-only candidate from an explicit reviewed mapping (stdlib only)."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, re, zipfile

PRIVATE_PATH = re.compile(r'(?:/(?:Users|home)/[^\s/]+|[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\s\\/]+)')
PRIVATE_KEY = re.compile(r'-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----')
TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,})\b')
DENIED = {'.git', '.venv', '.local', '.cache', 'node_modules', 'artifacts', '__pycache__'}
DENIED_SUFFIX = {'.key', '.pem', '.crt', '.p12', '.db', '.sqlite', '.sqlite3', '.dump', '.whl', '.zip', '.pyc', '.dylib', '.so'}


def safe_relative(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or '..' in p.parts or '\\' in value or str(p) != value:
        raise ValueError('Unsafe mapping path')
    if any(c in value for c in '\r\n\t'):
        raise ValueError('Control character in path')
    if any(x in DENIED for x in p.parts) or p.suffix in DENIED_SUFFIX:
        raise ValueError('Private or binary path excluded')
    if any(x.startswith('.env') and x != '.env.example' for x in p.parts):
        raise ValueError('Environment file excluded')
    return p


def scan_text(name, data):
    text = data.decode('utf-8')
    if '\x00' in text or PRIVATE_PATH.search(text) or PRIVATE_KEY.search(text) or TOKEN.search(text):
        # Do not echo the matching secret or private path.
        raise ValueError('Sensitive/binary content detected in ' + name)


def collect(root, spec):
    root = root.resolve()
    files = {}
    for entry in spec['files']:
        source, target = entry['source'], entry['target']
        safe_relative(source); safe_relative(target)
        if target in files or target == 'MANIFEST.sha256':
            raise ValueError('Duplicate or reserved target')
        path = root / source
        if any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
            raise ValueError('Symlink inputs excluded')
        if not path.resolve().is_relative_to(root) or not path.is_file():
            raise ValueError('Missing or escaping input')
        data = path.read_bytes(); scan_text(target, data); files[target] = data
    if not files:
        raise ValueError('Empty candidate')
    return files


def write_archive(files, archive):
    archive = Path(archive)
    if archive.exists():
        raise FileExistsError('Existing candidate must not be overwritten')
    digest = lambda b: hashlib.sha256(b).hexdigest()
    content = dict(files)
    content['MANIFEST.sha256'] = ''.join(digest(b) + '  ' + n + '\n' for n,b in sorted(files.items())).encode()
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open('xb') as handle, zipfile.ZipFile(handle, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(content.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, data)
    with zipfile.ZipFile(archive) as z:
        if set(z.namelist()) != set(content):
            raise ValueError('Archive member verification failed')
        for name, data in content.items():
            if z.read(name) != data:
                raise ValueError('Archive byte verification failed')
    return {'sha256': digest(archive.read_bytes()), 'manifest_entries': len(files), 'files': len(content),
            'text_scan_passed': True, 'private_data_bundled': False,
            'scope': 'Heuristic content checks plus explicit whitelist; not exhaustive secret detection or legal clearance'}


REQUIRED_RELEASE_FILES = frozenset({
    'LICENSE', 'NOTICE', 'pyproject.toml', 'requirements.lock', 'requirements-build.lock',
    'requirements-bootstrap.lock', 'third_party/DEPENDENCIES.json', 'third_party/TOOLS.json',
    'docker-compose.yml', 'docker-compose.i2.yml', '.env.example', 'package.json',
    'pnpm-lock.yaml', 'release/pnpm/package.json', 'release/pnpm/package-lock.json',
    'release/python-artifacts.json', 'release/pnpm-artifact.json', 'release/test_dependency_install.py',
    'scripts/test_postgres.py', 'scripts/i2_demo.py',
    'protocol/ecom_protocol_v0.1.schema.json', 'protocol/ecom_protocol_v0.1.example.json',
    'web/index.html', 'web/app.js', 'web/style.css', 'sql/001_init.sql',
    'release/public-files.json', 'release/export_source.py', 'release/test_export_source.py',
    'README.md', 'docs/INSTALL.md', 'SECURITY.md', 'docs/KNOWN_LIMITATIONS.md',
})


def validate_license_inventory(files):
    for name, key in [('third_party/DEPENDENCIES.json', 'packages'),
                      ('third_party/TOOLS.json', 'tools')]:
        inventory = json.loads(files[name])
        for package in inventory[key]:
            for ref in package.get('license_texts', []):
                path = ref['path']
                safe_relative(path)
                if path not in files or hashlib.sha256(files[path]).hexdigest() != ref['sha256']:
                    raise ValueError('License inventory content mismatch: ' + path)


def validate_release_files(files):
    if REQUIRED_RELEASE_FILES - set(files):
        raise ValueError('Required installation/release files missing')
    validate_license_inventory(files)


def main():
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((root/'artifacts/releases').resolve()):
        p.error('Output must be under this checkout artifacts/releases')
    spec = json.loads((root/'release/public-files.json').read_text())
    files = collect(root, spec)
    validate_release_files(files)
    report = write_archive(files, output)
    output.with_suffix(output.suffix+'.sha256').write_text(report['sha256']+'  '+output.name+'\n')
    output.with_suffix(output.suffix+'.verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
