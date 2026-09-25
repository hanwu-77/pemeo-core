import hashlib, importlib.util, json, zipfile
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('pemeo_export', Path(__file__).with_name('export_source.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

@pytest.mark.parametrize('path', ['../outside.txt', '/absolute.txt', '.env', '.local/config.json', 'node_modules/pkg/a.js', 'user.key', 'a/../b', 'a\\b'])
def test_rejects_private_or_escaping_mapping(path):
    with pytest.raises(ValueError): m.safe_relative(path)

def test_unlisted_private_file_never_enters_archive(tmp_path):
    (tmp_path/'README.md').write_text('public')
    (tmp_path/'.env').write_text('secret-value')
    files=m.collect(tmp_path,{'files':[{'source':'README.md','target':'README.md'}]})
    out=tmp_path/'a.zip';m.write_archive(files,out)
    with zipfile.ZipFile(out) as z:
        assert set(z.namelist()) == {'README.md','MANIFEST.sha256'}
        assert 'secret-value' not in z.read('README.md').decode()

@pytest.mark.parametrize('body', ['/'+'Users/'+'example/private', '-----BEGIN '+'PRIVATE KEY-----', 'ghp_'+'A'*40])
def test_rejects_sensitive_content_without_echo(body,tmp_path):
    (tmp_path/'x.txt').write_text(body)
    with pytest.raises(ValueError) as exc:
        m.collect(tmp_path,{'files':[{'source':'x.txt','target':'x.txt'}]})
    assert body not in str(exc.value)

def test_symlink_to_unlisted_file_rejected(tmp_path):
    (tmp_path/'secret').write_text('secret')
    (tmp_path/'link.txt').symlink_to(tmp_path/'secret')
    with pytest.raises(ValueError):m.collect(tmp_path,{'files':[{'source':'link.txt','target':'link.txt'}]})

def test_duplicate_target_rejected(tmp_path):
    (tmp_path/'x').write_text('public')
    with pytest.raises(ValueError):m.collect(tmp_path,{'files':[{'source':'x','target':'x'}]*2})

def test_reproducible_manifest_and_no_overwrite(tmp_path):
    files={'README.md':b'public','LICENSE':b'license'}
    one=tmp_path/'one.zip';two=tmp_path/'two.zip'
    m.write_archive(files,one);m.write_archive(files,two)
    assert one.read_bytes()==two.read_bytes()
    with zipfile.ZipFile(one) as z:
        for line in z.read('MANIFEST.sha256').decode().splitlines():
            h,n=line.split('  ',1);assert hashlib.sha256(z.read(n)).hexdigest()==h
    with pytest.raises(FileExistsError):m.write_archive(files,one)

@pytest.mark.parametrize('missing', ['docker-compose.yml', 'docker-compose.i2.yml', 'requirements-bootstrap.lock'])
def test_release_cannot_omit_database_configuration(missing):
    files={n:b'synthetic' for n in m.REQUIRED_RELEASE_FILES}
    files.pop(missing)
    with pytest.raises(ValueError):m.validate_release_files(files)

@pytest.mark.parametrize('fault', ['missing', 'overwritten', 'escaping'])
def test_license_reference_corruption_blocks_release(fault):
    path = 'third_party/licenses/tool/LICENSE'
    ref = {'path': path, 'sha256': hashlib.sha256(b'original').hexdigest()}
    files = {path: b'original'}
    if fault == 'missing': files.pop(path)
    if fault == 'overwritten': files[path] = b'another vendor notice'
    if fault == 'escaping': ref['path'] = '../outside'
    files['third_party/TOOLS.json'] = json.dumps({'tools': [{'license_texts': [ref]}]}).encode()
    files['third_party/DEPENDENCIES.json'] = b'{"packages": []}'
    with pytest.raises(ValueError): m.validate_license_inventory(files)

def test_real_release_inventory_references_match_exported_notices():
    root = Path(__file__).resolve().parents[1]
    files = m.collect(root, json.loads((root/'release/public-files.json').read_text()))
    m.validate_release_files(files)
