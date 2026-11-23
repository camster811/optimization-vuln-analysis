"""Byte formats and failure boundaries shared by the retained methods."""
import os
import stat
from pathlib import Path
import subprocess
import sys

import pytest

from optimization_vuln_analysis.common import artifacts, serialization
from optimization_vuln_analysis.inference import runtime as llm_runtime
from optimization_vuln_analysis.studies.representation import runner


def test_named_formats_preserve_unicode_key_order_and_newline_contracts():
    value = {'z': 'λ', 'a': 'line\n'}
    compact = '{"a":"line\\n","z":"λ"}'
    assert serialization.request_json(value) == compact
    assert serialization.canonical_json(value) == compact+'\n'
    assert serialization.report_json(value) == (compact+'\n').encode('utf-8')
    assert serialization.journal_json(value) == '{"a":"line\\n","z":"\\u03bb"}\n'
    assert serialization.inventory_json(value) == '{\n  "a": "line\\n",\n  "z": "λ"\n}\n'


@pytest.mark.parametrize('profile', [serialization.request_json, serialization.canonical_json,
    serialization.journal_json, serialization.report_json, serialization.inventory_json])
@pytest.mark.parametrize('number', [float('nan'), float('inf'), -float('inf')])
def test_all_profiles_reject_nonfinite_values(profile, number):
    with pytest.raises(ValueError):
        profile({'nested': [number]})


@pytest.mark.parametrize('text', ['{"x":1,"x":2}', '{"a":{"x":1,"x":2}}',
    '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}'])
def test_strict_json_rejects_ambiguous_nested_keys_and_nonfinite_values(text):
    with pytest.raises(ValueError):
        serialization.strict_json(text)


def test_raw_journals_retain_surrogates_and_canonical_utf8_does_not_repair_them(tmp_path):
    value = {'raw': '\ud800', 'text': 'λ'}
    path = tmp_path/'response.json'
    runner._publish(path, value, journal=True)
    assert path.read_bytes() == b'{"raw":"\\ud800","text":"\\u03bb"}\n'
    assert serialization.read_json(path) == value
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    with pytest.raises(UnicodeEncodeError):
        llm_runtime.write_new(tmp_path/'canonical.json', value)
    assert not (tmp_path/'canonical.json').exists()


def test_create_once_syncs_complete_bytes_before_linking_and_then_syncs_directory(tmp_path, monkeypatch):
    path = tmp_path/'record'
    sync, link, events = os.fsync, os.link, []

    def checked_sync(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        events.append('directory_synced' if directory else 'file_synced')
        assert path.exists() == directory
        return sync(fd)

    def checked_link(source, destination):
        assert Path(source).read_bytes() == b'complete\x00\xff\n'
        assert not path.exists()
        events.append('linked')
        return link(source, destination)

    monkeypatch.setattr(artifacts.os, 'fsync', checked_sync)
    monkeypatch.setattr(artifacts.os, 'link', checked_link)
    artifacts.publish_bytes(path, b'complete\x00\xff\n')
    assert events == ['file_synced', 'linked', 'directory_synced']
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob('.pending-*'))


def test_publication_never_replaces_existing_evidence_and_cleans_caught_errors(tmp_path):
    path = tmp_path/'record'
    artifacts.publish_bytes(path, b'original')
    with pytest.raises(FileExistsError):
        artifacts.publish_bytes(path, b'replacement')
    assert path.read_bytes() == b'original'
    with pytest.raises(RuntimeError):
        with artifacts.create_once(tmp_path/'failed') as stream:
            stream.write(b'partial')
            raise RuntimeError('Interrupted writer')
    assert not (tmp_path/'failed').exists()
    assert not list(tmp_path.glob('.pending-*'))


def test_process_interruption_leaves_uncommitted_bytes_without_adopting_them(tmp_path):
    path = tmp_path/'record'
    code = '''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from optimization_vuln_analysis.common.artifacts import create_once
with create_once(Path(sys.argv[2])) as stream:
    stream.write(b'uncommitted'); stream.flush(); os.fsync(stream.fileno())
    os._exit(17)
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
        str(Path(__file__).resolve().parents[1]/'src'), str(path)], timeout=30)
    assert result.returncode == 17
    pending, = tmp_path.glob('.pending-*')
    assert pending.read_bytes() == b'uncommitted' and not path.exists()
    artifacts.publish_bytes(path, b'committed')
    assert path.read_bytes() == b'committed'
    assert pending.read_bytes() == b'uncommitted'


@pytest.mark.parametrize('name', ['', '../escape', '/absolute', 'x/../escape', 'x//y', 'x\\y', 'C:drive'])
def test_relative_paths_reject_escape_and_noncanonical_spellings(tmp_path, name):
    with pytest.raises(ValueError):
        artifacts.local_path(tmp_path, name)


def test_containment_plain_files_and_inventories_keep_their_symlink_boundaries(tmp_path):
    root = tmp_path/'root'
    root.mkdir()
    (root/'record').write_bytes(b'data')
    (root/'alias').symlink_to(root/'record')
    assert artifacts.local_path(root, 'alias') == root/'alias'
    with pytest.raises(ValueError, match='Symlink'):
        artifacts.plain_file(root, 'alias')
    with pytest.raises(ValueError, match='symlinks'):
        artifacts.file_inventory(root)
    (root/'outside').symlink_to(tmp_path)
    with pytest.raises(ValueError, match='External path'):
        artifacts.local_path(root, 'outside/record')


def test_inventory_rejects_nonregular_inputs(tmp_path):
    os.mkfifo(tmp_path/'pipe')
    with pytest.raises(ValueError, match='Nonregular'):
        artifacts.file_inventory(tmp_path)


def test_common_imports_do_not_load_runtime_or_study_modules():
    code = '''import sys
sys.path.insert(0,sys.argv[1])
from optimization_vuln_analysis.common import artifacts,serialization
assert not any(n.startswith(('pipeline','optimization_vuln_analysis.inputs','optimization_vuln_analysis.studies')) for n in sys.modules)
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
        str(Path(__file__).resolve().parents[1]/'src')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
