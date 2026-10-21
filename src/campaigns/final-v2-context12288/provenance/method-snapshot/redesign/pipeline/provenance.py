"""Capture or verify the predecessor snapshot without modifying historical campaigns."""
import argparse
import gzip
import io
from pathlib import Path
import subprocess
import tarfile

from .inventory import ROOT, digest, encode, read_json, require


REPOSITORY = ROOT.parent
HISTORICAL = {
    'campaigns/windows-abi-v1.tar.gz': '4e09694617f1979eb83799f02898908a161971ed13cc4c012ff8a0783689873a',
    'campaigns/gcc-abi-v2.tar.gz': '735cc4b3db628c685e33fc45d7bb7e99311f5c3e24488b3b8850ea4117b90ce0',
}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPOSITORY)


def capture():
    destination = ROOT / 'provenance'
    require(not (destination / 'start.json').exists(), 'Starting provenance already exists')
    require(all(digest(REPOSITORY / name) == value for name, value in HISTORICAL.items()),
            'Historical archive changed')
    names = ['config.json', 'analysis_plan.md', 'compile.sh', 'requirements.txt', 'pytest.ini']
    for directory in ('pipeline', 'llm', 'ghidra', 'tests', 'documentation/juliet-redesign'):
        names.extend(p.relative_to(REPOSITORY).as_posix()
                     for p in (REPOSITORY / directory).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and p.name != 'test_redesign.py')
    files = {name: digest(REPOSITORY / name) for name in sorted(names)}
    destination.mkdir(parents=True, exist_ok=True)
    archive_path = destination / 'starting-code.tar.gz'
    with archive_path.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for name in files:
                    content = (REPOSITORY / name).read_bytes()
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(content), 0o644
                    archive.addfile(member, io.BytesIO(content))
    patch = destination / 'working-tree.patch'
    patch.write_bytes(git('diff', '--binary', 'HEAD', '--', '.', ':!redesign', ':!tests/test_redesign.py'))
    status = git('status', '--porcelain', '--untracked-files=all').decode().splitlines()
    status = [line for line in status if not line[3:].startswith('redesign/')
              and line[3:] != 'tests/test_redesign.py']
    state = {'schema_version': 2, 'starting_revision': git('rev-parse', 'HEAD').decode().strip(),
             'starting_working_tree': status, 'snapshot_files': files,
             'snapshot_sha256': digest(archive_path), 'tracked_patch_sha256': digest(patch),
             'historical_archives': HISTORICAL,
             'scope': 'Predecessor code/tests/settings and Phase 0 documents; no old corpus or results are new inputs.'}
    (destination / 'start.json').write_text(encode(state))


def verify():
    state = read_json(ROOT / 'provenance/start.json')
    archive_path = ROOT / 'provenance/starting-code.tar.gz'
    require(digest(archive_path) == state['snapshot_sha256'], 'Snapshot changed')
    require(digest(ROOT / 'provenance/working-tree.patch') == state['tracked_patch_sha256'], 'Patch changed')
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        require(len(members) == len(state['snapshot_files']), 'Snapshot member count mismatch')
        import hashlib
        actual = {m.name: hashlib.sha256(archive.extractfile(m).read()).hexdigest()
                  for m in members if m.isfile()}
        require(actual == state['snapshot_files'], 'Snapshot file inventory mismatch')
    require(all(digest(REPOSITORY / name) == value
                for name, value in state['historical_archives'].items()), 'Historical archive changed')
    return {'snapshot_files': len(actual), 'historical_archives': len(state['historical_archives']),
            'status': 'verified'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('capture', 'verify'))
    args = parser.parse_args()
    if args.command == 'capture':
        capture()
    print(encode(verify()), end='')


if __name__ == '__main__':
    main()
