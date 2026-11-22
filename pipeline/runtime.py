"""Runtime identity primitives; all inputs are supplied by the caller."""
import hashlib
import os
from pathlib import Path
import subprocess

from . import run_llm
from redesign.pipeline.inventory import require

def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def process_identity(pid, command):
    proc = Path('/proc') / str(pid)
    actual = (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    require(actual == command, 'Live server command differs from the recorded command')
    # PID reuse and a replaced executable cannot silently pass as the same server.
    start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    return {'pid': pid, 'start_ticks': start, 'binary_sha256': digest(proc / 'exe')}


def owns_listener(pid, port):
    sockets = set()
    for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        if link.startswith('socket:['):
            sockets.add(link[8:-1])
    for filename in ('/proc/net/tcp', '/proc/net/tcp6'):
        for line in Path(filename).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and int(fields[1].split(':')[-1], 16) == port and fields[9] in sockets:
                return True
    return False


def props_identity(props):
    return {key: props[key] for key in ('model_alias', 'model_path', 'build_info', 'total_slots',
                                       'default_generation_settings', 'chat_template')}


def model_stat(path):
    stat = path.stat()
    return {key: getattr(stat, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def source_identity(home):
    try:
        revision = subprocess.check_output(['git', '-C', str(home), 'rev-parse', 'HEAD'], text=True,
                                           stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(['git', '-C', str(home), 'status', '--porcelain'], text=True))
    except subprocess.CalledProcessError:
        revision, dirty = None, None
    files = {}
    for directory in ('src', 'common', 'tools/server', 'ggml/src', 'include'):
        for path in sorted((home / directory).rglob('*')):
            if path.is_file():
                files[path.relative_to(home).as_posix()] = digest(path)
    return {'git_revision': revision, 'git_dirty': dirty,
            'source_tree_sha256': hashlib.sha256(run_llm.canonical_json(files).encode()).hexdigest(),
            'source_files': len(files)}
