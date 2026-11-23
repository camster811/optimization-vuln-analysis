"""Paths, hashes and create-once binary artifacts without study policy."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import tempfile

from . import require


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bytes_digest(raw):
    return hashlib.sha256(raw).hexdigest()


def local_path(root, name):
    require(isinstance(name, str) and name, 'Missing relative path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and '\\' not in name
            and ':' not in name and path.as_posix() == name, f'Unsafe path: {name}')
    result = root/name
    require(result.resolve().is_relative_to(root.resolve()), f'External path: {name}')
    return result


def plain_file(root, name):
    path = local_path(root, name)
    require(path.is_file(), f'Missing input: {name}')
    require(all(not p.is_symlink() for p in (path, *path.parents) if p != root.parent),
            f'Symlink input: {name}')
    return path


def file_inventory(directory, *, symlink_error='Artifact symlinks are not allowed',
                   nonregular_error='Nonregular artifact input'):
    nodes = list(Path(directory).rglob('*'))
    require(not any(p.is_symlink() for p in nodes), symlink_error)
    require(all(p.is_dir() or p.is_file() for p in nodes), nonregular_error)
    return {p.relative_to(directory).as_posix(): digest(p) for p in sorted(nodes) if p.is_file()}


@contextmanager
def create_once(path, *, prefix='.pending-', mode=None):
    """Sync a complete file before linking it into place, without replacement.

    Python exceptions remove the temporary file. Process interruption can leave
    it behind for the caller's recovery rules; this primitive never adopts it.
    Callers choose final permission policy and serialize content before writing.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=prefix)
    try:
        with os.fdopen(fd, 'wb') as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        if mode is not None:
            path.chmod(mode)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def publish_bytes(path, raw):
    """Publish exact bytes; strings and JSON belong in serialization adapters."""
    with create_once(path) as stream:
        stream.write(raw)
