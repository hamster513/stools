"""Bounded metadata-only scan: never follows links or reads file contents."""
import os
import stat
import time
from pathlib import Path


def file_module(relative: Path) -> str:
    first = relative.parts[0]
    return {'ad': 'ad', 'ksc': 'ksc', 'vm': 'vm', 'archives': 'siem',
            'siem': 'siem', 'toolbox': 'toolbox', 'attack': 'attack', 'assets': 'assets'}.get(first, 'platform')


def measure_files(root: Path, *, max_entries: int = 100_000, max_seconds: float = 5) -> dict:
    result = {'bytes': None, 'modules': {}, 'complete': True, 'symlinks': 0, 'files': 0}
    if not root.is_dir() or root.is_symlink():
        return {**result, 'complete': False}
    result['bytes'] = 0
    stack, seen, entries = [root], set(), 0
    deadline = time.monotonic() + max_seconds
    while stack:
        directory = stack.pop()
        descriptor = None
        try:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            with os.scandir(descriptor) as children:
                for child in children:
                    entries += 1
                    if entries > max_entries or time.monotonic() >= deadline:
                        return {**result, 'complete': False}
                    try:
                        info = child.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            result['symlinks'] += 1
                        elif stat.S_ISDIR(info.st_mode):
                            stack.append(directory / child.name)
                        elif stat.S_ISREG(info.st_mode):
                            identity = info.st_dev, info.st_ino
                            if identity in seen:
                                continue
                            seen.add(identity)
                            size = info.st_blocks * 512 if hasattr(info, 'st_blocks') else info.st_size
                            module = file_module((directory / child.name).relative_to(root))
                            result['modules'][module] = result['modules'].get(module, 0) + size
                            result['bytes'] += size
                            result['files'] += 1
                    except OSError:
                        result['complete'] = False
        except OSError:
            result['complete'] = False
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return result
