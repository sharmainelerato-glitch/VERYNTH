"""Trusted code *inside* the container. Never run on the NESSON application host."""
import ast
import io
import os
import pathlib
import subprocess
import sys
import zipfile

ROOT = pathlib.Path('/work/repository')
LIMIT_FILE_COUNT = 300
LIMIT_UNCOMPRESSED = 8 * 1024 * 1024


def extract():
    raw = pathlib.Path('/input/repository.zip').read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('Archive too large')
    ROOT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos = z.infolist()
        if not infos or len(infos) > LIMIT_FILE_COUNT:
            raise ValueError('Invalid archive file count')
        total = 0
        seen = set()
        for info in infos:
            path = info.filename
            rel = pathlib.PurePosixPath(path)
            if (not path or '\\' in path or '\x00' in path or path.startswith('/')
                or any(p in ('', '..', '.') for p in path.split('/') if p != '' )
                or ':' in path or path.startswith('~')):
                raise ValueError('Unsafe archive path')
            if any(part in ('.', '..') for part in rel.parts) or len(rel.parts) > 16:
                raise ValueError('Unsafe archive path')
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Symlink not allowed')
            key = path.rstrip('/')
            if key in seen:
                raise ValueError('Duplicate path')
            seen.add(key)
            if info.is_dir():
                continue
            total += info.file_size
            if info.file_size > 1024 * 1024 or total > LIMIT_UNCOMPRESSED:
                raise ValueError('Archive expansion limit')
            target = ROOT.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, target.open('wb') as dest:
                content = src.read(1024 * 1024 + 1)
                if len(content) != info.file_size:
                    raise ValueError('Incorrect archive size')
                dest.write(content)
    return len([i for i in infos if not i.is_dir()])


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('pytest', 'unittest'):
        raise SystemExit(64)
    try:
        count = extract()
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print('Archive validation failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(65)
    print('Validated files: ' + str(count), flush=True)
    os.chdir(ROOT)
    if sys.argv[1] == 'pytest':
        cmd = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider']
    else:
        cmd = [sys.executable, '-m', 'unittest', 'discover', '-s', '.', '-p', 'test_*.py', '-v']
    p = subprocess.run(cmd, env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME':'/tmp',
                                 'PYTHONDONTWRITEBYTECODE':'1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1'},
                       stdin=subprocess.DEVNULL, timeout=100, check=False)
    raise SystemExit(p.returncode if 0 <= p.returncode <= 125 else 125)

if __name__ == '__main__':
    main()
