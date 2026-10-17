#!/usr/bin/env python3
"""Offline, private, verified archival of superseded Ghidra projects. Never opens Ghidra."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'work/archives/step33'
MANIFEST = DEST / 'manifest.json'
ARCHIVE = DEST / 'projects.tar.gz'
RETAINED = 'work/ghidra_thumb_special_pair_scoped'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def dump(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    path.chmod(0o600)


def snapshot(directory):
    result = []
    for p in [directory, *sorted(directory.rglob('*'))]:
        if p.is_symlink() or not (p.is_dir() or p.is_file()):
            raise ValueError(f'Unsupported entry: {p}')
        s = p.stat()
        row = dict(path=p.relative_to(ROOT).as_posix(), kind='dir' if p.is_dir() else 'file',
                   mode=s.st_mode & 0o7777, mtime_ns=s.st_mtime_ns)
        if p.is_file():
            row.update(size=s.st_size, sha256=digest(p))
        result.append(row)
    return result


def no_ghidra():
    for p in Path('/proc').glob('[0-9]*/cmdline'):
        if int(p.parent.name) == os.getpid():
            continue
        try:
            args = p.read_bytes().split(b'\0')
        except (OSError, PermissionError):
            continue
        # Match executable/Java arguments, not shell scripts containing this check.
        if args and (b'analyzeHeadless' in args[0] or
                     (b'java' in args[0] and any(b'ghidra.' in a for a in args))):
            raise ValueError(f'Ghidra process active: {p.parent.name}')
    if list((ROOT / 'work').glob('ghidra*/**/*.lock*')):
        raise ValueError('Ghidra lock present')


def prepare():
    no_ghidra()
    if DEST.exists():
        raise ValueError('Archive destination already exists')
    projects = sorted(p for p in (ROOT / 'work').glob('ghidra*') if p.is_dir())
    require(ROOT / RETAINED in projects, 'Retained project missing')
    rows = []
    for p in projects:
        if p == ROOT / RETAINED:
            continue
        name = p.name
        rejected = name == 'ghidra_thumb_literal_medium'  # only explicit rejection (step21.md); other probes are unpromoted, status replaced
        status = 'rejected' if rejected else 'replaced'
        role = 'unpromoted experiment' if ('probe' in name or name == 'ghidra_shared_annotated') else 'historical project'
        rows.append(dict(path=p.relative_to(ROOT).as_posix(), status=status, role=role,
                         status_basis='work/step21_attempt.md' if name == 'ghidra_thumb_literal_medium' else
                         'work/step26.md' if name == 'ghidra_thumb_special_pair_probe' else
                         'RUN_STATE.md: sole currently retained project', entries=snapshot(p)))
    protected = []
    for p in sorted((ROOT / 'work').rglob('*.json')):
        rel = p.relative_to(ROOT)
        if any(x.startswith('ghidra') or x in ('repo', 'rom', 'archives') or
               x.endswith(('_private', '_tools')) for x in rel.parts):
            continue
        protected.append(dict(path=rel.as_posix(), sha256=digest(p)))
    allocated = sum(p.lstat().st_blocks * 512 for row in rows
                    for p in [ROOT / row['path'], *(ROOT / row['path']).rglob('*')])
    DEST.mkdir(parents=True, mode=0o700)
    DEST.chmod(0o700)
    try:
        write_archive(rows, protected, allocated)
    except BaseException:
        shutil.rmtree(DEST)  # created by this call; a failed run must not block a retry
        raise


def write_archive(rows, protected, allocated):
    partial = DEST / 'projects.partial'
    # Fixed gzip header and explicit per-entry order make a retry reproducible.
    with partial.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for row in rows:
                for entry in row['entries']:
                    tar.add(ROOT / entry['path'], arcname=entry['path'], recursive=False)
    partial.chmod(0o600)
    partial.rename(ARCHIVE)
    data = dict(schema=1, archive=ARCHIVE.relative_to(ROOT).as_posix(),
                archive_sha256=digest(ARCHIVE), projects=rows, retained=snapshot(ROOT / RETAINED),
                protected_json=protected, source_allocated_bytes=allocated,
                source_file_bytes=sum(e.get('size', 0) for r in rows for e in r['entries']))
    dump(MANIFEST, data)
    verify(require_live=True)


def verify(require_live=False, check_protected=True, check_retained=True):
    data = json.loads(MANIFEST.read_text())
    require(digest(ARCHIVE) == data['archive_sha256'], 'Archive SHA256 mismatch')
    expected = {e['path']: e for r in data['projects'] for e in r['entries']}
    seen = set()
    with tarfile.open(ARCHIVE, 'r|gz') as tar:
        for member in tar:
            require(member.name in expected and member.name not in seen, member.name)
            e = expected[member.name]
            require(member.mode == e['mode'], member.name)
            require(member.isdir() if e['kind'] == 'dir' else member.isfile(), member.name)
            # PAX/tarfile uses a float; exact nanoseconds are preserved in the manifest.
            require(abs(member.mtime * 1_000_000_000 - e['mtime_ns']) <= 1024, member.name)
            if member.isfile():
                require(member.size == e['size'], member.name)
                require(hashlib.file_digest(tar.extractfile(member), 'sha256').hexdigest() == e['sha256'], member.name)
            seen.add(member.name)
    require(seen == set(expected), 'Missing archive members')
    for row in data['projects']:
        p = ROOT / row['path']
        if require_live:
            require(snapshot(p) == row['entries'], f'Live project changed: {p}')
        elif p.exists():
            # A half-deleted project (interrupted prune) is a verified subset of the manifest.
            known = {e['path']: e for e in row['entries']}
            def same(e):
                k = known.get(e['path'])
                # A directory's mtime changes when children are removed; compare identity and mode only.
                if k and e['kind'] == 'dir':
                    return k['kind'] == 'dir' and k['mode'] == e['mode']
                return k == e
            require(all(same(e) for e in snapshot(p)), f'Live project changed: {p}')
    if check_retained:
        require(snapshot(ROOT / RETAINED) == data['retained'], 'Retained project changed')
    if check_protected:
        for row in data['protected_json']:
            if row['path'] == 'work/step33_catalog.json':
                continue  # lot 33's own working file, edited after prepare
            require(digest(ROOT / row['path']) == row['sha256'], row['path'])
    return data


def prune():
    no_ghidra()
    data = verify()  # tolerates projects already removed or half-removed by an interrupted prune
    # Finish all checks before deleting the first project. Retained is excluded twice.
    paths = [ROOT / r['path'] for r in data['projects']]
    require(all(p.parent == ROOT / 'work' and p.name.startswith('ghidra') and p != ROOT / RETAINED for p in paths), 'Unsafe prune path')
    for p in paths:
        if p.exists():
            shutil.rmtree(p)
    verify()
    dump(DEST / 'prune_receipt.json', dict(archive_sha256=data['archive_sha256'],
         removed_projects=[r['path'] for r in data['projects']],
         source_allocated_bytes=data['source_allocated_bytes'],
         archive_allocated_bytes=ARCHIVE.stat().st_blocks * 512,
         net_project_bytes_freed=data['source_allocated_bytes'] - ARCHIVE.stat().st_blocks * 512))


def restore(name, destination):
    data = verify(check_protected=False, check_retained=False)
    row = next((r for r in data['projects'] if Path(r['path']).name == name), None)
    require(row is not None, f'Unknown project: {name}')
    out = Path(destination).resolve()
    # Restoration is deliberately confined outside the current work/ tree.
    require(out != ROOT and ROOT not in out.parents, 'Restore outside the project')
    require(not out.exists(), 'Destination already exists')
    out.mkdir(parents=True, mode=0o700)
    prefix = row['path'] + '/'
    with tarfile.open(ARCHIVE, 'r|gz') as tar:
        for member in tar:
            if member.name == row['path']:
                continue
            if not member.name.startswith(prefix):
                continue
            rel = Path(member.name[len(prefix):])
            require(not rel.is_absolute() and '..' not in rel.parts, 'Unsafe restore path')
            p = out / rel
            if member.isdir():
                p.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with p.open('xb') as f:
                    shutil.copyfileobj(tar.extractfile(member), f)
                p.chmod(member.mode)
    for e in reversed(row['entries']):
        p = out / Path(e['path']).relative_to(row['path'])
        p.chmod(e['mode'])
        os.utime(p, ns=(e['mtime_ns'], e['mtime_ns']))
    expected = {e['path'] for e in row['entries']}
    actual = {row['path']} | {row['path'] + '/' + p.relative_to(out).as_posix() for p in out.rglob('*')}
    require(expected == actual, 'Restored tree differs')
    for e in row['entries']:
        p = out / Path(e['path']).relative_to(row['path'])
        s = p.stat()
        require(s.st_mode & 0o7777 == e['mode'] and s.st_mtime_ns == e['mtime_ns'], str(p))
        require(p.is_dir() if e['kind'] == 'dir' else p.is_file(), str(p))
        if e['kind'] == 'file':
            require(s.st_size == e['size'] and digest(p) == e['sha256'], str(p))
    print(f'Restored and hash-verified: {name} -> {out}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'verify', 'prune', 'restore'])
    parser.add_argument('--project')
    parser.add_argument('--destination')
    args = parser.parse_args()
    if args.action == 'restore':
        if not args.project or not args.destination:
            parser.error('restore requires --project and --destination')
        restore(args.project, args.destination)
    else:
        result = {'prepare': prepare, 'verify': verify, 'prune': prune}[args.action]()
        print(f'{args.action}: verified')
