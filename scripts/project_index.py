#!/usr/bin/env python3
"""Regenerate/verify a metadata-only SQLite index using the local source catalog."""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from archive_projects import ROOT, MANIFEST, ARCHIVE, RETAINED, digest, require

CATALOG = ROOT / 'work/step33_catalog.json'
DATABASE = ROOT / 'work/project_index.sqlite'


def current_artifacts():
    excluded = {'repo', 'rom', 'archives', 'step31_tools', '__pycache__'}
    files = []
    for base in (ROOT / 'work', ROOT / 'scripts'):
        for p in base.rglob('*'):
            rel = p.relative_to(ROOT)
            if any(part in excluded or part.startswith('ghidra') for part in rel.parts):
                continue
            if p == DATABASE or p.name.startswith('.project_index-') or p.is_dir():
                continue
            if p.is_symlink():
                raise ValueError(f'Unexpected symlink {p}')
            files.append(p)
    files += list(ROOT.glob('*.md'))
    return sorted(set(files))


def build(destination):
    catalog = json.loads(CATALOG.read_text())
    manifest = json.loads(MANIFEST.read_text())
    require(digest(ARCHIVE) == manifest['archive_sha256'], 'Archive SHA256 mismatch')
    con = sqlite3.connect(destination)
    con.executescript('''
      PRAGMA page_size=4096;
      PRAGMA foreign_keys=ON;
      CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE stages(id TEXT PRIMARY KEY, number INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('retained','rejected','replaced')),
        availability TEXT NOT NULL, report TEXT, proof TEXT, proof_sha256 TEXT,
        notes TEXT NOT NULL);
      CREATE TABLE artifacts(path TEXT PRIMARY KEY, kind TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('retained','rejected','replaced')),
        size INTEGER, sha256 TEXT, archive_path TEXT, archive_member TEXT);
      CREATE TABLE stage_artifacts(stage_id TEXT REFERENCES stages(id),
        path TEXT REFERENCES artifacts(path), role TEXT NOT NULL,
        PRIMARY KEY(stage_id,path,role));
      CREATE VIEW proofs AS SELECT id,proof,proof_sha256 FROM stages WHERE proof IS NOT NULL;
      CREATE VIEW reports_and_reviews AS SELECT s.stage_id,a.path,s.role
        FROM stage_artifacts s JOIN artifacts a USING(path)
        WHERE s.role IN ('report','review');
    ''')
    for k, v in sorted(dict(schema='1', catalog_sha256=digest(CATALOG),
                            archive_manifest_sha256=digest(MANIFEST),
                            coverage='Steps 1-7: no persisted step reports; steps 8-33 indexed',
                            statuses='Evidence files retained; stage outcome and project status tracked separately').items()):
        con.execute('INSERT INTO metadata VALUES (?,?)', (k, v))
    for p in current_artifacts():
        con.execute('INSERT INTO artifacts VALUES (?,?,?,?,?,?,?)',
                    (p.relative_to(ROOT).as_posix(), 'file', 'retained', p.stat().st_size, digest(p), None, None))
    # All archive members get their original logical path plus an explicit physical locator.
    for row in manifest['projects']:
        for e in row['entries']:
            con.execute('INSERT INTO artifacts VALUES (?,?,?,?,?,?,?)',
                        (e['path'], e['kind'], row['status'], e.get('size'), e.get('sha256'),
                         manifest['archive'], e['path']))
    for e in manifest['retained']:
        con.execute('INSERT INTO artifacts VALUES (?,?,?,?,?,?,?)',
                    (e['path'], e['kind'], 'retained', e.get('size'), e.get('sha256'), None, None))
    available = {r[0] for r in con.execute('SELECT path FROM artifacts')}
    for row in catalog['stages']:
        report, proof = row.get('report'), row.get('proof')
        for p in (report, proof, *row.get('reviews', [])):
            if p and p not in available:
                raise ValueError(f'Catalog points to missing file: {p}')
        con.execute('INSERT INTO stages VALUES (?,?,?,?,?,?,?,?)',
                    (row['id'], row['number'], row['status'], row['availability'], report, proof,
                     digest(ROOT / proof) if proof else None, row.get('notes', '')))
        links = set()
        for path in available:
            if any(path.startswith(prefix) for prefix in row.get('prefixes', [])):
                links.add((row['id'], path, 'artifact'))
        for p in row.get('files', []):
            if p not in available:
                raise ValueError(f'Explicit catalog file missing: {p}')
            links.add((row['id'], p, 'artifact'))
        for role, paths in [('report', [report]), ('proof', [proof]), ('review', row.get('reviews', []))]:
            links.update((row['id'], p, role) for p in paths if p)
        con.executemany('INSERT INTO stage_artifacts VALUES (?,?,?)', sorted(links))
    require(con.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SQLite integrity failure')
    require(not con.execute('PRAGMA foreign_key_check').fetchall(), 'Foreign key failure')
    con.commit()
    con.close()
    Path(destination).chmod(0o600)


def verify():
    # Rebuilding checks every live hash/path, source catalog, archive locator, link and schema.
    with tempfile.TemporaryDirectory(prefix='gs-index-') as directory:
        candidate = Path(directory) / 'index.sqlite'
        build(candidate)
        require(candidate.read_bytes() == DATABASE.read_bytes(), 'Index stale or tampered; regenerate')
    con = sqlite3.connect(f'file:{DATABASE}?mode=ro', uri=True)
    result = dict(stages=con.execute('SELECT count(*) FROM stages').fetchone()[0],
                  artifacts=con.execute('SELECT count(*) FROM artifacts').fetchone()[0],
                  links=con.execute('SELECT count(*) FROM stage_artifacts').fetchone()[0],
                  sha256=digest(DATABASE))
    con.close()
    return result


def regenerate():
    fd, name = tempfile.mkstemp(prefix='.project_index-', dir=DATABASE.parent)
    os.close(fd)
    try:
        build(name)
        os.replace(name, DATABASE)
    finally:
        Path(name).unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'verify'])
    args = parser.parse_args()
    if args.action == 'build':
        regenerate()
    print(json.dumps(verify(), sort_keys=True))
