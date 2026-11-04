"""Consistent SQLite snapshots to new files; never imports app or contacts GitHub."""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

REQUIRED={'jobs':{'id','payload','state','attempts','check_id','updated','retry_at','error'},
          'worker_health':{'id','updated'},'worker_backoff':{'id','retry_at'}}


def readonly(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Expected an existing regular queue file')
    return sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=5)


def inspect_connection(db):
    version=db.execute('PRAGMA user_version').fetchone()[0]
    if version not in {0,1}:raise ValueError('Unsupported queue schema version')
    if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Queue integrity check failed')
    for table,columns in REQUIRED.items():
        actual={row[1] for row in db.execute(f'PRAGMA table_info({table})')}
        if not columns.issubset(actual):raise ValueError('Queue schema is incomplete')
    counts={row[0]:row[1] for row in db.execute('SELECT state,count(*) FROM jobs GROUP BY state')}
    if set(counts)-{'queued','running','done','failed'}:raise ValueError('Unknown queue state')
    legacy=0;invalid=0
    for encoded,state in db.execute("SELECT payload,state FROM jobs WHERE state IN ('queued','running')"):
        try:
            p=json.loads(encoded)
            if not isinstance(p,dict):raise ValueError()
            if p.get('kind')!='base_push' and not re.fullmatch('[0-9a-f]{40}',p.get('base_sha','')):legacy+=1
        except (ValueError,TypeError):invalid+=1
    return {'schema_version':version,'integrity':'ok','counts':counts,'legacy_active':legacy,'invalid_active':invalid}


def inspect_queue(path):
    db=readonly(path)
    try:return inspect_connection(db)
    finally:db.close()


def snapshot(source,target):
    """Backup API captures WAL commits. Publish atomically, never overwrite."""
    target=Path(target)
    if target.exists() or target.is_symlink() or any(Path(str(target)+suffix).exists() for suffix in ('-wal','-shm')):
        raise FileExistsError('Destination must be new and have no SQLite sidecars')
    source_db=readonly(source)
    temporary=None
    try:
        inspect_connection(source_db)
        fd,name=tempfile.mkstemp(prefix='.queue-snapshot-',dir=target.parent);os.close(fd);temporary=Path(name)
        destination=sqlite3.connect(temporary)
        started=time.monotonic()
        def progress(*args):
            if time.monotonic()-started>10:raise TimeoutError('Snapshot exceeded time budget')
        try:
            source_db.backup(destination,pages=128,progress=progress,sleep=.05)
            result=inspect_connection(destination)
        finally:destination.close()
        with temporary.open('rb') as file:os.fsync(file.fileno())
        os.link(temporary,target)  # Atomic publication; existing targets cannot be replaced.
        return result
    finally:
        source_db.close()
        if temporary is not None:temporary.unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    read=sub.add_parser('inspect');read.add_argument('source')
    for action in ('backup','restore'):
        cmd=sub.add_parser(action);cmd.add_argument('source');cmd.add_argument('target')
    args=parser.parse_args()
    try:result=inspect_queue(args.source) if args.action=='inspect' else snapshot(args.source,args.target)
    except (ValueError,OSError,sqlite3.Error) as error:
        parser.exit(1,f'Queue operation refused: {type(error).__name__}. Check schema, integrity and paths; no destination was overwritten.\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
