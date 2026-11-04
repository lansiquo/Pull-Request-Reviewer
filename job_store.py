"""Single-host durable work queue; payloads contain identifiers, never credentials."""
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
import sqlite3
import time


class JobStore:
    MAX_ATTEMPTS = 8
    def __init__(self, path):
        self.path = Path(path)
        shared = os.getenv("PRSEC_SHARED_STATE", "0") == "1"
        if shared:
            # Provisioned by the operator: two separate service UIDs share only
            # this queue group, not credentials or the worker's Docker socket.
            parent = self.path.parent
            mode = stat.S_IMODE(parent.stat().st_mode) if parent.is_dir() else 0
            # macOS inherits the directory group without setgid; Linux needs it.
            if mode & 0o777 != 0o770 or (sys.platform == "linux" and not mode & stat.S_ISGID):
                raise RuntimeError("Shared queue requires a pre-provisioned group directory (2770 on Linux)")
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o660)
            except FileExistsError:
                if self.path.is_symlink() or stat.S_IMODE(self.path.stat().st_mode) != 0o660:
                    raise RuntimeError("Shared queue database must be a regular mode-660 file")
            else:
                try:
                    os.fchmod(fd, 0o660)
                finally:
                    os.close(fd)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            if db.execute('PRAGMA user_version').fetchone()[0] > 1:
                raise RuntimeError('Queue schema is newer than this application')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone():
                columns = {row[1] for row in db.execute('PRAGMA table_info(jobs)')}
                if not {'id','payload','state','attempts','check_id','updated','retry_at','error'}.issubset(columns):
                    raise RuntimeError('Queue schema requires an unsupported migration')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS worker_backoff (id INTEGER PRIMARY KEY, retry_at REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS worker_health (id INTEGER PRIMARY KEY, updated REAL NOT NULL)')
            db.execute('''CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, check_id INTEGER,
                updated REAL NOT NULL, retry_at REAL NOT NULL DEFAULT 0,
                error TEXT)''')
            db.execute('PRAGMA user_version=1')
        if not shared:
            self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, payload, capacity=100):
        encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        key = hashlib.sha256(encoded.encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT state FROM jobs WHERE id=?', (key,)).fetchone()
            if existing:
                return key, False
            db.execute("DELETE FROM jobs WHERE state='done' AND updated<?", (time.time() - 30 * 86400,))
            if db.execute('SELECT count(*) FROM jobs').fetchone()[0] >= 10000:
                raise OverflowError('Queue storage limit exceeded')
            active = db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0]
            if active >= capacity:
                raise OverflowError('Queue capacity exceeded')
            db.execute('INSERT INTO jobs(id,payload,state,updated) VALUES (?, ?, ?, ?)',
                       (key, encoded, 'queued', time.time()))
        return key, True

    def expand(self, parent, payloads, capacity=100):
        """Commit all children and complete the expansion event in one transaction."""
        encoded = {hashlib.sha256((value := json.dumps(p, sort_keys=True, separators=(',', ':'))).encode()).hexdigest(): value for p in payloads}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            state = db.execute('SELECT state FROM jobs WHERE id=?', (parent,)).fetchone()
            if not state or state[0] != 'running': return False
            new = {key: value for key, value in encoded.items() if not db.execute('SELECT 1 FROM jobs WHERE id=?', (key,)).fetchone()}
            active = db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0]
            total = db.execute('SELECT count(*) FROM jobs').fetchone()[0]
            if active - 1 + len(new) > capacity or total + len(new) > 10000:
                raise OverflowError('Queue capacity exceeded during push expansion')
            for key, value in new.items():
                db.execute('INSERT INTO jobs(id,payload,state,updated) VALUES (?,?,?,?)', (key,value,'queued',time.time()))
            db.execute("UPDATE jobs SET state='done',error=NULL,updated=? WHERE id=?", (time.time(),parent))
        return True

    def quarantine_legacy(self):
        count = 0
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT id,payload FROM jobs WHERE state IN ('queued','running')").fetchall():
                reason = None
                try:
                    payload = json.loads(row['payload'])
                    if not isinstance(payload, dict): raise ValueError()
                    if payload.get('kind') != 'base_push' and not re.fullmatch('[0-9a-f]{40}', payload.get('base_sha', '')):
                        reason = 'legacy_base_context_missing'
                except (ValueError, TypeError):
                    reason = 'malformed_job_payload'
                if reason:
                    db.execute("UPDATE jobs SET state='failed',error=?,updated=? WHERE id=?", (reason,time.time(),row['id']))
                    count += 1
        return count

    def recover(self):
        # Called only while holding the exclusive worker lock.
        self.quarantine_legacy()
        with self.connect() as db:
            db.execute("UPDATE jobs SET state='failed',error='retry_exhausted:interrupted',updated=? WHERE state='running' AND attempts>=?", (time.time(), self.MAX_ATTEMPTS))
            db.execute("UPDATE jobs SET state='queued', updated=? WHERE state='running'", (time.time(),))

    def claim(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            blocked = db.execute('SELECT retry_at FROM worker_backoff WHERE id=1').fetchone()
            if blocked and blocked[0] > time.time():
                return None
            row = db.execute("SELECT * FROM jobs WHERE state='queued' AND retry_at<=? ORDER BY updated LIMIT 1",
                             (time.time(),)).fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET state='running',attempts=attempts+1,updated=? WHERE id=?",
                       (time.time(), row['id']))
            job = dict(row)
            job['payload'] = json.loads(job['payload'])
            job['attempts'] += 1
            return job

    def set_check(self, key, check_id):
        with self.connect() as db:
            db.execute('UPDATE jobs SET check_id=?,updated=? WHERE id=?', (check_id, time.time(), key))

    def finish(self, key):
        with self.connect() as db:
            db.execute("UPDATE jobs SET state='done',error=NULL,updated=? WHERE id=?", (time.time(), key))

    def retry(self, key, error, retry_after=None):
        # Bound retries across restarts; terminal jobs need explicit local recovery.
        with self.connect() as db:
            row = db.execute('SELECT attempts FROM jobs WHERE id=?', (key,)).fetchone()
            delay = min(300, 5 * 2 ** min(row['attempts'], 6))
            if retry_after is not None:
                delay = max(delay, retry_after)
                db.execute('INSERT INTO worker_backoff(id,retry_at) VALUES (1,?) ON CONFLICT(id) DO UPDATE SET retry_at=MAX(retry_at,excluded.retry_at)', (time.time() + delay,))
            if row['attempts'] >= self.MAX_ATTEMPTS:
                db.execute("UPDATE jobs SET state='failed',error=?,updated=? WHERE id=?",
                           (('retry_exhausted:' + error)[:80], time.time(), key))
                return False
            db.execute("UPDATE jobs SET state='queued',error=?,retry_at=?,updated=? WHERE id=?",
                       (error[:80], time.time() + delay, time.time(), key))
            return True

    def fail(self, key, reason):
        with self.connect() as db:
            db.execute("UPDATE jobs SET state='failed',error=?,updated=? WHERE id=?",
                       (reason[:80], time.time(), key))

    def requeue_failed(self, key, capacity=100):
        """Explicit operator recovery only; retain Check identity to avoid duplicates."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT state FROM jobs WHERE id=?', (key,)).fetchone()
            if not row or row['state'] != 'failed':
                return False
            if db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0] >= capacity:
                raise OverflowError('Queue capacity exceeded')
            db.execute("UPDATE jobs SET state='queued',attempts=0,retry_at=0,error=NULL,updated=? WHERE id=?",
                       (time.time(), key))
            return True

    def status(self):
        with self.connect() as db:
            counts = {state: 0 for state in ('queued', 'running', 'done', 'failed')}
            counts.update({row[0]: row[1] for row in db.execute('SELECT state,count(*) FROM jobs GROUP BY state')})
            blocked = db.execute('SELECT retry_at FROM worker_backoff WHERE id=1').fetchone()
            failures = [dict(row) for row in db.execute(
                "SELECT id,attempts,check_id,error,updated FROM jobs WHERE state='failed' ORDER BY updated DESC LIMIT 20")]
        return {'counts': counts, 'needs_attention': counts['failed'] > 0,
                'worker_alive': self.ready(),
                'cooldown_until': blocked[0] if blocked and blocked[0] > time.time() else None,
                'recent_failures': failures}

    def heartbeat(self):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO worker_health(id,updated) VALUES (1,?)', (time.time(),))

    def ready(self):
        with self.connect() as db:
            row = db.execute('SELECT updated FROM worker_health WHERE id=1').fetchone()
            return bool(row and time.time() - row[0] < 300)
