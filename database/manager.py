"""
Database Layer — Structured access with connection pooling, pagination, dedup
"""
import sqlite3, threading, uuid, os
from datetime import datetime
from contextlib import contextmanager
from config import Config
from utils.logger import log

def _get_flask_g():
    """Try to get Flask's g object, return None if outside request context"""
    try:
        from flask import g, has_request_context
        if has_request_context():
            return g
    except Exception:
        pass
    return None

class Database:
    _local = threading.local()  # Fallback for non-Flask context

    @classmethod
    def _get_conn(cls):
        """Get or create connection — uses Flask g if available, else threading.local"""
        g = _get_flask_g()
        if g is not None:
            if not hasattr(g, '_db_conn') or g._db_conn is None:
                g._db_conn = cls._create_conn()
            return g._db_conn
        else:
            if not hasattr(cls._local, 'conn') or cls._local.conn is None:
                cls._local.conn = cls._create_conn()
            return cls._local.conn

    @classmethod
    def _create_conn(cls):
        conn = sqlite3.connect(Config.DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @classmethod
    @contextmanager
    def connection(cls):
        """Get a DB connection — auto-commit, per-request in Flask"""
        conn = cls._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            log.error(f"DB error: {e}")
            raise

    @classmethod
    def close(cls):
        """Close connection — called by Flask teardown"""
        g = _get_flask_g()
        if g is not None:
            conn = getattr(g, '_db_conn', None)
            if conn:
                conn.close()
                g._db_conn = None
        elif hasattr(cls._local, 'conn') and cls._local.conn:
            cls._local.conn.close()
            cls._local.conn = None

    @classmethod
    def init(cls):
        with cls.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    module TEXT NOT NULL,
                    target TEXT NOT NULL,
                    tool TEXT,
                    status TEXT DEFAULT 'running',
                    total_results INTEGER DEFAULT 0,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    duration_sec REAL,
                    error_msg TEXT
                );
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT,
                    type TEXT NOT NULL,
                    confidence REAL DEFAULT 0.5,
                    extra TEXT,
                    found_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1,
                    tags TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_entity TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    confidence REAL DEFAULT 0.5,
                    UNIQUE(source_entity, target_entity, relation_type)
                );
                CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_results_type ON results(type);
                CREATE INDEX IF NOT EXISTS idx_results_value ON results(value);
                CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(started_at);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
                CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
            """)
            # ── Auto-migration: add missing columns to old databases ──
            cls._migrate(conn)
        log.info("Database initialized")

    @classmethod
    def _migrate(cls, conn):
        """Add missing columns from older versions"""
        migrations = [
            ("results", "confidence", "ALTER TABLE results ADD COLUMN confidence REAL DEFAULT 0.5"),
            ("results", "extra", "ALTER TABLE results ADD COLUMN extra TEXT"),
            ("scans", "duration_sec", "ALTER TABLE scans ADD COLUMN duration_sec REAL"),
            ("scans", "error_msg", "ALTER TABLE scans ADD COLUMN error_msg TEXT"),
            ("scans", "notes", "ALTER TABLE scans ADD COLUMN notes TEXT DEFAULT ''"),
            ("scans", "starred", "ALTER TABLE scans ADD COLUMN starred INTEGER DEFAULT 0"),
        ]
        for table, column, sql in migrations:
            try:
                cols = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
                if column not in cols:
                    conn.execute(sql)
                    log.info(f"Migration: added '{column}' to '{table}'")
            except Exception as e:
                log.warning(f"Migration skip ({table}.{column}): {e}")


class ScanDB:
    @staticmethod
    def create(module, target, tool):
        sid = str(uuid.uuid4())[:8]
        with Database.connection() as conn:
            conn.execute(
                "INSERT INTO scans (id,module,target,tool,started_at) VALUES (?,?,?,?,?)",
                (sid, module, target, tool, datetime.now().isoformat()))
        return sid

    @staticmethod
    def finish(sid, status, total, error_msg=None):
        with Database.connection() as conn:
            scan = conn.execute("SELECT started_at FROM scans WHERE id=?", (sid,)).fetchone()
            dur = None
            if scan:
                start = datetime.fromisoformat(scan["started_at"])
                dur = (datetime.now() - start).total_seconds()
            conn.execute(
                "UPDATE scans SET ended_at=?,status=?,total_results=?,duration_sec=?,error_msg=? WHERE id=?",
                (datetime.now().isoformat(), status, total, dur, error_msg, sid))

    @staticmethod
    def get_history(page=1, per_page=50):
        offset = (page - 1) * per_page
        with Database.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            scans = conn.execute(
                "SELECT * FROM scans ORDER BY starred DESC, started_at DESC LIMIT ? OFFSET ?",
                (per_page, offset)).fetchall()
        return {"items": [dict(s) for s in scans], "total": total, "page": page, "pages": (total + per_page - 1) // per_page}

    @staticmethod
    def get(sid):
        """Return scan dict or None if not found"""
        with Database.connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def save_notes(sid, notes):
        with Database.connection() as conn:
            conn.execute("UPDATE scans SET notes=? WHERE id=?", (notes[:2000], sid))

    @staticmethod
    def get_notes(sid):
        with Database.connection() as conn:
            row = conn.execute("SELECT notes FROM scans WHERE id=?", (sid,)).fetchone()
            return row["notes"] if row and row["notes"] else ""

    @staticmethod
    def delete(sid):
        with Database.connection() as conn:
            conn.execute("DELETE FROM results WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))

    @staticmethod
    def toggle_star(sid):
        """Toggle starred status. Returns new state (True=starred, False=unstarred)."""
        with Database.connection() as conn:
            row = conn.execute("SELECT starred FROM scans WHERE id=?", (sid,)).fetchone()
            if not row: return False
            new_state = 0 if row["starred"] else 1
            conn.execute("UPDATE scans SET starred=? WHERE id=?", (new_state, sid))
            return bool(new_state)

    @staticmethod
    def cleanup_old(days=30, keep_starred=True):
        """Delete scans older than N days. Never deletes starred scans if keep_starred=True."""
        from datetime import datetime, timedelta
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with Database.connection() as conn:
            if keep_starred:
                cursor = conn.execute(
                    "DELETE FROM scans WHERE started_at<? AND (starred IS NULL OR starred=0)",
                    (cutoff,))
            else:
                cursor = conn.execute("DELETE FROM scans WHERE started_at<?", (cutoff,))
            # Orphan results cleanup
            conn.execute("DELETE FROM results WHERE scan_id NOT IN (SELECT id FROM scans)")
            return cursor.rowcount

    @staticmethod
    def vacuum():
        """Reclaim disk space after deletions"""
        with Database.connection() as conn:
            conn.execute("VACUUM")

    @staticmethod
    def db_size_mb():
        """Return DB file size in MB"""
        try:
            return round(os.path.getsize(Config.DB_PATH) / (1024 * 1024), 2)
        except Exception:
            return 0.0


class ResultDB:
    @staticmethod
    def add(scan_id, value, source, rtype, confidence=0.5, extra=None):
        with Database.connection() as conn:
            # Dedup check within same scan
            existing = conn.execute(
                "SELECT id FROM results WHERE scan_id=? AND value=? AND type=?",
                (scan_id, value, rtype)).fetchone()
            if existing:
                return False  # Duplicate
            conn.execute(
                "INSERT INTO results (scan_id,value,source,type,confidence,extra,found_at) VALUES (?,?,?,?,?,?,?)",
                (scan_id, value, source, rtype, confidence, extra, datetime.now().isoformat()))
        # Update entity tracking
        EntityDB.upsert(value, rtype)
        return True

    @staticmethod
    def get_by_scan(scan_id, page=1, per_page=100):
        offset = (page - 1) * per_page
        with Database.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM results WHERE scan_id=?", (scan_id,)).fetchone()[0]
            items = conn.execute(
                "SELECT * FROM results WHERE scan_id=? ORDER BY found_at LIMIT ? OFFSET ?",
                (scan_id, per_page, offset)).fetchall()
        return {"items": [dict(r) for r in items], "total": total}

    @staticmethod
    def count_value(value):
        """Count how many times a value appears across all scans"""
        with Database.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as c FROM results WHERE value=?",
                (value,)).fetchone()
            return row["c"] if row else 0

    @staticmethod
    def search(query, rtype=None, limit=100):
        with Database.connection() as conn:
            if rtype:
                items = conn.execute(
                    "SELECT * FROM results WHERE value LIKE ? AND type=? ORDER BY found_at DESC LIMIT ?",
                    (f"%{query}%", rtype, limit)).fetchall()
            else:
                items = conn.execute(
                    "SELECT * FROM results WHERE value LIKE ? ORDER BY found_at DESC LIMIT ?",
                    (f"%{query}%", limit)).fetchall()
        return [dict(r) for r in items]


class EntityDB:
    @staticmethod
    def upsert(value, etype):
        now = datetime.now().isoformat()
        with Database.connection() as conn:
            existing = conn.execute("SELECT id,scan_count FROM entities WHERE value=?", (value,)).fetchone()
            if existing:
                conn.execute("UPDATE entities SET last_seen=?,scan_count=scan_count+1 WHERE id=?",
                            (now, existing["id"]))
            else:
                conn.execute("INSERT INTO entities (value,type,first_seen,last_seen) VALUES (?,?,?,?)",
                            (value, etype, now, now))

    @staticmethod
    def add_relation(src, tgt, rel_type, confidence=0.5):
        with Database.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO relations (source_entity,target_entity,relation_type,confidence) VALUES (?,?,?,?)",
                (src, tgt, rel_type, confidence))

    @staticmethod
    def get_stats():
        with Database.connection() as conn:
            return {
                "total_scans": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
                "total_results": conn.execute("SELECT COUNT(*) FROM results").fetchone()[0],
                "emails": conn.execute("SELECT COUNT(*) FROM results WHERE type='email'").fetchone()[0],
                "usernames": conn.execute("SELECT COUNT(*) FROM results WHERE type='username'").fetchone()[0],
                "metadata": conn.execute("SELECT COUNT(*) FROM results WHERE type='metadata'").fetchone()[0],
                "subdomains": conn.execute("SELECT COUNT(*) FROM results WHERE type='subdomain'").fetchone()[0],
                "entities": conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
                "relations": conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0],
            }
