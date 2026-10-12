"""sqlite: Slack thread sessions + report history (for 'new this hour' and hour-over-hour movers)."""
import json
import sqlite3
import threading
import time

from .config import db_path

_lock = threading.Lock()
MAX_TURN_MESSAGES = 60      # cap stored history per thread
SESSION_TTL_S = 24 * 3600


def _db():
    c = sqlite3.connect(db_path())
    c.execute("CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, updated REAL, messages TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS reports (ts REAL PRIMARY KEY, data TEXT)")
    return c


def load_session(key):
    with _lock, _db() as c:
        row = c.execute("SELECT updated, messages FROM sessions WHERE key=?", (key,)).fetchone()
    if not row or time.time() - row[0] > SESSION_TTL_S:
        return []
    return json.loads(row[1])


def save_session(key, messages):
    if len(messages) > MAX_TURN_MESSAGES:
        return  # thread too long; keep the stored prefix (append-only), caller starts fresh next time
    with _lock, _db() as c:
        c.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?)", (key, time.time(), json.dumps(messages)))


def save_report(data):
    with _lock, _db() as c:
        c.execute("INSERT INTO reports VALUES (?,?)", (time.time(), json.dumps(data)))
        c.execute("DELETE FROM reports WHERE ts < ?", (time.time() - 7 * 86400,))


def recent_reports(n=24):
    with _lock, _db() as c:
        rows = c.execute("SELECT data FROM reports ORDER BY ts DESC LIMIT ?", (n,)).fetchall()
    return [json.loads(r[0]) for r in rows]
