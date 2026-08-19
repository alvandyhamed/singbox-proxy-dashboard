import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from .config import settings

_local = threading.local()
_write_lock = threading.Lock()

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS subscriptions (
  id                INTEGER PRIMARY KEY,
  name              TEXT    NOT NULL,
  url               TEXT    NOT NULL UNIQUE,
  user_agent        TEXT,
  format            TEXT,
  added_at          INTEGER NOT NULL,
  last_fetch_at     INTEGER,
  last_fetch_ok     INTEGER,
  last_fetch_via    TEXT,
  last_error        TEXT,
  update_interval_h INTEGER,
  quota_total       INTEGER,
  quota_upload      INTEGER,
  quota_download    INTEGER,
  expires_at        INTEGER,
  is_active         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS servers (
  id              INTEGER PRIMARY KEY,
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  identity_hash   TEXT    NOT NULL,
  outbound_tag    TEXT    NOT NULL UNIQUE,
  label           TEXT,
  protocol        TEXT    NOT NULL,
  server_host     TEXT    NOT NULL,
  server_port     INTEGER NOT NULL,
  outbound_json   TEXT    NOT NULL,
  raw_uri         TEXT    NOT NULL,
  parse_warning   TEXT,
  first_seen_at   INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  is_present      INTEGER NOT NULL DEFAULT 1,
  last_ok_at      INTEGER,
  UNIQUE (subscription_id, identity_hash)
);

CREATE TABLE IF NOT EXISTS fetch_log (
  id              INTEGER PRIMARY KEY,
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  ts              INTEGER NOT NULL,
  ok              INTEGER NOT NULL,
  via             TEXT,
  user_agent      TEXT,
  http_status     INTEGER,
  server_count    INTEGER,
  diff_summary    TEXT,
  error           TEXT
);

CREATE TABLE IF NOT EXISTS traffic_samples (
  ts          INTEGER PRIMARY KEY,
  up_bytes    INTEGER NOT NULL,
  down_bytes  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS host_traffic (
  bucket_ts   INTEGER NOT NULL,
  host        TEXT    NOT NULL,
  attributed  INTEGER NOT NULL,
  outbound    TEXT    NOT NULL DEFAULT '',
  up_bytes    INTEGER NOT NULL,
  down_bytes  INTEGER NOT NULL,
  conn_count  INTEGER NOT NULL,
  PRIMARY KEY (bucket_ts, host, outbound)
);

CREATE TABLE IF NOT EXISTS connections (
  id           TEXT PRIMARY KEY,
  host         TEXT,
  dest_ip      TEXT,
  dest_port    INTEGER,
  network      TEXT,
  outbound     TEXT,
  matched_rule TEXT,
  started_at   INTEGER NOT NULL,
  ended_at     INTEGER,
  up_bytes     INTEGER NOT NULL DEFAULT 0,
  down_bytes   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_conn_started ON connections(started_at);
CREATE INDEX IF NOT EXISTS idx_conn_host    ON connections(host, started_at);

CREATE TABLE IF NOT EXISTS host_daily (
  day         TEXT    NOT NULL,
  host        TEXT    NOT NULL,
  outbound    TEXT    NOT NULL DEFAULT '',
  up_bytes    INTEGER NOT NULL,
  down_bytes  INTEGER NOT NULL,
  conn_count  INTEGER NOT NULL,
  PRIMARY KEY (day, host, outbound)
);

CREATE TABLE IF NOT EXISTS rules (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  value      TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  note       TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id      INTEGER PRIMARY KEY,
  ts      INTEGER NOT NULL,
  action  TEXT    NOT NULL,
  detail  TEXT,
  ok      INTEGER NOT NULL,
  src_ip  TEXT
);

CREATE TABLE IF NOT EXISTS health_checks (
  ts         INTEGER PRIMARY KEY,
  ok         INTEGER NOT NULL,
  latency_ms INTEGER,
  target     TEXT,
  error      TEXT
);

CREATE TABLE IF NOT EXISTS server_net_samples (
  ts        INTEGER PRIMARY KEY,
  rx_bytes  INTEGER NOT NULL,
  tx_bytes  INTEGER NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = _connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


@contextmanager
def get_db():
    """Per-request read connection (no locking needed for reads in WAL)."""
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_write_db():
    """Serialised write connection."""
    with _write_lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def run_retention() -> None:
    """Nightly retention: roll up old host_traffic, trim old rows."""
    import time

    now = int(time.time())
    seven_days = now - 7 * 86400
    thirty_days = now - 30 * 86400
    ninety_days = now - 90 * 86400

    with get_write_db() as conn:
        # Aggregate host_traffic older than 7 days into host_daily
        conn.execute("""
            INSERT OR REPLACE INTO host_daily (day, host, outbound, up_bytes, down_bytes, conn_count)
            SELECT
                strftime('%Y-%m-%d', bucket_ts, 'unixepoch') as day,
                host, outbound,
                SUM(up_bytes), SUM(down_bytes), SUM(conn_count)
            FROM host_traffic
            WHERE bucket_ts < ?
            GROUP BY day, host, outbound
        """, (seven_days,))
        conn.execute("DELETE FROM host_traffic WHERE bucket_ts < ?", (seven_days,))
        conn.execute("DELETE FROM connections WHERE ended_at IS NOT NULL AND ended_at < ?", (thirty_days,))
        conn.execute("DELETE FROM traffic_samples WHERE ts < ?", (seven_days,))
        conn.execute("DELETE FROM health_checks WHERE ts < ?", (ninety_days,))
        conn.execute("DELETE FROM server_net_samples WHERE ts < ?", (ninety_days,))
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
