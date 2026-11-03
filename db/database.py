"""
database.py
------------
SQLite storage (one file, no server). Tables follow the project brief:

  packets          lightweight per-packet metadata (NEVER payloads)
  traffic_stats    per-minute aggregates by device / application / protocol / direction
  devices          devices seen on the network (running totals)
  applications     detected applications (running totals)
  health_metrics   periodic health snapshots (score + measured metrics)
  alerts           anomaly alerts

Why aggregates? Storing every packet forever explodes in size. Historical
questions ("how much did I use today?", "which app used the most?") are
answered from the small traffic_stats table instead of scanning millions of
packet rows. Rows are written with UPSERT, so flushing every few seconds
never makes the table grow faster than one row per minute per combination.
"""

import json
import hashlib
import secrets
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from threading import Lock

DEFAULT_PACKET_RETENTION_DAYS = 7


def default_db_path():
    """Return a writable per-user location rather than placing data in source."""
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share")
    return os.path.join(root, "NetInsight", "netinsight.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    timestamp TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_mac TEXT, dst_mac TEXT,
    protocol TEXT, app_protocol TEXT,
    src_port INTEGER, dst_port INTEGER,
    packet_size INTEGER, ttl INTEGER, tcp_flags TEXT,
    application TEXT, domain TEXT, direction TEXT,
    transport_protocol TEXT, payload_len INTEGER, seq INTEGER, ack INTEGER,
    icmp_type INTEGER, arp_op INTEGER, dns_json TEXT, sni TEXT, http_host TEXT,
    app_method TEXT, confidence TEXT, family TEXT,
    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    time_window TEXT NOT NULL,
    device TEXT NOT NULL DEFAULT '',
    application TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    direction TEXT NOT NULL DEFAULT '',
    packet_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    UNIQUE (time_window, device, application, protocol, direction),
    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_key TEXT PRIMARY KEY,
    name TEXT, ip TEXT, mac TEXT, hostname TEXT, vendor TEXT,
    first_seen TEXT, last_seen TEXT,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, packets INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS applications (
    name TEXT PRIMARY KEY,
    first_seen TEXT, last_seen TEXT,
    total_bytes INTEGER DEFAULT 0, total_packets INTEGER DEFAULT 0, last_domain TEXT
);
CREATE TABLE IF NOT EXISTS health_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    timestamp TEXT NOT NULL,
    score INTEGER, latency_ms REAL, packet_loss_pct REAL, retransmission_pct REAL,
    dup_ack_pct REAL, dns_latency_ms REAL, conn_failure_pct REAL, bandwidth_util_pct REAL,
    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    timestamp TEXT NOT NULL,
    severity TEXT, metric TEXT, title TEXT, message TEXT, details TEXT,
    resolved_at TEXT,
    event_id INTEGER,
    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS monitoring_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    interface_name TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    error TEXT,
    metadata_json TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    generated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready',
    snapshot_json TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    detected_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source TEXT,
    resolved_at TEXT,
    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_src_dst ON packets(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_window ON traffic_stats(time_window);
CREATE INDEX IF NOT EXISTS idx_health_ts ON health_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_reports_user_time ON reports(user_id, generated_at DESC);
"""


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _minute_str(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M")


class Database:
    def __init__(self, db_path=None, packet_retention_days=DEFAULT_PACKET_RETENTION_DAYS):
        self.db_path = db_path or default_db_path()
        if packet_retention_days < 1:
            raise ValueError("packet_retention_days must be at least 1")
        self.packet_retention_days = int(packet_retention_days)
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._lock = Lock()
        # Another NetInsight process may briefly hold the database while it
        # flushes. Wait for that transaction instead of failing the worker
        # thread immediately with "database is locked".
        self._conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.DatabaseError:
            pass
        self._migrate_phase1()
        self._conn.executescript(SCHEMA)
        self._add_missing_columns("packets", {
            "session_id": "INTEGER", "application": "TEXT", "domain": "TEXT", "direction": "TEXT",
            "transport_protocol": "TEXT", "payload_len": "INTEGER", "seq": "INTEGER", "ack": "INTEGER",
            "icmp_type": "INTEGER", "arp_op": "INTEGER", "dns_json": "TEXT", "sni": "TEXT",
            "http_host": "TEXT", "app_method": "TEXT", "confidence": "TEXT", "family": "TEXT",
        })
        self._add_missing_columns("traffic_stats", {"session_id": "INTEGER"})
        self._add_missing_columns("health_metrics", {"session_id": "INTEGER"})
        self._add_missing_columns("alerts", {"session_id": "INTEGER", "event_id": "INTEGER"})
        self._conn.executescript("""
            CREATE INDEX IF NOT EXISTS idx_packets_session_timestamp ON packets(session_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_session_window ON traffic_stats(session_id, time_window);
            CREATE INDEX IF NOT EXISTS idx_events_session_time ON network_events(session_id, detected_at);
        """)
        self._conn.commit()

    # ---- users and reports ---------------------------------------------
    @staticmethod
    def _password_hash(password, salt=None):
        salt = salt or secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
        return f"{salt}${digest.hex()}"

    def create_user(self, email, password):
        if not email or len(password or "") < 8:
            raise ValueError("email and a password of at least 8 characters are required")
        now = _iso(datetime.now(timezone.utc).timestamp())
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO users (email, password_hash, created_at, last_seen_at) VALUES (?,?,?,?)",
                (email.strip().lower(), self._password_hash(password), now, now))
            self._conn.commit()
            return {"id": cur.lastrowid, "email": email.strip().lower()}

    def authenticate_user(self, email, password):
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
            if not row:
                return None
            salt, expected = row["password_hash"].split("$", 1)
            actual = self._password_hash(password, salt).split("$", 1)[1]
            if not secrets.compare_digest(actual, expected):
                return None
            self._conn.execute("UPDATE users SET last_seen_at = ? WHERE id = ?",
                               (_iso(datetime.now(timezone.utc).timestamp()), row["id"]))
            self._conn.commit()
            return {"id": row["id"], "email": row["email"]}

    def user_by_id(self, user_id):
        with self._lock:
            row = self._conn.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def user_by_email(self, email):
        with self._lock:
            row = self._conn.execute("SELECT id, email FROM users WHERE email = ?",
                                     (email.strip().lower(),)).fetchone()
        return dict(row) if row else None

    def create_report(self, user_id, snapshot):
        now = _iso(datetime.now(timezone.utc).timestamp())
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO reports (user_id, generated_at, status, snapshot_json) VALUES (?,?,?,?)",
                (user_id, now, "ready", json.dumps(snapshot, separators=(",", ":"))))
            self._conn.commit()
            return {"id": cur.lastrowid, "report_id": f"RPT-{cur.lastrowid:06d}",
                    "generated_at": now, "status": "ready", "snapshot": snapshot}

    def list_reports(self, user_id):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, generated_at, status, snapshot_json FROM reports WHERE user_id = ? "
                "ORDER BY generated_at DESC", (user_id,)).fetchall()
        out = []
        for row in rows:
            snapshot = json.loads(row["snapshot_json"])
            out.append({"id": row["id"], "report_id": f"RPT-{row['id']:06d}",
                        "generated_at": row["generated_at"], "status": row["status"],
                        "health_score": snapshot.get("health", {}).get("score"),
                        "snapshot": snapshot})
        return out

    def get_report(self, user_id, report_id):
        try:
            report_id = int(report_id.removeprefix("RPT-"))
        except (AttributeError, ValueError):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT id, generated_at, status, snapshot_json FROM reports WHERE id = ? AND user_id = ?",
                (report_id, user_id)).fetchone()
        if not row:
            return None
        return {"id": row["id"], "report_id": f"RPT-{row['id']:06d}",
                "generated_at": row["generated_at"], "status": row["status"],
                "snapshot": json.loads(row["snapshot_json"])}

    # ---- sessions ------------------------------------------------------
    def create_session(self, interface_name=None, metadata=None):
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO monitoring_sessions
                   (started_at, interface_name, status, metadata_json) VALUES (?,?,?,?)""",
                (_iso(datetime.now(timezone.utc).timestamp()), interface_name, "running",
                 json.dumps(metadata or {}, separators=(",", ":"))))
            self._conn.commit()
            return cur.lastrowid

    def complete_session(self, session_id, status="completed", error=None):
        if status not in ("completed", "failed"):
            raise ValueError("session completion status must be completed or failed")
        with self._lock:
            self._conn.execute(
                "UPDATE monitoring_sessions SET ended_at=?, status=?, error=? WHERE id=?",
                (_iso(datetime.now(timezone.utc).timestamp()), status, error, session_id))
            self._conn.commit()

    def session(self, session_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM monitoring_sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    # ---- schema upgrades (so a teammate's old Phase 1 .db still works) ----
    def _columns(self, table):
        return {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}

    def _migrate_phase1(self):
        cols = self._columns("traffic_stats")
        if cols and "device" not in cols:     # old Phase 1 layout: keep it under a new name
            self._conn.execute("ALTER TABLE traffic_stats RENAME TO traffic_stats_phase1")

    def _add_missing_columns(self, table, wanted):
        have = self._columns(table)
        for name, typ in wanted.items():
            if name not in have:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")

    # ---- writes ---------------------------------------------------------
    def insert_packets_batch(self, records):
        if not records:
            return
        rows = [(r.get("session_id"), r["timestamp"], r["src_ip"], r["dst_ip"], r["src_mac"], r["dst_mac"], r["protocol"],
                 r.get("app_protocol"), r["src_port"], r["dst_port"], r["packet_size"], r["ttl"],
                 r["tcp_flags"], r.get("app"), r.get("domain"), r.get("direction"), r.get("protocol"),
                 r.get("payload_len"), r.get("seq"), r.get("ack"), r.get("icmp_type"), r.get("arp_op"),
                 json.dumps(r.get("dns"), separators=(",", ":")) if r.get("dns") else None,
                 r.get("sni"), r.get("http_host"), r.get("app_method"), r.get("confidence"),
                 r.get("family")) for r in records]
        with self._lock:
            self._conn.executemany(
                """INSERT INTO packets
                   (session_id, timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol, app_protocol,
                    src_port, dst_port, packet_size, ttl, tcp_flags, application, domain, direction,
                    transport_protocol, payload_len, seq, ack, icmp_type, arp_op, dns_json, sni,
                    http_host, app_method, confidence, family)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            self._conn.commit()

    def flush_usage(self, minute_cells, app_delta, now, session_id=None):
        """minute_cells: {(minute, device, app, proto, dir): [packets, bytes]}"""
        rows = [(session_id, _minute_str(m * 60), dev, app, proto, d, cell[0], cell[1])
                for (m, dev, app, proto, d), cell in minute_cells.items()]
        iso = _iso(now)
        with self._lock:
            self._conn.executemany(
                """INSERT INTO traffic_stats
                   (session_id, time_window, device, application, protocol, direction, packet_count, total_bytes)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(time_window, device, application, protocol, direction)
                   DO UPDATE SET packet_count = packet_count + excluded.packet_count,
                                 total_bytes = total_bytes + excluded.total_bytes""", rows)
            for app, (b, p, domain) in app_delta.items():
                self._conn.execute(
                    """INSERT INTO applications (name, first_seen, last_seen, total_bytes, total_packets, last_domain)
                       VALUES (?,?,?,?,?,?)
                       ON CONFLICT(name) DO UPDATE SET last_seen = excluded.last_seen,
                           total_bytes = total_bytes + excluded.total_bytes,
                           total_packets = total_packets + excluded.total_packets,
                           last_domain = COALESCE(excluded.last_domain, last_domain)""",
                    (app, iso, iso, b, p, domain))
            self._conn.commit()

    def upsert_devices(self, devices):
        with self._lock:
            for d in devices:
                self._conn.execute(
                    """INSERT INTO devices (device_key, name, ip, mac, hostname, vendor, first_seen, last_seen,
                           bytes_in, bytes_out, packets) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(device_key) DO UPDATE SET name=excluded.name, ip=excluded.ip, mac=excluded.mac,
                           hostname=excluded.hostname, vendor=excluded.vendor, last_seen=excluded.last_seen,
                           bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out,
                           packets = packets + excluded.packets""",
                    (d["key"], d["name"], d["ip"], d["mac"], d["hostname"], d["vendor"],
                     _iso(d["first_seen"]), _iso(d["last_seen"]), d["bytes_in"], d["bytes_out"], d["packets"]))
            self._conn.commit()

    def insert_health(self, ts, h, session_id=None):
        m = h["metrics"]
        with self._lock:
            self._conn.execute(
                """INSERT INTO health_metrics (session_id, timestamp, score, latency_ms, packet_loss_pct, retransmission_pct,
                   dup_ack_pct, dns_latency_ms, conn_failure_pct, bandwidth_util_pct) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (session_id, _iso(ts), h["score"], m["latency_ms"], m["packet_loss_pct"], m["retransmission_pct"],
                 m["dup_ack_pct"], m["dns_latency_ms"], m["conn_failure_pct"], m["bandwidth_util_pct"]))
            self._conn.commit()

    def insert_alert(self, alert, session_id=None):
        details = json.dumps({k: alert[k] for k in ("rate", "baseline", "ratio", "z", "causes", "context", "advice", "reason")
                              if k in alert}, separators=(",", ":"))
        with self._lock:
            event = self._conn.execute(
                """INSERT INTO network_events
                   (session_id, detected_at, event_type, severity, description, evidence_json, source)
                   VALUES (?,?,?,?,?,?,?)""",
                (session_id, _iso(alert["ts"]), alert["metric"], alert["severity"],
                 alert["message"], details, "statistical-anomaly"))
            cur = self._conn.execute(
                """INSERT INTO alerts
                   (session_id, timestamp, severity, metric, title, message, details, event_id)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (session_id, _iso(alert["ts"]), alert["severity"], alert["metric"],
                 alert["title"], alert["message"], details, event.lastrowid))
            self._conn.commit()
            return cur.lastrowid

    def resolve_alert(self, db_id, ts):
        with self._lock:
            resolved = _iso(ts)
            self._conn.execute("UPDATE alerts SET resolved_at=? WHERE id=?", (resolved, db_id))
            self._conn.execute(
                """UPDATE network_events SET resolved_at=?
                   WHERE id=(SELECT event_id FROM alerts WHERE id=?)""", (resolved, db_id))
            self._conn.commit()

    def prune_packets(self, keep=200_000, now=None):
        cutoff = _iso((now or datetime.now(timezone.utc).timestamp()) -
                      self.packet_retention_days * 86400)
        with self._lock:
            self._conn.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
            row = self._conn.execute("SELECT MAX(id) AS m FROM packets").fetchone()
            if row and row["m"] and row["m"] > keep:
                self._conn.execute("DELETE FROM packets WHERE id <= ?", (row["m"] - keep,))
            self._conn.commit()

    def cleanup_expired_packets(self, now=None):
        """Remove packet metadata only; aggregates, sessions and events remain."""
        cutoff = _iso((now or datetime.now(timezone.utc).timestamp()) -
                      self.packet_retention_days * 86400)
        with self._lock:
            cur = self._conn.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
            return cur.rowcount

    def query_packets(self, session_id=None, start=None, end=None, limit=200):
        """Return lightweight packet metadata for the inspector/history tools."""
        if limit < 1:
            raise ValueError("limit must be positive")
        clauses, params = [], []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            clauses.append("timestamp < ?")
            params.append(end)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(min(int(limit), 10_000))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM packets{where} ORDER BY timestamp DESC, id DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def traffic_series(self, session_id=None, start=None, end=None):
        """Return stored aggregates in chronological order."""
        clauses, params = [], []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if start is not None:
            clauses.append("time_window >= ?")
            params.append(start)
        if end is not None:
            clauses.append("time_window < ?")
            params.append(end)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT * FROM traffic_stats{where}
                    ORDER BY time_window ASC, id ASC""", params
            ).fetchall()
        return [dict(row) for row in rows]

    def insert_event(self, session_id, detected_at, event_type, severity, description, evidence, source):
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO network_events
                   (session_id, detected_at, event_type, severity, description, evidence_json, source)
                   VALUES (?,?,?,?,?,?,?)""",
                (session_id, _iso(detected_at), event_type, severity, description,
                 json.dumps(evidence or {}, separators=(",", ":")), source))
            self._conn.commit()
            return cur.lastrowid

    # ---- reads (history) -------------------------------------------------
    @staticmethod
    def _start_for(range_key, now):
        if range_key == "today":
            d = datetime.fromtimestamp(now, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            return d.strftime("%Y-%m-%dT%H:%M")
        days = {"24h": 1, "7d": 7, "30d": 30}.get(range_key, 1)
        return _minute_str(now - days * 86400)

    def _group(self, column, start, limit=10):
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT {column} AS name, SUM(total_bytes) AS bytes, SUM(packet_count) AS packets
                    FROM traffic_stats WHERE time_window >= ? AND {column} != ''
                    GROUP BY {column} ORDER BY bytes DESC LIMIT ?""", (start, limit)).fetchall()
        total = sum(r["bytes"] for r in rows) or 1
        return [{"name": r["name"], "bytes": r["bytes"], "packets": r["packets"],
                 "percent": round(100.0 * r["bytes"] / total, 1)} for r in rows]

    def history_summary(self, range_key, now):
        start = self._start_for(range_key, now)
        with self._lock:
            dirs = {r["direction"]: r["b"] for r in self._conn.execute(
                "SELECT direction, SUM(total_bytes) AS b FROM traffic_stats WHERE time_window >= ? GROUP BY direction",
                (start,))}
        return {
            "range": range_key,
            "bytes_in": dirs.get("in", 0) or 0, "bytes_out": dirs.get("out", 0) or 0,
            "bytes_local": dirs.get("local", 0) or 0,
            "applications": self._group("application", start),
            "devices": self._group("device", start),
            "protocols": self._group("protocol", start),
        }

    def history_timeline(self, granularity, now):
        """granularity: minutes (last 60), hours (last 24), days (last 7)."""
        cfg = {"minutes": (60, 60, 16, "%Y-%m-%dT%H:%M"),
               "hours": (24, 3600, 13, "%Y-%m-%dT%H"),
               "days": (7, 86400, 10, "%Y-%m-%d")}[granularity]
        count, step, plen, fmt = cfg
        end = datetime.fromtimestamp(now, timezone.utc)
        buckets = []
        if granularity == "minutes":
            base = end.replace(second=0, microsecond=0)
            buckets = [base - timedelta(minutes=i) for i in range(count - 1, -1, -1)]
        elif granularity == "hours":
            base = end.replace(minute=0, second=0, microsecond=0)
            buckets = [base - timedelta(hours=i) for i in range(count - 1, -1, -1)]
        else:
            base = end.replace(hour=0, minute=0, second=0, microsecond=0)
            buckets = [base - timedelta(days=i) for i in range(count - 1, -1, -1)]
        keys = [b.strftime(fmt) for b in buckets]
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT substr(time_window,1,{plen}) AS b, direction, SUM(total_bytes) AS bytes
                    FROM traffic_stats WHERE time_window >= ? GROUP BY b, direction""", (keys[0],)).fetchall()
        data = {k: {"in": 0, "out": 0, "local": 0} for k in keys}
        for r in rows:
            if r["b"] in data and r["direction"] in data[r["b"]]:
                data[r["b"]][r["direction"]] = r["bytes"]
        return [{"bucket": k, "in": data[k]["in"], "out": data[k]["out"], "local": data[k]["local"]} for k in keys]

    def history_health(self, granularity, now):
        plen = {"minutes": 16, "hours": 13, "days": 10}[granularity]
        span = {"minutes": 3600, "hours": 86400, "days": 7 * 86400}[granularity]
        start = _iso(now - span)
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT substr(timestamp,1,{plen}) AS b, AVG(score) AS score, AVG(latency_ms) AS latency_ms,
                           AVG(packet_loss_pct) AS packet_loss_pct, AVG(dns_latency_ms) AS dns_latency_ms
                    FROM health_metrics WHERE timestamp >= ? GROUP BY b ORDER BY b""", (start,)).fetchall()
        return [dict(r) for r in rows]

    def history_answers(self, now):
        """Direct answers to the questions in the project brief."""
        start = self._start_for("today", now)
        summ = self.history_summary("today", now)
        with self._lock:
            slow = self._conn.execute(
                """SELECT substr(timestamp,1,16) AS m, AVG(latency_ms) AS v FROM health_metrics
                   WHERE timestamp >= ? AND latency_ms IS NOT NULL GROUP BY m ORDER BY v DESC LIMIT 1""", (start,)).fetchone()
            loss = self._conn.execute(
                """SELECT substr(timestamp,1,16) AS m, AVG(packet_loss_pct) AS v FROM health_metrics
                   WHERE timestamp >= ? AND packet_loss_pct IS NOT NULL GROUP BY m ORDER BY v DESC LIMIT 1""", (start,)).fetchone()
        named_apps = [a for a in summ["applications"]]
        return {
            "traffic_today": {"bytes_in": summ["bytes_in"], "bytes_out": summ["bytes_out"],
                              "total": summ["bytes_in"] + summ["bytes_out"] + summ["bytes_local"]},
            "top_application": named_apps[0] if named_apps else None,
            "top_device": summ["devices"][0] if summ["devices"] else None,
            "slowest_minute": {"time": slow["m"], "latency_ms": round(slow["v"], 1)} if slow else None,
            "highest_loss_minute": {"time": loss["m"], "packet_loss_pct": round(loss["v"], 2)} if loss else None,
        }

    def total_packet_count(self):
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) AS c FROM packets").fetchone()["c"]

    def close(self):
        with self._lock:
            self._conn.close()
