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
import sqlite3
from datetime import datetime, timedelta
from threading import Lock

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_mac TEXT, dst_mac TEXT,
    protocol TEXT, app_protocol TEXT,
    src_port INTEGER, dst_port INTEGER,
    packet_size INTEGER, ttl INTEGER, tcp_flags TEXT,
    application TEXT, domain TEXT, direction TEXT
);
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time_window TEXT NOT NULL,
    device TEXT NOT NULL DEFAULT '',
    application TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    direction TEXT NOT NULL DEFAULT '',
    packet_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    UNIQUE (time_window, device, application, protocol, direction)
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
    timestamp TEXT NOT NULL,
    score INTEGER, latency_ms REAL, packet_loss_pct REAL, retransmission_pct REAL,
    dup_ack_pct REAL, dns_latency_ms REAL, conn_failure_pct REAL, bandwidth_util_pct REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT, metric TEXT, title TEXT, message TEXT, details TEXT,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_traffic_window ON traffic_stats(time_window);
CREATE INDEX IF NOT EXISTS idx_health_ts ON health_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
"""


def _iso(ts):
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")


def _minute_str(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:%M")


class Database:
    def __init__(self, db_path="netinsight.db"):
        self.db_path = db_path
        self._lock = Lock()
        # Another NetInsight process may briefly hold the database while it
        # flushes. Wait for that transaction instead of failing the worker
        # thread immediately with "database is locked".
        self._conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.DatabaseError:
            pass
        self._migrate_phase1()
        self._conn.executescript(SCHEMA)
        self._add_missing_columns("packets", {"application": "TEXT", "domain": "TEXT", "direction": "TEXT"})
        self._conn.commit()

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
        rows = [(r["timestamp"], r["src_ip"], r["dst_ip"], r["src_mac"], r["dst_mac"], r["protocol"],
                 r.get("app_protocol"), r["src_port"], r["dst_port"], r["packet_size"], r["ttl"],
                 r["tcp_flags"], r.get("app"), r.get("domain"), r.get("direction")) for r in records]
        with self._lock:
            self._conn.executemany(
                """INSERT INTO packets (timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol, app_protocol,
                   src_port, dst_port, packet_size, ttl, tcp_flags, application, domain, direction)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            self._conn.commit()

    def flush_usage(self, minute_cells, app_delta, now):
        """minute_cells: {(minute, device, app, proto, dir): [packets, bytes]}"""
        rows = [(_minute_str(m * 60), dev, app, proto, d, cell[0], cell[1])
                for (m, dev, app, proto, d), cell in minute_cells.items()]
        iso = _iso(now)
        with self._lock:
            self._conn.executemany(
                """INSERT INTO traffic_stats (time_window, device, application, protocol, direction, packet_count, total_bytes)
                   VALUES (?,?,?,?,?,?,?)
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

    def insert_health(self, ts, h):
        m = h["metrics"]
        with self._lock:
            self._conn.execute(
                """INSERT INTO health_metrics (timestamp, score, latency_ms, packet_loss_pct, retransmission_pct,
                   dup_ack_pct, dns_latency_ms, conn_failure_pct, bandwidth_util_pct) VALUES (?,?,?,?,?,?,?,?,?)""",
                (_iso(ts), h["score"], m["latency_ms"], m["packet_loss_pct"], m["retransmission_pct"],
                 m["dup_ack_pct"], m["dns_latency_ms"], m["conn_failure_pct"], m["bandwidth_util_pct"]))
            self._conn.commit()

    def insert_alert(self, alert):
        details = json.dumps({k: alert[k] for k in ("rate", "baseline", "ratio", "z", "causes", "context", "advice")})
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (timestamp, severity, metric, title, message, details) VALUES (?,?,?,?,?,?)",
                (_iso(alert["ts"]), alert["severity"], alert["metric"], alert["title"], alert["message"], details))
            self._conn.commit()
            return cur.lastrowid

    def resolve_alert(self, db_id, ts):
        with self._lock:
            self._conn.execute("UPDATE alerts SET resolved_at=? WHERE id=?", (_iso(ts), db_id))
            self._conn.commit()

    def prune_packets(self, keep=200_000):
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) AS m FROM packets").fetchone()
            if row and row["m"] and row["m"] > keep:
                self._conn.execute("DELETE FROM packets WHERE id <= ?", (row["m"] - keep,))
                self._conn.commit()

    # ---- reads (history) -------------------------------------------------
    @staticmethod
    def _start_for(range_key, now):
        if range_key == "today":
            d = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
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
        end = datetime.fromtimestamp(now)
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
