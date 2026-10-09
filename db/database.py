"""
database.py
------------
Handles all SQLite storage. SQLite stores everything in a single
.db file on disk - no server to install or configure, which is why
it's a good fit for Phase 1 (you can always migrate to PostgreSQL
later; the SQL you write here is ~95% compatible).

Two tables, matching the PS doc's "Core Database Concept" (section 23):

  packets         -> individual packet metadata (kept lightweight,
                      no payload contents - just headers, for privacy)
  traffic_stats   -> periodic aggregated snapshots (time_window,
                      protocol, packet_count, total_bytes), so
                      historical analytics don't require re-scanning
                      every single packet ever captured.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from threading import Lock

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_mac TEXT,
    dst_mac TEXT,
    protocol TEXT,
    app_protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    packet_size INTEGER,
    ttl INTEGER,
    tcp_flags TEXT
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time_window TEXT NOT NULL,
    protocol TEXT,
    packet_count INTEGER,
    total_bytes INTEGER
);

CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
"""


class Database:
    def __init__(self, db_path: str = "netinsight.db"):
        self.db_path = db_path
        self._lock = Lock()
        # check_same_thread=False because our writer thread differs from
        # whichever thread first created the connection
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def insert_packet(self, record: dict):
        with self._lock:
            self._conn.execute(
                """INSERT INTO packets
                   (timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol,
                    app_protocol, src_port, dst_port, packet_size, ttl, tcp_flags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.get("timestamp"),
                    record.get("src_ip"),
                    record.get("dst_ip"),
                    record.get("src_mac"),
                    record.get("dst_mac"),
                    record.get("protocol"),
                    record.get("app_protocol"),
                    record.get("src_port"),
                    record.get("dst_port"),
                    record.get("packet_size"),
                    record.get("ttl"),
                    record.get("tcp_flags"),
                ),
            )
            self._conn.commit()

    def insert_packets_batch(self, records: list):
        """Insert many packets at once - much faster than one-by-one for bulk flushes."""
        if not records:
            return
        with self._lock:
            self._conn.executemany(
                """INSERT INTO packets
                   (timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol,
                    app_protocol, src_port, dst_port, packet_size, ttl, tcp_flags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        r.get("timestamp"), r.get("src_ip"), r.get("dst_ip"),
                        r.get("src_mac"), r.get("dst_mac"), r.get("protocol"),
                        r.get("app_protocol"), r.get("src_port"), r.get("dst_port"),
                        r.get("packet_size"), r.get("ttl"), r.get("tcp_flags"),
                    )
                    for r in records
                ],
            )
            self._conn.commit()

    def save_traffic_snapshot(self, protocol_packet_count: dict, protocol_byte_count: dict):
        """Save one aggregated stats row per protocol for this moment in time."""
        window = datetime.now().isoformat()
        with self._lock:
            for protocol, count in protocol_packet_count.items():
                self._conn.execute(
                    """INSERT INTO traffic_stats (time_window, protocol, packet_count, total_bytes)
                       VALUES (?, ?, ?, ?)""",
                    (window, protocol, count, protocol_byte_count.get(protocol, 0)),
                )
            self._conn.commit()

    def total_packet_count(self):
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM packets")
            return cur.fetchone()[0]

    def close(self):
        self._conn.close()
