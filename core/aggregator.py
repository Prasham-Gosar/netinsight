"""
aggregator.py
--------------
Keeps running totals as packets flow in, so we don't have to re-scan
every packet ever seen just to answer "how many TCP packets so far?"

Analogy: instead of re-counting a giant pile of coins every time
someone asks "how much money do we have?", the tally clerk keeps a
running total and just updates it by +1 coin each time one comes in.

Uses plain dictionaries as hash maps - the PS doc calls this out
explicitly under "Data Structures" (IP -> Bytes, Protocol -> Count, etc).
"""

from collections import defaultdict, deque
from threading import Lock

RECENT_PACKETS_LIMIT = 200  # how many recent packets to keep for the live feed


class TrafficAggregator:
    def __init__(self):
        self._lock = Lock()  # protects all the counters below from race conditions
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_packet_count = defaultdict(int)   # "TCP" -> 1523
        self.protocol_byte_count = defaultdict(int)      # "TCP" -> 812004
        self.app_protocol_count = defaultdict(int)        # "DNS" -> 42
        self.src_ip_bytes = defaultdict(int)               # "192.168.1.5" -> bytes
        self.dst_ip_bytes = defaultdict(int)               # "8.8.8.8" -> bytes
        # Rolling buffer of the most recent packets, for a live "Packet #152"-style
        # feed. deque(maxlen=N) automatically drops the oldest entry once full -
        # like a security camera that only keeps its last 200 frames.
        self.recent_packets = deque(maxlen=RECENT_PACKETS_LIMIT)

    def add(self, record: dict):
        """Fold one parsed packet record into the running totals."""
        size = record.get("packet_size", 0)
        protocol = record.get("protocol") or "UNKNOWN"
        app_protocol = record.get("app_protocol") or protocol

        with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            self.protocol_packet_count[protocol] += 1
            self.protocol_byte_count[protocol] += size
            self.app_protocol_count[app_protocol] += 1

            if record.get("src_ip"):
                self.src_ip_bytes[record["src_ip"]] += size
            if record.get("dst_ip"):
                self.dst_ip_bytes[record["dst_ip"]] += size

            self.recent_packets.appendleft({
                "packet_number": self.total_packets,
                "timestamp": record.get("timestamp"),
                "src_ip": record.get("src_ip"),
                "dst_ip": record.get("dst_ip"),
                "protocol": protocol,
                "app_protocol": app_protocol,
                "src_port": record.get("src_port"),
                "dst_port": record.get("dst_port"),
                "packet_size": size,
                "tcp_flags": record.get("tcp_flags"),
            })

    def get_recent_packets(self, n: int = 50):
        """Most recent packets first, for a live feed display."""
        with self._lock:
            return list(self.recent_packets)[:n]

    def protocol_distribution_percent(self):
        """Returns {protocol: percentage_of_total_packets} - for the pie chart / terminal bar."""
        with self._lock:
            if self.total_packets == 0:
                return {}
            return {
                proto: round((count / self.total_packets) * 100, 1)
                for proto, count in self.protocol_packet_count.items()
            }

    def top_talkers(self, n: int = 5):
        """Returns the top N source IPs by bytes sent - 'who is using the most bandwidth'."""
        with self._lock:
            sorted_ips = sorted(self.src_ip_bytes.items(), key=lambda kv: kv[1], reverse=True)
            return sorted_ips[:n]

    def snapshot(self):
        """A read-only copy of the current stats, safe to hand to the DB writer or UI."""
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "protocol_packet_count": dict(self.protocol_packet_count),
                "protocol_byte_count": dict(self.protocol_byte_count),
                "app_protocol_count": dict(self.app_protocol_count),
            }
