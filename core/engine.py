"""
engine.py
----------
The conductor of Phase 2 + 3. One Engine owns every analyser and runs the
processing loop:

    queue -> parse -> identify protocol -> direction -> application
          -> device -> flow/TCP health -> DNS latency -> bandwidth
          -> (health score, anomaly detection, insights, explanations)
          -> SQLite

Everything shared between the processing thread and the web API is guarded
by one re-entrant lock, so a dashboard request never sees half-updated
numbers.
"""

import threading
import time
from collections import Counter, deque
from datetime import datetime

from capture.packet_parser import parse_packet
from capture.protocol_identifier import identify_application_protocol, protocol_family
from .aggregator import TrafficAggregator
from .anomaly import MIN_BASE, SHORT, AnomalyDetector
from .app_detector import AppDetector
from .bandwidth import BandwidthTracker
from .device_tracker import DeviceTracker
from .dns_tracker import DnsTracker
from .explainer import explain_packet
from .flow_tracker import FlowTracker
from .health import HealthMonitor
from .insights import build_insights
from .packet_queue import PacketQueue
from .timeseries import SampleStore, TimeSeries, median

FLUSH_EVERY = 10          # seconds between database flushes
HEALTH_SAVE_EVERY = 10
LATENCY_HISTORY_EVERY = 60


class Engine:
    def __init__(self, ctx, database=None, mode="live", store_packets=True,
                 resolve_hostnames=True, interface_label=None):
        self.ctx = ctx
        self.db = database
        self.mode = mode
        self.store_packets = store_packets
        self.interface_label = interface_label
        self.lock = threading.RLock()

        self.queue = PacketQueue(maxsize=20000)
        self.ts = TimeSeries(horizon=3600)
        self.rtt_samples = SampleStore()
        self.dns_samples = SampleStore()

        self.aggregator = TrafficAggregator()          # Phase 1 totals (used by the console view)
        self.apps = AppDetector()
        self.devices = DeviceTracker(ctx, resolve_hostnames=resolve_hostnames)
        self.flows = FlowTracker(self.ts, self.rtt_samples)
        self.dns = DnsTracker(self.ts, self.dns_samples)
        self.bandwidth = BandwidthTracker(self.ts)
        self.health = HealthMonitor(self.ts, self.rtt_samples, self.dns_samples, ctx)
        self.anomaly = AnomalyDetector(self.ts, context_fn=self._anomaly_context)

        self.recent_packets = deque(maxlen=300)
        self._recent_dns = deque(maxlen=20000)         # (ts, qname)
        self._recent_traffic = deque(maxlen=60000)     # (ts, app, device_key, size)
        self._recent_syn = deque(maxlen=20000)         # (ts, remote, domain)
        self.latency_history = deque(maxlen=240)       # (ts, median rtt) per minute
        self.packets_total = 0
        self.parse_errors = 0
        self._last_ts = 0.0
        self._cur_sec, self._cur_dst = None, set()
        self._batch = []
        self._dev_flushed = {}
        self._health_cache = None

        self.started_wall = time.time()
        self._next = {"second": 0, "anomaly": 0, "health_save": 0, "latency": 0, "flush": 0, "prune": 0}
        self._stop = threading.Event()
        self._thread = None
        self.capture = None       # CaptureEngine (live mode)
        self.simulator = None     # SimulatorRunner (simulation mode)
        self.db_ids = {}

    # ------------------------------------------------------------------
    def now(self):
        return max(time.time(), self._last_ts)

    # ---- per-packet pipeline ---------------------------------------------
    def process(self, item):
        """Handle one queue item: (timestamp, scapy packet) or an already-parsed dict."""
        if isinstance(item, tuple):
            try:
                rec = parse_packet(item[1], item[0])
            except Exception:
                self.parse_errors += 1
                return None
        else:
            rec = item
        if rec is None:
            return None
        rec["app_protocol"] = identify_application_protocol(rec)
        rec["family"] = protocol_family(rec)
        with self.lock:
            self._handle(rec)
        return rec

    def _handle(self, rec):
        ts, size = rec["ts"], rec["packet_size"]
        src, dst = rec["src_ip"], rec["dst_ip"]
        self._last_ts = max(self._last_ts, ts)
        self.packets_total += 1
        rec["n"] = self.packets_total

        direction = self.ctx.direction(src, dst)
        remote = self.ctx.remote_ip(src, dst, direction)
        cls = self.apps.classify(rec, remote)
        rec["direction"], rec["app"], rec["domain"] = direction, cls["app"], cls["domain"]
        rec["app_method"], rec["confidence"] = cls["method"], cls["confidence"]

        src_key, dst_key = self.devices.observe(rec, size)
        dev_key = (dst_key if direction == "in" else src_key) or src_key or dst_key or "Unknown"

        if rec.get("dns") and rec["dns"]["qname"]:
            self.dns.update(rec)
            if rec["dns"]["qr"] == 0:
                self._recent_dns.append((ts, rec["dns"]["qname"]))

        flow = self.flows.update(rec, cls["app"], cls["domain"])
        if flow is not None and flow.app and cls["app"] == "Unclassified":
            rec["app"] = flow.app                      # inherit from the flow's earlier packets
            cls = dict(cls, app=flow.app)
        if rec["protocol"] == "TCP":
            fl = rec["tcp_flags"] or ""
            if "S" in fl and "A" not in fl and direction == "out":
                self._recent_syn.append((ts, remote, cls["domain"]))

        sec = int(ts)
        if self._cur_sec is None:
            self._cur_sec = sec
        elif sec > self._cur_sec:
            if self._cur_dst:
                self.ts.add(self._cur_sec, "uniq_dst", len(self._cur_dst))
            self._cur_sec, self._cur_dst = sec, set()
        if direction == "out" and remote:
            self._cur_dst.add(remote)

        self.bandwidth.add(rec, direction, cls, dev_key, remote)
        self.aggregator.add(rec)
        self._recent_traffic.append((ts, cls["app"], dev_key, size))
        self.recent_packets.appendleft(rec)
        if self.store_packets and self.db:
            self._batch.append(rec)

    # ---- periodic work ---------------------------------------------------
    def tick(self, now=None):
        """Housekeeping that must run about once a second. `now` can be injected by tests."""
        with self.lock:
            now = now if now is not None else self.now()
            n = self._next
            if now >= n["second"]:
                n["second"] = now + 1
                self.flows.sweep(now)
                self.dns.sweep(now)
                self.bandwidth.note_peak(now)
            if now >= n["anomaly"]:
                n["anomaly"] = now + 2
                new, resolved = self.anomaly.check(now)
                for a in new:
                    if self.db:
                        a["db_id"] = self.db.insert_alert(a)
                for a in resolved:
                    if self.db and a.get("db_id"):
                        self.db.resolve_alert(a["db_id"], now)
            if now >= n["latency"]:
                n["latency"] = now + LATENCY_HISTORY_EVERY
                self.latency_history.append((now, median(self.rtt_samples.values(60, now))))
            if now >= n["health_save"]:
                n["health_save"] = now + HEALTH_SAVE_EVERY
                self._health_cache = self.health.compute(now)
                if self.db and self._health_cache["score"] is not None:
                    self.db.insert_health(now, self._health_cache)
            if now >= n["flush"]:
                n["flush"] = now + FLUSH_EVERY
                self.flush(now)
            if now >= n["prune"]:
                n["prune"] = now + 600
                if self.db:
                    self.db.prune_packets()

    def flush(self, now=None):
        """Write everything accumulated since the last flush to SQLite."""
        if not self.db:
            return
        with self.lock:
            now = now if now is not None else self.now()
            batch, self._batch = self._batch, []
            cells, apps = self.bandwidth.drain()
            merged = {}
            for (minute, dev_key, app, proto, d), cell in cells.items():
                k = (minute, self.devices.label_for_key(dev_key) if dev_key != "Unknown" else "Unknown", app, proto, d)
                m = merged.setdefault(k, [0, 0])
                m[0] += cell[0]
                m[1] += cell[1]
            dev_rows = []
            for d in self.devices.snapshot(now):
                key = d["key"]
                pin, pout, ppk = self._dev_flushed.get(key, (0, 0, 0))
                self._dev_flushed[key] = (d["bytes_in"], d["bytes_out"], d["packets"])
                dev_rows.append(dict(d, bytes_in=d["bytes_in"] - pin, bytes_out=d["bytes_out"] - pout,
                                     packets=d["packets"] - ppk))
        self.db.insert_packets_batch(batch)
        self.db.flush_usage(merged, apps, now)
        self.db.upsert_devices(dev_rows)

    # ---- anomaly context ("anomaly analysis") -------------------------------
    def _anomaly_context(self, key, now, seconds):
        lo = now - seconds - 1
        notes = []
        if key == "dns_q":
            parents = {}
            for t, q in self._recent_dns:
                if t >= lo:
                    parents.setdefault(".".join(q.split(".")[-2:]), []).append(q)
            if parents:
                top = sorted(parents.items(), key=lambda kv: len(kv[1]), reverse=True)[:3]
                notes.append("Most queried domains: " + ", ".join(
                    f"{p} ({len(v)} lookups, {len(set(v))} distinct names)" for p, v in top))
        elif key in ("bytes", "pkts"):
            by_app, by_dev = Counter(), Counter()
            for t, app, dev, size in self._recent_traffic:
                if t >= lo:
                    by_app[app] += size
                    by_dev[dev] += size
            if by_app:
                total = sum(by_app.values())
                a, ab = by_app.most_common(1)[0]
                notes.append(f"Largest contributor: {a} ({100 * ab // total}% of the burst)")
            if by_dev:
                d, _ = by_dev.most_common(1)[0]
                notes.append(f"Busiest device: {self.devices.label_for_key(d) if d != 'Unknown' else 'Unknown'}")
        else:
            dests = Counter((dom or ip) for t, ip, dom in self._recent_syn if t >= lo)
            if dests:
                top = ", ".join(f"{n} ({c})" for n, c in dests.most_common(3))
                notes.append(f"Most contacted: {top}")
                notes.append(f"{len(dests)} distinct destinations in the last {seconds}s")
        return notes

    # ---- public views for the API -------------------------------------------
    @staticmethod
    def _public_packet(rec):
        src = f"{rec['src_ip']}:{rec['src_port']}" if rec["src_port"] else (rec["src_ip"] or "-")
        dst = f"{rec['dst_ip']}:{rec['dst_port']}" if rec["dst_port"] else (rec["dst_ip"] or "-")
        return {
            "n": rec["n"], "time": datetime.fromtimestamp(rec["ts"]).strftime("%H:%M:%S"),
            "src": src, "dst": dst, "protocol": rec["app_protocol"], "family": rec["family"],
            "size": rec["packet_size"], "flags": rec["tcp_flags"], "ttl": rec["ttl"],
            "app": rec["app"], "domain": rec["domain"], "direction": rec["direction"],
            "confidence": rec["confidence"], "explanation": explain_packet(rec),
        }

    def packets_view(self, limit=30):
        with self.lock:
            return [self._public_packet(r) for r in list(self.recent_packets)[:limit]]

    def health_view(self):
        with self.lock:
            return self.health.compute(self.now())

    def alerts_view(self, n=30):
        with self.lock:
            out = []
            for a in self.anomaly.recent(n):
                item = {k: v for k, v in a.items() if k != "db_id"}
                item["time"] = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
                out.append(item)
            return out

    def _insight_snapshot(self, now, health):
        return {
            "total_bytes": self.bandwidth.total_bytes,
            "bytes_in": self.bandwidth.bytes_dir["in"], "bytes_out": self.bandwidth.bytes_dir["out"],
            "apps": self.bandwidth.top_apps(10), "protocols": self.bandwidth.protocols(12),
            "devices": self.devices.snapshot(now), "health": health,
            "latency_history": list(self.latency_history),
            "peak_bps": self.bandwidth.peak_bps, "peak_ts": self.bandwidth.peak_ts,
        }

    def insights_view(self):
        with self.lock:
            now = self.now()
            return build_insights(self._insight_snapshot(now, self.health.compute(now)))

    def dashboard(self, bandwidth_seconds=120, packets=30, flows=12):
        """Everything the live dashboard needs, in one consistent snapshot."""
        with self.lock:
            now = self.now()
            health = self.health.compute(now)
            devices = self.devices.snapshot(now)
            snap = self._insight_snapshot(now, health)
            bw = self.bandwidth
            return {
                "meta": {
                    "mode": self.mode, "interface": self.interface_label,
                    "uptime_s": int(now - self.started_wall), "now": now,
                    "link_mbps": self.ctx.link_mbps, "storing_packets": bool(self.store_packets and self.db),
                    "database": bool(self.db),
                },
                "totals": {
                    "packets": bw.total_packets, "bytes": bw.total_bytes,
                    "bytes_in": bw.bytes_dir["in"], "bytes_out": bw.bytes_dir["out"], "bytes_local": bw.bytes_dir["local"],
                    "devices": len(devices), "active_devices": sum(1 for d in devices if d["active"]),
                    "flows_active": self.flows.active_count(), "alerts_active": self.anomaly.active_count(),
                    "queue": self.queue.qsize(), "dropped": self.queue.dropped,
                },
                "rate": bw.current_rate(now),
                "baseline": {"seconds": int(self.ts.covered_seconds(now)), "needed": MIN_BASE + SHORT,
                             "ready": self.ts.covered_seconds(now) >= MIN_BASE + SHORT},
                "health": health,
                "bandwidth": bw.rates(bandwidth_seconds, now),
                "protocols": bw.families(),
                "app_protocols": bw.protocols(10),
                "applications": bw.top_apps(8),
                "devices": devices[:8],
                "top_ips": bw.top_remotes(8),
                "alerts": self.alerts_view(10),
                "insights": build_insights(snap),
                "packets": [self._public_packet(r) for r in list(self.recent_packets)[:packets]],
                "flows": self.flows.top_flows(flows),
            }

    # ---- threads --------------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True, name="processing")
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            item = self.queue.get(timeout=0.25)
            if item is not None:
                self.process(item)
                for _ in range(500):                    # drain a burst before ticking
                    nxt = self.queue.get(timeout=0.0005)
                    if nxt is None:
                        break
                    self.process(nxt)
            self.tick()
            if self.store_packets and self.db and len(self._batch) >= 500:
                self.flush()

    def stop(self):
        self._stop.set()
        if self.capture:
            self.capture.stop()
        if self.simulator:
            self.simulator.stop()
        if self._thread:
            self._thread.join(timeout=3)
        if self.db:
            try:
                self.flush()
            finally:
                self.db.close()
