"""
bandwidth.py
-------------
Bandwidth analytics: who/what is using the network?

Everything is a dictionary lookup + an addition (O(1) per packet), so the
cost does not grow as the capture runs longer. We aggregate by:
application, protocol, protocol family, remote address/domain and
direction, and keep a per-minute accumulator that is flushed to the
database for historical reports.
"""

from collections import defaultdict


def _row():
    return {"bytes": 0, "packets": 0, "bytes_in": 0, "bytes_out": 0}


class BandwidthTracker:
    def __init__(self, ts_store):
        self.ts = ts_store
        self.total_bytes = self.total_packets = 0
        self.bytes_dir = {"in": 0, "out": 0, "local": 0}
        self.by_app = defaultdict(_row)
        self.by_protocol = defaultdict(_row)
        self.by_family = defaultdict(_row)
        self.by_remote = {}                    # ip -> [bytes, packets, domain, app]
        self._minute = defaultdict(lambda: [0, 0])    # (minute, device, app, proto, dir) -> [pkts, bytes]
        self._app_delta = {}                   # app -> [bytes, packets, domain]
        self.peak_bps = 0.0
        self.peak_ts = None

    def add(self, rec, direction, cls, device_label, remote_ip):
        size, ts = rec["packet_size"], rec["ts"]
        d = direction if direction in ("in", "out") else "local"
        app = cls["app"]

        self.total_bytes += size
        self.total_packets += 1
        self.bytes_dir[d] += size
        self.ts.add(ts, "bytes", size)
        self.ts.add(ts, "bytes_" + d, size)
        self.ts.add(ts, "pkts")

        for table, name in ((self.by_app, app),
                            (self.by_protocol, rec["app_protocol"]),
                            (self.by_family, rec["family"])):
            r = table[name]
            r["bytes"] += size
            r["packets"] += 1
            if d == "in":
                r["bytes_in"] += size
            elif d == "out":
                r["bytes_out"] += size

        if remote_ip:
            r = self.by_remote.get(remote_ip)
            if r is None:
                if len(self.by_remote) > 20000:
                    self._trim_remote()
                r = self.by_remote[remote_ip] = [0, 0, None, None]
            r[0] += size
            r[1] += 1
            if cls["domain"]:
                r[2] = cls["domain"]
            if app not in ("Unclassified",):
                r[3] = app

        minute = int(ts // 60)
        cell = self._minute[(minute, device_label, app, rec["app_protocol"], d)]
        cell[0] += 1
        cell[1] += size
        a = self._app_delta.setdefault(app, [0, 0, None])
        a[0] += size
        a[1] += 1
        if cls["domain"]:
            a[2] = cls["domain"]

    def _trim_remote(self):
        keep = sorted(self.by_remote.items(), key=lambda kv: kv[1][0], reverse=True)[:10000]
        self.by_remote = dict(keep)

    # ---- reads --------------------------------------------------------
    def rates(self, seconds, now):
        """Per-second bandwidth for the live graph (bytes/s)."""
        end = int(now) - 1
        bin_ = self.ts.series("bytes_in", seconds, now)
        bout = self.ts.series("bytes_out", seconds, now)
        bloc = self.ts.series("bytes_local", seconds, now)
        pk = self.ts.series("pkts", seconds, now)
        t0 = end - seconds + 1
        return [{"t": t0 + i, "in": bin_[i], "out": bout[i], "local": bloc[i], "pps": pk[i]}
                for i in range(seconds)]

    def current_rate(self, now, seconds=5):
        return {
            "in_bps": self.ts.window_sum("bytes_in", seconds, now) / seconds,
            "out_bps": self.ts.window_sum("bytes_out", seconds, now) / seconds,
            "pps": self.ts.window_sum("pkts", seconds, now) / seconds,
        }

    def note_peak(self, now):
        bps = (self.ts.window_sum("bytes", 3, now) / 3.0)
        if bps > self.peak_bps:
            self.peak_bps, self.peak_ts = bps, now

    @staticmethod
    def _top(table, n, total):
        items = sorted(table.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:n]
        return [{"name": k, "bytes": v["bytes"], "packets": v["packets"],
                 "bytes_in": v["bytes_in"], "bytes_out": v["bytes_out"],
                 "percent": round(100.0 * v["bytes"] / total, 1) if total else 0.0}
                for k, v in items]

    def top_apps(self, n=10):
        return self._top(self.by_app, n, self.total_bytes)

    def protocols(self, n=12):
        return self._top(self.by_protocol, n, self.total_bytes)

    def families(self):
        """Protocol distribution for the donut chart (by packets AND bytes)."""
        out = []
        for name, v in self.by_family.items():
            out.append({"name": name, "packets": v["packets"], "bytes": v["bytes"],
                        "percent_packets": round(100.0 * v["packets"] / self.total_packets, 1) if self.total_packets else 0.0,
                        "percent_bytes": round(100.0 * v["bytes"] / self.total_bytes, 1) if self.total_bytes else 0.0})
        out.sort(key=lambda x: x["packets"], reverse=True)
        return out

    def top_remotes(self, n=10):
        items = sorted(self.by_remote.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
        return [{"ip": ip, "bytes": v[0], "packets": v[1], "domain": v[2], "app": v[3]} for ip, v in items]

    # ---- database hand-off -------------------------------------------
    def drain(self):
        """Return and reset what accumulated since the last flush."""
        minute, self._minute = self._minute, defaultdict(lambda: [0, 0])
        apps, self._app_delta = self._app_delta, {}
        return minute, apps
