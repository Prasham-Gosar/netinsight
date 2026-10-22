"""
anomaly.py
-----------
Abnormal traffic detection using plain statistics (no black-box ML).

Idea: learn what "normal" looks like from the last 5 minutes, then flag
the last 10 seconds if they are far outside it.

   baseline  = mean and spread of the previous 300 s (per second)
   now       = mean over the latest 10 s
   ratio     = now / baseline_mean            (e.g. "10x higher")
   z-score   = (now - baseline_mean) / spread (how many "normal wobbles" away)

An alert fires only if ALL of these hold, which avoids false alarms:
   * ratio >= 3                (clearly higher, not a small wiggle)
   * z-score >= 3              (statistically unusual)
   * now >= a minimum rate     (0.1 -> 0.5 queries/s is not worth an alert)

We deliberately never say "malware". The wording is: "Potentially unusual
traffic detected; further investigation may be required."
"""

import math
import time

SHORT = 10          # seconds in the "current" window
BASE = 300          # seconds in the baseline window
MIN_BASE = 60       # need at least this much history before alerting
RATIO_MIN = 3.0
Z_MIN = 3.0
COOLDOWN = 30       # seconds after an alert resolves before the same metric may alert again

METRICS = [
    dict(key="dns_q", label="DNS activity", subject="DNS requests", verb="are", min_rate=2.0, unit="req/s",
         causes=["An application repeatedly resolving domain names", "A misconfigured app or DNS setting",
                 "A network issue causing lookups to be retried", "Unusual behaviour worth investigating"]),
    dict(key="pkts", label="packet rate", subject="The packet rate", verb="is", min_rate=100.0, unit="pkt/s",
         causes=["A large download, upload or stream starting", "A device flooding the network",
                 "A loop or retry storm in an application"]),
    dict(key="bytes", label="traffic volume", subject="Network traffic volume", verb="is", min_rate=200_000.0, unit="B/s",
         causes=["A big download or upload (video, backup, update)", "Many devices becoming active at once",
                 "Unexpected background transfer"]),
    dict(key="syn", label="connection attempts", subject="New connection attempts", verb="are", min_rate=5.0, unit="conn/s",
         causes=["An application opening many connections (e.g. a busy web page)", "A scan or probe of many hosts/ports",
                 "A retry loop after failures"]),
    dict(key="rst", label="connection resets", subject="Connection resets", verb="are", min_rate=2.0, unit="rst/s",
         causes=["A service refusing connections", "Firewall or middlebox interference", "A crashing server or app"]),
    dict(key="uniq_dst", label="destination spread", subject="The number of distinct destinations contacted", verb="is",
         min_rate=8.0, unit="IPs/s",
         causes=["Browsing many different sites at once", "A scan of many addresses", "Peer-to-peer or discovery software"]),
]
NOTE = "Potentially unusual traffic detected; further investigation may be required."


def _mean(v):
    return sum(v) / len(v) if v else 0.0


def _std(v, m):
    return math.sqrt(sum((x - m) ** 2 for x in v) / len(v)) if v else 0.0


def fmt_rate(value, unit):
    if unit == "B/s":
        for u, d in (("MB/s", 1e6), ("KB/s", 1e3)):
            if value >= d:
                return f"{value / d:.1f} {u}"
        return f"{value:.0f} B/s"
    return f"{value:.1f} {unit}"


class AnomalyDetector:
    def __init__(self, ts_store, context_fn=None):
        self.ts = ts_store
        self.context_fn = context_fn
        self.alerts = []                 # newest last
        self._active = {}                # metric key -> alert dict
        self._quiet_since = {}
        self._cooldown_until = {}
        self._next_id = 1

    def check(self, now):
        """Run all detectors. Returns (new_alerts, resolved_alerts)."""
        new, resolved = [], []
        if self.ts.covered_seconds(now) < MIN_BASE + SHORT:
            return new, resolved
        base_len = int(min(BASE, self.ts.covered_seconds(now) - SHORT))

        for m in METRICS:
            key = m["key"]
            rate = _mean(self.ts.series(key, SHORT, now))
            base = self.ts.series(key, base_len, now, offset=SHORT)
            mu = _mean(base)
            mu_eff = max(mu, m["min_rate"] / 10.0)
            sd_eff = max(_std(base, mu), 0.25 * mu_eff)
            ratio, z = rate / mu_eff, (rate - mu) / sd_eff

            active = self._active.get(key)
            if active is None:
                if (rate >= m["min_rate"] and ratio >= RATIO_MIN and z >= Z_MIN
                        and now >= self._cooldown_until.get(key, 0)):
                    alert = self._raise(m, now, rate, mu_eff, ratio, z)
                    self._active[key] = alert
                    new.append(alert)
            else:
                active["peak_ratio"] = max(active["peak_ratio"], round(ratio, 1))
                active["peak_rate"] = max(active["peak_rate"], round(rate, 2))
                elevated = rate >= max(m["min_rate"] * 0.5, 2.0 * active["baseline"])
                if elevated:
                    self._quiet_since.pop(key, None)
                    if (ratio >= 8 and z >= 6) and active["severity"] != "critical":
                        active["severity"] = "critical"
                else:
                    since = self._quiet_since.setdefault(key, now)
                    if now - since >= 10:
                        active["active"] = False
                        active["resolved_ts"] = now
                        del self._active[key]
                        self._quiet_since.pop(key, None)
                        self._cooldown_until[key] = now + COOLDOWN
                        resolved.append(active)
        return new, resolved

    def _raise(self, m, now, rate, mu, ratio, z):
        ratio_txt = f"{ratio:.0f}×" if ratio >= 10 else f"{ratio:.1f}×"
        context = []
        if self.context_fn:
            try:
                context = self.context_fn(m["key"], now, SHORT)
            except Exception:
                context = []
        alert = {
            "id": self._next_id,
            "metric": m["key"],
            "severity": "critical" if (ratio >= 8 and z >= 6) else "warning",
            "title": f"Unusual {m['label']} detected",
            "message": (f"{m['subject']} {m['verb']} approximately {ratio_txt} higher than the recent baseline "
                        f"({fmt_rate(rate, m['unit'])} vs {fmt_rate(mu, m['unit'])})."),
            "advice": NOTE,
            "causes": m["causes"],
            "context": context,
            "ts": now,
            "active": True,
            "rate": round(rate, 2), "baseline": round(mu, 2), "peak_rate": round(rate, 2), "unit": m["unit"],
            "ratio": round(ratio, 1), "peak_ratio": round(ratio, 1), "z": round(z, 1),
            "resolved_ts": None,
        }
        self._next_id += 1
        self.alerts.append(alert)
        if len(self.alerts) > 200:
            del self.alerts[:50]
        return alert

    def recent(self, n=30):
        return list(reversed(self.alerts[-n:]))

    def active_count(self):
        return len(self._active)
