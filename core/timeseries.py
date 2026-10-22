"""
timeseries.py
--------------
Per-second counters and timed samples.

Analogy: a tally sheet with one row per second. Every event ("a DNS query
happened", "1400 bytes arrived") adds a tick to that second's row. Later
we can ask "how many DNS queries in the last 10 seconds?" or "give me the
last 120 rows to draw a graph" without re-reading any old packets.
"""

from collections import defaultdict, deque


class TimeSeries:
    def __init__(self, horizon=3600):
        self.horizon = horizon
        self._buckets = {}          # second -> {key: value}
        self.first_sec = None

    def add(self, ts, key, value=1):
        sec = int(ts)
        bucket = self._buckets.get(sec)
        if bucket is None:
            bucket = self._buckets[sec] = defaultdict(float)
            if self.first_sec is None or sec < self.first_sec:
                self.first_sec = sec
            if len(self._buckets) > self.horizon + 120:
                cutoff = sec - self.horizon
                for old in [s for s in self._buckets if s < cutoff]:
                    del self._buckets[old]
        bucket[key] += value

    def series(self, key, seconds, now, offset=0):
        """List of `seconds` values, oldest first, ending at the last COMPLETE second
        (or `offset` seconds before that)."""
        end = int(now) - 1 - offset
        out = []
        for sec in range(end - seconds + 1, end + 1):
            b = self._buckets.get(sec)
            out.append(b.get(key, 0.0) if b else 0.0)
        return out

    def window_sum(self, key, seconds, now, offset=0):
        """Sum over `seconds` complete seconds, optionally shifted `offset` seconds into the past."""
        end = int(now) - 1 - offset
        total = 0.0
        for sec in range(end - seconds + 1, end + 1):
            b = self._buckets.get(sec)
            if b:
                total += b.get(key, 0.0)
        return total

    def covered_seconds(self, now):
        """How many seconds of history we have (used to know if a baseline is trustworthy)."""
        if self.first_sec is None:
            return 0
        return max(0, int(now) - self.first_sec)


class SampleStore:
    """Timed measurements (e.g. round-trip times). Newest last."""

    def __init__(self, maxlen=5000):
        self._d = deque(maxlen=maxlen)

    def add(self, ts, value):
        self._d.append((ts, value))

    def values(self, window, now):
        lo = now - window
        return [v for (t, v) in self._d if t >= lo]

    def values_between(self, start, end):
        return [v for (t, v) in self._d if start <= t < end]


def median(values):
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]
