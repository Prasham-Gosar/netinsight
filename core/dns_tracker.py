"""
dns_tracker.py
---------------
Measures DNS latency by matching each DNS question to its answer.

A DNS question and its answer share an ID number, like a coat-check
ticket. Time between the two = how long name lookups take. Questions that
never get an answer within 5 seconds are recorded as 5000 ms timeouts.
"""

TIMEOUT = 5.0


class DnsTracker:
    def __init__(self, ts_store, latency_samples):
        self.ts = ts_store
        self.samples = latency_samples
        self.pending = {}      # (id, client_ip, qname) -> time asked

    def update(self, rec):
        dns, ts = rec["dns"], rec["ts"]
        if dns["qr"] == 0:
            self.pending[(dns["id"], rec["src_ip"], dns["qname"])] = ts
            self.ts.add(ts, "dns_q")
        else:
            self.ts.add(ts, "dns_r")
            asked = self.pending.pop((dns["id"], rec["dst_ip"], dns["qname"]), None)
            if asked is not None:
                self.samples.add(ts, max(0.0, (ts - asked) * 1000.0))
            if dns["rcode"] == 2:                        # SERVFAIL
                self.ts.add(ts, "dns_servfail")

    def sweep(self, now):
        stale = [k for k, t in self.pending.items() if now - t > TIMEOUT]
        for k in stale:
            asked = self.pending.pop(k)
            self.samples.add(asked + TIMEOUT, TIMEOUT * 1000.0)
            self.ts.add(asked + TIMEOUT, "dns_timeout")
