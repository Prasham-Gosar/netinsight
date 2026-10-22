"""
health.py
----------
Network Health Score (0-100) built ONLY from things we actually measured.

Think of it like a car's dashboard check: start at 100 points and lose
points for each warning light. Every metric has a "fine" level (no
points lost) and a "bad" level (all of its points lost); in between the
penalty grows in a straight line.

    metric               weight   fine -> bad
    latency (TCP RTT)      20     50 ms  -> 400 ms
    packet loss (est.)     25     0.5 %  -> 5 %
    retransmissions        10     1 %    -> 8 %
    duplicate ACKs          5     1 %    -> 10 %
    DNS latency            15     50 ms  -> 500 ms
    connection failures    15     2 %    -> 30 %
    bandwidth utilisation  10     70 %   -> 100 % of link speed

A metric with too few samples is skipped (no penalty, flagged "not enough
data") so the score never pretends to know more than it does.

Honest note: a passive sniffer cannot see packets that were lost
*before* they reached it. Packet loss is therefore an ESTIMATE:
(retransmitted segments + sequence gaps) / data segments.
"""

from .timeseries import median, percentile

COMPONENTS = [
    # key, label, noun for sentences, weight, good, bad, unit
    ("latency", "Latency", "latency", 20, 50.0, 400.0, "ms"),
    ("packet_loss", "Packet loss (est.)", "packet loss estimate", 25, 0.5, 5.0, "%"),
    ("retransmissions", "Retransmissions", "retransmission rate", 10, 1.0, 8.0, "%"),
    ("dup_acks", "Duplicate ACKs", "duplicate-ACK rate", 5, 1.0, 10.0, "%"),
    ("dns_latency", "DNS latency", "DNS latency", 15, 50.0, 500.0, "ms"),
    ("conn_failures", "Connection failures", "connection failure rate", 15, 2.0, 30.0, "%"),
    ("bandwidth", "Bandwidth utilisation", "bandwidth utilisation", 10, 70.0, 100.0, "%"),
]

MIN_TCP_DATA = 30
MIN_RTT = 3
MIN_DNS = 3
MIN_SYN = 5


def status_for(score):
    if score is None:
        return "Collecting data", "gray"
    if score >= 90:
        return "Excellent", "green"
    if score >= 75:
        return "Good", "lime"
    if score >= 50:
        return "Fair", "amber"
    return "Poor", "red"


def _penalty(value, good, bad, weight):
    if value is None:
        return 0.0
    frac = (value - good) / (bad - good)
    return weight * min(1.0, max(0.0, frac))


def _fmt(value, unit):
    if unit == "ms":
        return f"{value:.0f} ms" if value >= 10 else f"{value:.1f} ms"
    return f"{value:.1f}%"


class HealthMonitor:
    def __init__(self, ts_store, rtt_samples, dns_samples, ctx):
        self.ts, self.rtt, self.dns, self.ctx = ts_store, rtt_samples, dns_samples, ctx

    def compute(self, now, window=60):
        ts = self.ts
        tcp_data = ts.window_sum("tcp_data", window, now)
        retrans = ts.window_sum("retrans", window, now)
        gaps = ts.window_sum("seq_gap", window, now)
        dups = ts.window_sum("dup_ack", window, now)
        syns = ts.window_sum("syn", window, now)
        fails = ts.window_sum("conn_fail", window, now)

        rtts = self.rtt.values(window, now)
        dnss = self.dns.values(window, now)

        value = {k: None for k, *_ in COMPONENTS}
        if len(rtts) >= MIN_RTT:
            value["latency"] = median(rtts)
        if tcp_data >= MIN_TCP_DATA:
            value["packet_loss"] = min(100.0, 100.0 * (retrans + gaps) / tcp_data)
            value["retransmissions"] = min(100.0, 100.0 * retrans / tcp_data)
            value["dup_acks"] = min(100.0, 100.0 * dups / tcp_data)
        if len(dnss) >= MIN_DNS:
            value["dns_latency"] = percentile(dnss, 75)
        if syns >= MIN_SYN:
            value["conn_failures"] = min(100.0, 100.0 * fails / syns)
        link_bps = self.ctx.link_mbps * 1e6 / 8.0
        peak = max(ts.window_sum("bytes_in", 10, now), ts.window_sum("bytes_out", 10, now)) / 10.0
        value["bandwidth"] = min(100.0, 100.0 * peak / link_bps) if link_bps else None

        components, issues, total_pen, measured = [], [], 0.0, 0
        for key, label, noun, weight, good, bad, unit in COMPONENTS:
            v = value[key]
            pen = _penalty(v, good, bad, weight)
            total_pen += pen
            if v is not None and key != "bandwidth":
                measured += 1
            components.append({"key": key, "label": label, "value": None if v is None else round(v, 2),
                               "unit": unit, "penalty": round(pen, 1), "max_penalty": weight,
                               "good": good, "bad": bad, "measured": v is not None})
            if v is not None and pen / weight > 0.05:
                ratio = pen / weight
                adj = "Slightly elevated" if ratio < 0.3 else ("Elevated" if ratio < 0.65 else "High")
                if key == "bandwidth":
                    adj = "Light" if ratio < 0.3 else ("Moderate" if ratio < 0.65 else "Heavy")
                issues.append(f"{adj} {noun} ({_fmt(v, unit)})")

        enough = measured >= 2 or tcp_data >= MIN_TCP_DATA
        score = int(round(max(0.0, 100.0 - total_pen))) if enough else None
        status, color = status_for(score)
        return {
            "score": score, "status": status, "color": color, "window_s": window,
            "metrics": {
                "latency_ms": value["latency"], "packet_loss_pct": value["packet_loss"],
                "retransmission_pct": value["retransmissions"], "dup_ack_pct": value["dup_acks"],
                "dns_latency_ms": value["dns_latency"], "conn_failure_pct": value["conn_failures"],
                "bandwidth_util_pct": value["bandwidth"],
            },
            "components": components, "issues": issues,
            "samples": {"rtt": len(rtts), "dns": len(dnss), "tcp_data": int(tcp_data), "syn": int(syns)},
        }
