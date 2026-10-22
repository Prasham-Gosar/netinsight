"""
insights.py
------------
Turns numbers into sentences a non-expert can act on.

Rule: every sentence is generated from a MEASURED value in `snap`. If a
number is missing (not enough data yet) the corresponding insight is
simply not produced.
"""

from datetime import datetime

SYSTEM_LABELS = {"DNS", "ARP", "ICMP", "DHCP", "NTP", "SSH", "Local discovery", "Unclassified", "Other"}


def _fmt_bytes(n):
    for unit, d in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= d:
            return f"{n / d:.1f} {unit}"
    return f"{int(n)} B"


def _fmt_rate(bps):
    bits = bps * 8
    if bits >= 1e6:
        return f"{bits / 1e6:.1f} Mbps"
    return f"{bits / 1e3:.0f} kbps"


def _median(v):
    s = sorted(v)
    n = len(s)
    return None if not n else (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2)


def build_insights(snap):
    out = []

    def add(level, title, text):
        out.append({"level": level, "title": title, "text": text})

    total = snap["total_bytes"]
    if total < 50_000:
        add("info", "Collecting data", "NetInsight needs a little more traffic before it can say anything meaningful.")
        return out

    # --- who is using the bandwidth ------------------------------------
    named = [a for a in snap["apps"] if a["name"] not in SYSTEM_LABELS]
    if named and named[0]["percent"] >= 15:
        top = named[0]
        text = f"{top['name']} accounts for approximately {top['percent']:.0f}% of the monitored bandwidth during the current session ({_fmt_bytes(top['bytes'])})."
        if len(named) > 1 and named[1]["percent"] >= 10:
            text += f" {named[1]['name']} follows with about {named[1]['percent']:.0f}%."
        add("info", "Top application", text)

    # --- direction ------------------------------------------------------
    inb, outb = snap["bytes_in"], snap["bytes_out"]
    internet = inb + outb
    if internet > 0:
        if inb / internet >= 0.8:
            add("info", "Mostly downloading", f"About {100 * inb / internet:.0f}% of internet traffic is incoming - typical of streaming, browsing or downloads.")
        elif outb / internet >= 0.6:
            add("info", "Mostly uploading", f"About {100 * outb / internet:.0f}% of internet traffic is outgoing - typical of video calls, cloud backups or uploads.")

    # --- health-driven statements --------------------------------------
    m = snap["health"]["metrics"]
    loss, lat, dns, fail = m["packet_loss_pct"], m["latency_ms"], m["dns_latency_ms"], m["conn_failure_pct"]
    if loss is not None:
        if loss >= 2:
            add("bad", "Packet loss", f"Packet loss has increased significantly (about {loss:.1f}% estimated) and may affect video calls, gaming, and other latency-sensitive applications.")
        elif loss >= 0.5:
            add("warn", "Slight packet loss", f"A small amount of packet loss is estimated ({loss:.1f}%). It is unlikely to be noticeable except on very sensitive applications.")
    if lat is not None:
        if lat >= 150:
            add("bad", "High latency", f"Connections take about {lat:.0f} ms to respond, which can make calls, gaming and page loads feel sluggish.")
        elif lat >= 80:
            add("warn", "Elevated latency", f"Response time to servers is about {lat:.0f} ms - fine for browsing, noticeable in real-time apps.")
    if dns is not None and dns >= 200:
        add("warn", "Slow DNS", f"Name lookups are taking about {dns:.0f} ms, so websites may take longer to start loading. Trying a different DNS server may help.")
    if fail is not None and fail >= 10:
        add("bad", "Failed connections", f"About {fail:.0f}% of new connection attempts failed. That points to an unreliable link or an unreachable service.")

    # --- latency trend vs earlier baseline ------------------------------
    hist = [h for h in snap["latency_history"] if h[1] is not None]
    if len(hist) >= 5:
        recent = _median([v for _, v in hist[-2:]])
        base = _median([v for _, v in hist[:-2][-10:]])
        if base and recent and recent >= 1.5 * base and recent - base >= 30:
            when = datetime.fromtimestamp(hist[-2][0]).strftime("%H:%M")
            add("warn", "Latency increased", f"Network latency increased substantially after {when} (from about {base:.0f} ms to {recent:.0f} ms) compared with the earlier baseline.")

    # --- devices ----------------------------------------------------------
    devs = [d for d in snap["devices"] if d["bytes_total"] > 0]
    if len(devs) >= 2:
        dtotal = sum(d["bytes_total"] for d in devs)
        top = devs[0]
        if dtotal and top["bytes_total"] / dtotal >= 0.5:
            add("info", "Busiest device", f"{top['name']} generated about {100 * top['bytes_total'] / dtotal:.0f}% of the traffic seen from local devices.")

    # --- encryption / peaks ---------------------------------------------
    enc = sum(p["bytes"] for p in snap["protocols"] if p["name"] in ("HTTPS/TLS", "QUIC"))
    if total and enc / total >= 0.5:
        add("info", "Mostly encrypted", f"About {100 * enc / total:.0f}% of traffic is encrypted (HTTPS/QUIC). NetInsight can see where traffic goes and how much, but never the content.")
    if snap["peak_bps"] > 0:
        when = datetime.fromtimestamp(snap["peak_ts"]).strftime("%H:%M:%S")
        add("info", "Peak throughput", f"Peak throughput this session was {_fmt_rate(snap['peak_bps'])} at {when}.")
    util = m["bandwidth_util_pct"]
    if util is not None and util >= 70:
        add("warn", "Link nearly full", f"Current traffic uses about {util:.0f}% of the configured link speed, so congestion is likely.")

    if snap["health"]["score"] is not None and snap["health"]["score"] >= 90 and not any(i["level"] in ("warn", "bad") for i in out):
        add("good", "Network looks healthy", "Latency, loss and DNS are all within normal ranges.")
    return out
