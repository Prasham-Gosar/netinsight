"""
flow_tracker.py
----------------
Groups packets into FLOWS (conversations) and watches TCP behaviour.

A flow is every packet between the same two endpoints:
    (TCP, 192.168.1.5:51432  <->  142.250.1.1:443)

Analogy: a phone-call log. Instead of remembering every word, we log one
line per call: who called whom, how long, how much was said, and whether
the line was crackly.

From TCP headers alone (no content!) we can measure real network quality:

  * Round-trip time  - time between SYN and SYN/ACK in the 3-way handshake
  * Retransmission   - the same sequence number sent again => the first copy was probably lost
  * Sequence gap     - a segment skipped ahead => something before it went missing
  * Duplicate ACK    - receiver repeating "I still need that earlier segment"
  * Failed connection- SYN answered by RST, or never answered at all
"""

MASK = 0xFFFFFFFF
HALF = 0x80000000
SANE_GAP = 1 << 20           # ignore giant jumps (capture started mid-stream)
SYN_TIMEOUT = 5.0


class Flow:
    __slots__ = ("key", "proto", "app_protocol", "client", "server", "packets", "bytes",
                 "bytes_c2s", "bytes_s2c", "start", "last", "app", "domain", "state",
                 "syn_ts", "rtt_ms", "retrans", "seq_gaps", "dup_acks", "next_seq",
                 "last_ack", "fins", "failed")

    def __init__(self, key, proto, client, server, ts):
        self.key, self.proto = key, proto
        self.client, self.server = client, server
        self.app_protocol = None
        self.packets = self.bytes = self.bytes_c2s = self.bytes_s2c = 0
        self.start = self.last = ts
        self.app = None
        self.domain = None
        self.state = "ACTIVE"
        self.syn_ts = None
        self.rtt_ms = None
        self.retrans = self.seq_gaps = self.dup_acks = 0
        self.next_seq = [None, None]
        self.last_ack = [None, None]
        self.fins = set()
        self.failed = False


class FlowTracker:
    def __init__(self, ts_store, rtt_samples, idle_timeout=120, max_flows=5000):
        self.ts = ts_store
        self.rtt = rtt_samples
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        self.flows = {}
        self.finished = 0

    # ------------------------------------------------------------------
    def update(self, rec, app=None, domain=None):
        proto = rec["protocol"]
        if proto not in ("TCP", "UDP", "ICMP", "ICMPv6"):
            return None
        ts = rec["ts"]
        src = (rec["src_ip"], rec["src_port"] or 0)
        dst = (rec["dst_ip"], rec["dst_port"] or 0)
        key = (proto,) + tuple(sorted((src, dst)))

        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= self.max_flows:
                self._evict()
            flags = rec["tcp_flags"] or ""
            if proto == "TCP" and "S" in flags and "A" not in flags:
                client, server = src, dst
            elif proto == "TCP" and "S" in flags and "A" in flags:
                client, server = dst, src
            elif 0 < src[1] < 1024 <= dst[1]:
                client, server = dst, src       # we joined mid-conversation
            else:
                client, server = src, dst
            f = self.flows[key] = Flow(key, proto, client, server, ts)
            f.app_protocol = rec.get("app_protocol")

        size = rec["packet_size"]
        f.packets += 1
        f.bytes += size
        f.last = ts
        from_client = (src == f.client)
        if from_client:
            f.bytes_c2s += size
        else:
            f.bytes_s2c += size
        if app and app != "Unclassified" and f.app in (None, "Unclassified"):
            f.app = app
        if domain and not f.domain:
            f.domain = domain

        if proto == "TCP":
            self._tcp(f, rec, 0 if from_client else 1)
        return f

    # ------------------------------------------------------------------
    def _tcp(self, f, rec, side):
        ts_store, ts = self.ts, rec["ts"]
        flags = rec["tcp_flags"] or ""
        syn, ack, fin, rst = "S" in flags, "A" in flags, "F" in flags, "R" in flags
        plen, seq, ackn = rec["payload_len"], rec["seq"], rec["ack"]

        ts_store.add(ts, "tcp_pkts")
        if plen > 0:
            ts_store.add(ts, "tcp_data")

        if rst:
            ts_store.add(ts, "rst")
            if f.state == "SYN_SENT" and not f.failed:
                f.failed = True
                ts_store.add(ts, "conn_fail")
            f.state = "RESET"
            return

        # --- sequence tracking: retransmissions and gaps ---------------
        seg = plen + (1 if syn else 0) + (1 if fin else 0)
        if seg > 0 and seq is not None:
            end = (seq + seg) & MASK
            expected = f.next_seq[side]
            if expected is None:
                f.next_seq[side] = end
            else:
                diff = (seq - expected) & MASK
                if diff == 0:
                    f.next_seq[side] = end
                elif diff >= HALF:                       # behind what we expected
                    if plen > 0 or syn:
                        f.retrans += 1
                        ts_store.add(ts, "retrans")
                    if ((end - expected) & MASK) < HALF and end != expected:
                        f.next_seq[side] = end
                elif diff < SANE_GAP:                    # skipped ahead
                    f.seq_gaps += 1
                    ts_store.add(ts, "seq_gap")
                    f.next_seq[side] = end
                else:
                    f.next_seq[side] = end               # resync, don't count

        # --- duplicate ACKs -------------------------------------------
        if ack and ackn is not None:
            if flags == "A" and plen == 0:
                last, outstanding = f.last_ack[side], f.next_seq[1 - side]
                if (last is not None and last == ackn and outstanding is not None
                        and 0 < ((outstanding - ackn) & MASK) < HALF):
                    f.dup_acks += 1
                    ts_store.add(ts, "dup_ack")
            f.last_ack[side] = ackn

        # --- handshake / state machine --------------------------------
        if syn and not ack:
            if f.syn_ts is None:
                f.syn_ts = ts
                f.state = "SYN_SENT"
                ts_store.add(ts, "syn")
        elif syn and ack:
            if f.syn_ts is not None and f.rtt_ms is None and side == 1:
                f.rtt_ms = max(0.0, (ts - f.syn_ts) * 1000.0)
                self.rtt.add(ts, f.rtt_ms)
            if f.state == "SYN_SENT":
                f.state = "SYN_RECEIVED"
        elif ack and f.state == "SYN_RECEIVED" and side == 0:
            f.state = "ESTABLISHED"
            ts_store.add(ts, "conn_ok")

        if fin:
            f.fins.add(side)
            f.state = "CLOSED" if len(f.fins) == 2 else "CLOSING"
        elif f.state == "ACTIVE" and ack:
            f.state = "ESTABLISHED"          # joined mid-stream

    # ------------------------------------------------------------------
    def sweep(self, now):
        """Housekeeping: time out unanswered SYNs, forget idle flows."""
        for f in list(self.flows.values()):
            if f.state == "SYN_SENT" and not f.failed and now - f.syn_ts > SYN_TIMEOUT:
                f.failed = True
                f.state = "TIMEOUT"
                self.ts.add(f.syn_ts + SYN_TIMEOUT, "conn_fail")
            if now - f.last > self.idle_timeout:
                del self.flows[f.key]
                self.finished += 1

    def _evict(self):
        oldest = sorted(self.flows.values(), key=lambda x: x.last)[: self.max_flows // 10]
        for f in oldest:
            self.flows.pop(f.key, None)
            self.finished += 1

    def top_flows(self, n=15):
        flows = sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)[:n]
        return [{
            "proto": f.proto,
            "app_protocol": f.app_protocol,
            "client": f"{f.client[0]}:{f.client[1]}" if f.client[1] else f.client[0],
            "server": f"{f.server[0]}:{f.server[1]}" if f.server[1] else f.server[0],
            "app": f.app or "Unclassified",
            "domain": f.domain,
            "packets": f.packets,
            "bytes": f.bytes,
            "bytes_c2s": f.bytes_c2s,
            "bytes_s2c": f.bytes_s2c,
            "duration": round(f.last - f.start, 1),
            "state": f.state,
            "rtt_ms": round(f.rtt_ms, 1) if f.rtt_ms is not None else None,
            "retransmissions": f.retrans,
        } for f in flows]

    def active_count(self):
        return len(self.flows)
