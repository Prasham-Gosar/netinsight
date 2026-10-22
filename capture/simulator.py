"""
simulator.py
-------------
A traffic generator so the WHOLE system can be demonstrated and tested
without Npcap, Administrator rights or a busy network.

It builds genuine Scapy packets (real TCP handshakes, DNS questions and
answers with realistic delays, TLS ClientHellos produced by OpenSSL, UDP
call streams, ARP, ping, ...) and feeds them through the SAME parser and
pipeline as live capture. So everything downstream - app detection, flow
tracking, health score, anomaly detection - runs on real packet structures.

Demo network (as if captured on a router / mirrored port, so several
devices are visible):
    laptop 192.168.1.5   router 192.168.1.1   phone 192.168.1.8 (private MAC)
    TV 192.168.1.12      printer 192.168.1.30

You can inject problems on demand:
    dns_burst        a burst of DNS lookups (~10x normal)
    degradation      high latency, packet loss, failed connections
    bandwidth_spike  a big download
    scan             one host probing many addresses

Time is LOGICAL: stream() yields (timestamp, packet) in order. The live
runner sleeps until each timestamp; tests simply consume it instantly.
"""

import heapq
import itertools
import math
import random
import ssl
import threading
import time

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw

DEVICES = {
    "laptop": ("192.168.1.5", "3c:97:0e:11:22:33"),
    "router": ("192.168.1.1", "50:c7:bf:aa:bb:cc"),
    "phone": ("192.168.1.8", "da:a1:19:5c:2e:41"),     # locally-administered (private) MAC
    "tv": ("192.168.1.12", "8c:77:12:44:55:66"),
    "printer": ("192.168.1.30", "00:17:a4:12:34:56"),
}
IP_TO_MAC = {ip: mac for ip, mac in DEVICES.values()}
LAN_IPS = set(IP_TO_MAC)
ROUTER_IP, ROUTER_MAC = DEVICES["router"]

SERVICES = {
    "youtube": ("rr3---sn-gwpa-cvnl.googlevideo.com", ["142.250.77.46", "142.250.193.78"]),
    "netflix": ("ipv4-c001-bom001.1.oca.nflxvideo.net", ["45.57.90.1"]),
    "zoom": ("us02web.zoom.us", ["170.114.52.2"]),
    "instagram": ("scontent.cdninstagram.com", ["157.240.198.63"]),
    "spotify": ("audio-fa.scdn.co", ["35.186.224.25"]),
    "steam": ("cdn.steamcontent.com", ["23.62.10.10"]),
}
WEB = [
    ("www.google.com", "142.250.182.4"), ("github.com", "140.82.112.3"),
    ("www.reddit.com", "151.101.1.140"), ("en.wikipedia.org", "103.102.166.224"),
    ("outlook.office.com", "13.107.42.12"), ("www.canva.com", "104.16.20.1"),
    ("claude.ai", "160.79.104.10"), ("example.org", "93.184.216.34"),
    ("pypi.org", "151.101.0.223"), ("www.amazon.in", "52.84.150.12"),
]

_hello_cache = {}


def client_hello(domain):
    """A genuine TLS ClientHello for `domain`, produced by OpenSSL."""
    hello = _hello_cache.get(domain)
    if hello is None:
        ctx = ssl.create_default_context()
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        conn = ctx.wrap_bio(inc, out, server_hostname=domain)
        try:
            conn.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = _hello_cache[domain] = out.read()
    return hello


class _Stream:
    """A long-lived flow such as a YouTube video or a Zoom call."""

    def __init__(self, dev, svc, proto, pps_down, pps_up, size_down, size_up, start_at, port=443):
        self.dev, self.svc, self.proto = dev, svc, proto
        self.domain, ips = SERVICES[svc]
        self.server_ip = ips[0]
        self.port = port
        self.pps_down, self.pps_up = pps_down, pps_up
        self.size_down, self.size_up = size_down, size_up
        self.start_at = start_at
        self.started = False
        self.cport = 0
        self.c_seq = self.s_seq = 0
        self.rtt = 0.03


class TrafficSimulator:
    def __init__(self, seed=7, scale=1.0):
        self.rng = random.Random(seed)
        self.scale = scale
        self._events = []                 # injected (kind, start, end)
        self._lock = threading.Lock()
        self._plan_t = None
        self._counter = itertools.count()
        self._resolved = {}               # domain -> time until which DNS is "cached"
        self._streams = []
        self._tcp_id = itertools.count(1)
        self._spike_seq = 1_000_000
        self._dns_id = itertools.count(1000)

    # ---- injected problems ------------------------------------------------
    def inject(self, kind, duration=30.0, at=None):
        with self._lock:
            start = at if at is not None else (self._plan_t if self._plan_t is not None else time.time())
            self._events.append((kind, start, start + duration))

    def _active(self, kind, t):
        with self._lock:
            return any(k == kind and s <= t < e for k, s, e in self._events)

    # ---- small helpers --------------------------------------------------------
    def _poisson(self, lam):
        if lam <= 0:
            return 0
        limit, k, p = math.exp(-lam), 0, 1.0
        while True:
            p *= self.rng.random()
            if p <= limit:
                return k
            k += 1

    def _port(self):
        return self.rng.randint(49200, 65000)

    def _macs(self, src, dst):
        sm = IP_TO_MAC.get(src, ROUTER_MAC)
        dm = IP_TO_MAC.get(dst, ROUTER_MAC)
        return sm, dm

    def _tcp(self, ts, src, sport, dst, dport, flags, seq, ack, n=0, payload=None):
        sm, dm = self._macs(src, dst)
        pkt = (Ether(src=sm, dst=dm) / IP(src=src, dst=dst, ttl=64 if src in LAN_IPS else 52) /
               TCP(sport=sport, dport=dport, flags=flags, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF, window=65535))
        body = payload if payload is not None else (b"\x00" * n if n else b"")
        if body:
            pkt = pkt / Raw(body)
        return ts, Ether(bytes(pkt))

    def _udp(self, ts, src, sport, dst, dport, n=0, dns=None, dst_mac=None):
        sm, dm = self._macs(src, dst)
        pkt = Ether(src=sm, dst=dst_mac or dm) / IP(src=src, dst=dst, ttl=64 if src in LAN_IPS else 52) / UDP(sport=sport, dport=dport)
        pkt = pkt / dns if dns is not None else (pkt / Raw(b"\x00" * n) if n else pkt)
        return ts, Ether(bytes(pkt))

    def _rtt(self, t, base=None):
        base = base if base is not None else self.rng.uniform(0.012, 0.045)
        if self._active("degradation", t):
            return base * 4 + self.rng.uniform(0.08, 0.2)
        return base * self.rng.uniform(0.85, 1.25)

    # ---- building blocks ------------------------------------------------------
    def _dns(self, t, dev_ip, qname, answer_ip=None, nxdomain=False):
        qid = next(self._dns_id) & 0xFFFF
        sport = self._port()
        degraded = self._active("degradation", t)
        out = [self._udp(t, dev_ip, sport, ROUTER_IP, 53, dns=DNS(id=qid, rd=1, qd=DNSQR(qname=qname)))]
        if degraded and self.rng.random() < 0.05:
            return out                                        # lookup never answered
        latency = self.rng.uniform(0.15, 0.6) if degraded else self.rng.uniform(0.008, 0.04)
        if nxdomain:
            resp = DNS(id=qid, qr=1, ra=1, rcode=3, qd=DNSQR(qname=qname))
        else:
            resp = DNS(id=qid, qr=1, ra=1, qd=DNSQR(qname=qname),
                       an=DNSRR(rrname=qname, type="A", rdata=answer_ip or "93.184.216.34", ttl=120), ancount=1)
        out.append(self._udp(t + latency, ROUTER_IP, 53, dev_ip, sport, dns=resp))
        return out

    def _handshake(self, t, dev_ip, sport, server_ip, port, rtt):
        c_seq, s_seq = self.rng.randrange(1 << 32), self.rng.randrange(1 << 32)
        pk = [self._tcp(t, dev_ip, sport, server_ip, port, "S", c_seq, 0),
              self._tcp(t + rtt, server_ip, port, dev_ip, sport, "SA", s_seq, c_seq + 1),
              self._tcp(t + rtt + 0.0004, dev_ip, sport, server_ip, port, "A", c_seq + 1, s_seq + 1)]
        return pk, c_seq + 1, s_seq + 1

    def _web_session(self, t, dev_ip):
        domain, server_ip = self.rng.choice(WEB)
        pk = []
        if self._resolved.get(domain, 0) < t:
            pk += self._dns(t, dev_ip, domain, server_ip)
            self._resolved[domain] = t + 60
            t += 0.05
        sport, rtt = self._port(), self._rtt(t)
        degraded = self._active("degradation", t)

        if degraded and self.rng.random() < 0.15:           # failed connection attempt
            c_seq = self.rng.randrange(1 << 32)
            pk.append(self._tcp(t, dev_ip, sport, server_ip, 443, "S", c_seq, 0))
            if self.rng.random() < 0.5:
                pk.append(self._tcp(t + 0.08, server_ip, 443, dev_ip, sport, "RA", 0, c_seq + 1))
            else:
                pk.append(self._tcp(t + 1.0, dev_ip, sport, server_ip, 443, "S", c_seq, 0))   # SYN retry, no answer
            return pk

        hs, c_seq, s_seq = self._handshake(t, dev_ip, sport, server_ip, 443, rtt)
        pk += hs
        t += rtt + 0.001
        hello = client_hello(domain)
        pk.append(self._tcp(t, dev_ip, sport, server_ip, 443, "PA", c_seq, s_seq, payload=hello))
        c_seq += len(hello)
        t += rtt
        pk.append(self._tcp(t, server_ip, 443, dev_ip, sport, "A", s_seq, c_seq))
        for i in range(self.rng.randint(4, 30)):
            t += 0.004
            pk.append(self._tcp(t, server_ip, 443, dev_ip, sport, "PA", s_seq, c_seq, n=1400))
            s_seq += 1400
            if i % 2:
                pk.append(self._tcp(t + 0.0005, dev_ip, sport, server_ip, 443, "A", c_seq, s_seq))
        t += 0.01
        pk.append(self._tcp(t, dev_ip, sport, server_ip, 443, "FA", c_seq, s_seq))
        pk.append(self._tcp(t + rtt, server_ip, 443, dev_ip, sport, "FA", s_seq, c_seq + 1))
        pk.append(self._tcp(t + rtt + 0.0004, dev_ip, sport, server_ip, 443, "A", c_seq + 1, s_seq + 1))
        return pk

    def _ping(self, t, dev_ip, target="8.8.8.8"):
        rtt = self._rtt(t, self.rng.uniform(0.018, 0.035))
        sm, dm = self._macs(dev_ip, target)
        ident, seq = self.rng.randrange(65535), self.rng.randrange(1000)
        req = Ether(src=sm, dst=dm) / IP(src=dev_ip, dst=target) / ICMP(type=8, id=ident, seq=seq)
        rep = Ether(src=dm, dst=sm) / IP(src=target, dst=dev_ip) / ICMP(type=0, id=ident, seq=seq)
        return [(t, Ether(bytes(req))), (t + rtt, Ether(bytes(rep)))]

    def _arp_pair(self, t, asker, target):
        a_ip, a_mac = DEVICES[asker]
        t_ip, t_mac = DEVICES[target]
        req = Ether(src=a_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=a_mac, psrc=a_ip, pdst=t_ip)
        rep = Ether(src=t_mac, dst=a_mac) / ARP(op=2, hwsrc=t_mac, psrc=t_ip, hwdst=a_mac, pdst=a_ip)
        return [(t, Ether(bytes(req))), (t + 0.002, Ether(bytes(rep)))]

    def _multicast(self, t, dev, group, mac, port, n):
        ip, dmac = DEVICES[dev][0], DEVICES[dev][1]
        pkt = Ether(src=dmac, dst=mac) / IP(src=ip, dst=group, ttl=1) / UDP(sport=port, dport=port) / Raw(b"\x00" * n)
        return [(t, Ether(bytes(pkt)))]

    # ---- long-lived streams ---------------------------------------------------
    def _init_streams(self, t0):
        s = self.scale
        self._streams = [
            _Stream("laptop", "youtube", "tcp", 80 * s, 40 * s, 1400, 0, t0 + 1.0),
            _Stream("laptop", "zoom", "udp", 25 * s, 25 * s, 620, 340, t0 + 2.0, port=8801),
            _Stream("tv", "netflix", "tcp", 60 * s, 30 * s, 1400, 0, t0 + 3.0),
            _Stream("phone", "instagram", "tcp", 18 * s, 9 * s, 1300, 0, t0 + 4.0),
            _Stream("laptop", "spotify", "tcp", 5 * s, 3 * s, 1400, 0, t0 + 5.0),
        ]

    def _stream_second(self, t, st, out):
        dev_ip = DEVICES[st.dev][0]
        if not st.started:
            if t < st.start_at:
                return
            st.started = True
            st.cport = self._port()
            if st.proto == "tcp":
                out += self._dns(t, dev_ip, st.domain, st.server_ip)
                st.rtt = self._rtt(t)
                hs, st.c_seq, st.s_seq = self._handshake(t + 0.05, dev_ip, st.cport, st.server_ip, st.port, st.rtt)
                out += hs
                hello = client_hello(st.domain)
                tt = t + 0.05 + st.rtt + 0.002
                out.append(self._tcp(tt, dev_ip, st.cport, st.server_ip, st.port, "PA", st.c_seq, st.s_seq, payload=hello))
                st.c_seq += len(hello)
            else:
                out += self._dns(t, dev_ip, st.domain, st.server_ip)
            return

        degraded = self._active("degradation", t)
        n_down = self._poisson(st.pps_down)
        times = sorted(t + self.rng.random() for _ in range(n_down))
        for i, ts in enumerate(times):
            if st.proto == "udp":
                out.append(self._udp(ts, st.server_ip, st.port, dev_ip, st.cport, n=st.size_down))
                continue
            seq = st.s_seq
            st.s_seq += st.size_down
            if degraded and self.rng.random() < 0.05:            # this segment is "lost" ...
                out.append(self._tcp(ts + self.rng.uniform(0.2, 0.5), st.server_ip, st.port, dev_ip, st.cport,
                                     "PA", seq, st.c_seq, n=st.size_down))   # ... and retransmitted later
                for k in range(3):                                          # receiver repeats its ACK
                    out.append(self._tcp(ts + 0.03 + k * 0.002, dev_ip, st.cport, st.server_ip, st.port,
                                         "A", st.c_seq, seq))
                continue
            out.append(self._tcp(ts, st.server_ip, st.port, dev_ip, st.cport, "PA", seq, st.c_seq, n=st.size_down))
            if i % 2:
                out.append(self._tcp(ts + 0.0006, dev_ip, st.cport, st.server_ip, st.port, "A", st.c_seq, st.s_seq))
        if st.proto == "udp":
            for _ in range(self._poisson(st.pps_up)):
                out.append(self._udp(t + self.rng.random(), dev_ip, st.cport, st.server_ip, st.port, n=st.size_up))

    # ---- injected scenarios ---------------------------------------------------
    def _scenario_second(self, t, out):
        s = max(self.scale, 0.3)
        laptop = DEVICES["laptop"][0]
        if self._active("dns_burst", t):
            for _ in range(int(25 * s) + 3):
                name = "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8)) + ".metrics-sync.net"
                out += self._dns(t + self.rng.random() * 0.95, laptop, name,
                                 nxdomain=self.rng.random() < 0.5, answer_ip="104.21.5.5")
        if self._active("bandwidth_spike", t):
            domain, ips = SERVICES["steam"]
            for ts in sorted(t + self.rng.random() for _ in range(int(900 * s))):
                out.append(self._tcp(ts, ips[0], 443, laptop, 51888, "PA", self._spike_seq, 1, n=1400))
                self._spike_seq += 1400                # sequential, in time order (no fake retransmits)
        if self._active("scan", t):
            for _ in range(int(30 * s) + 6):
                target = f"{self.rng.randint(11, 190)}.{self.rng.randint(1, 250)}.{self.rng.randint(1, 250)}.{self.rng.randint(2, 250)}"
                sport, tt = self._port(), t + self.rng.random() * 0.9
                seq = self.rng.randrange(1 << 32)
                out.append(self._tcp(tt, laptop, sport, target, 22, "S", seq, 0))
                out.append(self._tcp(tt + 0.03, target, 22, laptop, sport, "RA", 0, seq + 1))

    # ---- main generator -----------------------------------------------------------
    def _plan_second(self, t, out):
        s = self.scale
        with self._lock:
            self._plan_t = t
        for st in self._streams:
            self._stream_second(t, st, out)
        for _ in range(self._poisson(0.6 * s)):
            dev = self.rng.choice(["laptop", "laptop", "laptop", "phone"])
            out += self._web_session(t + self.rng.random() * 0.9, DEVICES[dev][0])
        for _ in range(self._poisson(0.35 * s)):                       # chatty background DNS
            domain, ip = self.rng.choice(WEB)
            out += self._dns(t + self.rng.random() * 0.9, DEVICES[self.rng.choice(["laptop", "phone"])][0], domain, ip)
        for _ in range(self._poisson(0.05 * s)):
            out += self._ping(t + self.rng.random(), DEVICES["laptop"][0])
        for _ in range(self._poisson(0.3 * s)):
            asker, target = self.rng.choice([("router", "laptop"), ("phone", "router"), ("laptop", "router"), ("tv", "router")])
            out += self._arp_pair(t + self.rng.random(), asker, target)
        for _ in range(self._poisson(0.2 * s)):
            out += self._multicast(t + self.rng.random(), "printer", "224.0.0.251", "01:00:5e:00:00:fb", 5353, 80)
        for _ in range(self._poisson(0.1 * s)):
            out += self._multicast(t + self.rng.random(), "tv", "239.255.255.250", "01:00:5e:7f:ff:fa", 1900, 120)
        self._scenario_second(t, out)

    def stream(self, start, duration=None):
        """Yield (timestamp, packet) in time order, forever (or for `duration` seconds)."""
        self._init_streams(start)
        heap, t = [], start
        end = None if duration is None else start + duration
        while end is None or t < end:
            fresh = []
            self._plan_second(t, fresh)
            for ts, pkt in fresh:
                heapq.heappush(heap, (ts, next(self._counter), pkt))
            t_next = t + 1.0
            while heap and heap[0][0] < t_next:
                ts, _, pkt = heapq.heappop(heap)
                yield ts, pkt
            t = t_next


class SimulatorRunner:
    """Feeds a simulator into the engine's queue in real time (wall-clock speed)."""

    def __init__(self, simulator, packet_queue):
        self.sim, self.queue = simulator, packet_queue
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="simulator")
        self._thread.start()

    def _run(self):
        for ts, pkt in self.sim.stream(time.time()):
            if self._stop.is_set():
                return
            delay = ts - time.time()
            if delay > 0:
                time.sleep(delay)
            self.queue.put((ts, pkt))

    def stop(self):
        self._stop.set()
