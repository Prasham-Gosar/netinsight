"""
Automated checks for Phase 2 + 3. Run from the project folder with:

    python -m unittest discover -s tests -v

No Npcap, no Administrator rights and no network needed: packets come from the
simulator (which builds real Scapy packets), time is fast-forwarded.
"""

import os
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import DNS, DNSQR, DNSRR, ARP, ICMP, IP, TCP, UDP, Ether, Raw

from capture.packet_parser import parse_packet
from capture.protocol_identifier import identify_application_protocol, protocol_family
from capture.simulator import DEVICES, TrafficSimulator
from capture.tls_sni import extract_http_host, extract_sni
from core.app_detector import AppDetector, domain_to_app
from core.engine import Engine
from core.explainer import explain_packet
from core.flow_tracker import FlowTracker
from core.health import HealthMonitor
from core.netutil import NetContext, valid_unicast_mac
from core.oui import is_randomized, lookup_vendor
from core.timeseries import SampleStore, TimeSeries
from db.database import Database


def real_client_hello(domain):
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    conn = ctx.wrap_bio(inc, out, server_hostname=domain)
    try:
        conn.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def tcp_pkt(src, sport, dst, dport, flags, seq=1, ack=0, n=0, payload=None):
    body = payload if payload is not None else (b"\x00" * n)
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if body:
        pkt = pkt / Raw(body)
    return Ether(bytes(pkt))


def make_ctx():
    return NetContext(local_ips=["192.168.1.5"], gateway_ip="192.168.1.1", link_mbps=100)


class ParserTests(unittest.TestCase):
    def test_sni_from_real_openssl_hello(self):
        self.assertEqual(extract_sni(real_client_hello("www.youtube.com")), "www.youtube.com")

    def test_sni_garbage_and_truncated(self):
        hello = real_client_hello("example.org")
        self.assertIsNone(extract_sni(b""))
        self.assertIsNone(extract_sni(b"\x16\x03\x01"))
        self.assertIsNone(extract_sni(hello[:60]))        # truncated before extensions
        self.assertIsNone(extract_sni(b"GET / HTTP/1.1\r\n"))

    def test_http_host(self):
        self.assertEqual(extract_http_host(b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n"), "example.com")
        self.assertIsNone(extract_http_host(b"\x16\x03\x01\x00"))

    def test_tcp_fields_and_padding(self):
        r = parse_packet(tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "A", seq=10, ack=20), ts=5.0)
        self.assertEqual((r["seq"], r["ack"], r["payload_len"], r["tcp_flags"]), (10, 20, 0, "A"))   # padding ignored
        r = parse_packet(tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "PA", n=700), ts=5.0)
        self.assertEqual(r["payload_len"], 700)

    def test_dns_query_and_response(self):
        q = Ether(bytes(Ether() / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=5555, dport=53) /
                        DNS(id=9, rd=1, qd=DNSQR(qname="www.youtube.com"))))
        r = parse_packet(q, ts=1)
        self.assertEqual((r["dns"]["qr"], r["dns"]["qname"], r["dns"]["id"]), (0, "www.youtube.com", 9))
        a = Ether(bytes(Ether() / IP(src="8.8.8.8", dst="192.168.1.5") / UDP(sport=53, dport=5555) /
                        DNS(id=9, qr=1, qd=DNSQR(qname="www.youtube.com"),
                            an=DNSRR(rrname="www.youtube.com", type="A", rdata="142.250.1.1", ttl=60), ancount=1)))
        self.assertEqual(parse_packet(a, ts=1)["dns"]["answers"], ["142.250.1.1"])

    def test_arp_uses_inner_hardware_addresses(self):
        pkt = Ether(bytes(Ether() / ARP(op=1, psrc="192.168.1.8", pdst="192.168.1.1", hwsrc="da:a1:19:5c:2e:41")))
        r = parse_packet(pkt, ts=1)
        self.assertEqual((r["protocol"], r["src_mac"], r["arp_op"]), ("ARP", "da:a1:19:5c:2e:41", 1))

    def test_protocol_identification(self):
        quic = parse_packet(Ether(bytes(Ether() / IP(src="192.168.1.5", dst="142.250.1.1") / UDP(sport=5000, dport=443))), ts=1)
        quic["app_protocol"] = identify_application_protocol(quic)
        self.assertEqual(quic["app_protocol"], "QUIC")
        self.assertEqual(protocol_family(quic), "UDP")
        https = parse_packet(tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "S"), ts=1)
        self.assertEqual(identify_application_protocol(https), "HTTPS/TLS")


class NetContextTests(unittest.TestCase):
    def test_direction(self):
        c = make_ctx()
        self.assertEqual(c.direction("192.168.1.5", "8.8.8.8"), "out")
        self.assertEqual(c.direction("8.8.8.8", "192.168.1.5"), "in")
        self.assertEqual(c.direction("192.168.1.5", "192.168.1.1"), "local")
        self.assertEqual(c.direction("192.168.1.8", "142.250.1.1"), "out")      # another LAN device
        self.assertEqual(c.direction("192.168.1.5", "224.0.0.251"), "local")

    def test_mac_validation(self):
        self.assertTrue(valid_unicast_mac("3c:97:0e:11:22:33"))
        self.assertFalse(valid_unicast_mac("ff:ff:ff:ff:ff:ff"))
        self.assertFalse(valid_unicast_mac("01:00:5e:00:00:fb"))                  # multicast
        self.assertFalse(valid_unicast_mac(None))

    def test_oui(self):
        self.assertEqual(lookup_vendor("3c:97:0e:11:22:33"), "Intel")
        self.assertTrue(is_randomized("da:a1:19:5c:2e:41"))
        self.assertIsNone(lookup_vendor("da:a1:19:5c:2e:41"))


class AppDetectionTests(unittest.TestCase):
    def test_longest_suffix_wins(self):
        self.assertEqual(domain_to_app("meet.google.com"), "Google Meet")
        self.assertEqual(domain_to_app("www.google.com"), "Google")
        self.assertEqual(domain_to_app("rr1---sn-x.googlevideo.com"), "YouTube")
        self.assertIsNone(domain_to_app("unknown-site.example"))
        self.assertIsNone(domain_to_app("com"))

    def test_dns_then_ip_traffic_is_attributed(self):
        det = AppDetector()
        resp = {"dns": {"qr": 1, "qname": "www.youtube.com", "answers": ["142.250.1.1"], "id": 1, "rcode": 0},
                "sni": None, "http_host": None, "app_protocol": "DNS"}
        self.assertEqual(det.classify(resp, "8.8.8.8")["app"], "DNS")
        later = {"dns": None, "sni": None, "http_host": None, "app_protocol": "HTTPS/TLS"}
        got = det.classify(later, "142.250.1.1")
        self.assertEqual((got["app"], got["method"]), ("YouTube", "dns"))

    def test_sni_beats_dns(self):
        det = AppDetector()
        det._remember("1.2.3.4", "cdn.example.net", "dns")
        rec = {"dns": None, "sni": "www.netflix.com", "http_host": None, "app_protocol": "HTTPS/TLS"}
        self.assertEqual(det.classify(rec, "1.2.3.4")["app"], "Netflix")

    def test_unknown_and_known_ranges(self):
        det = AppDetector()
        self.assertEqual(det.classify({"dns": None, "sni": None, "http_host": None, "app_protocol": "ICMP"}, "8.8.8.8")["app"], "Google DNS")
        self.assertEqual(det.classify({"dns": None, "sni": None, "http_host": None, "app_protocol": "TCP"}, "5.5.5.5")["app"], "Unclassified")


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.ts, self.rtt = TimeSeries(), SampleStore()
        self.ft = FlowTracker(self.ts, self.rtt)

    def feed(self, ts, pkt):
        rec = parse_packet(pkt, ts)
        rec["app_protocol"] = identify_application_protocol(rec)
        self.ft.update(rec)

    def test_handshake_rtt(self):
        self.feed(100.0, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "S", seq=100))
        self.feed(100.050, tcp_pkt("1.1.1.1", 443, "192.168.1.5", 5000, "SA", seq=900, ack=101))
        self.feed(100.051, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "A", seq=101, ack=901))
        self.assertAlmostEqual(self.rtt.values(10, 101)[0], 50.0, delta=1.0)
        self.assertEqual(self.ts.window_sum("conn_ok", 5, 102), 1)

    def test_retransmission_gap_and_dup_ack(self):
        self.feed(10.0, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "S", seq=100))
        self.feed(10.02, tcp_pkt("1.1.1.1", 443, "192.168.1.5", 5000, "SA", seq=900, ack=101))
        self.feed(10.03, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "A", seq=101, ack=901))
        self.feed(11.0, tcp_pkt("1.1.1.1", 443, "192.168.1.5", 5000, "PA", seq=901, ack=101, n=1000))   # in order
        self.feed(11.1, tcp_pkt("1.1.1.1", 443, "192.168.1.5", 5000, "PA", seq=2901, ack=101, n=1000))  # gap: 1901 missing
        self.feed(11.2, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "A", seq=101, ack=1901))
        self.feed(11.21, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 443, "A", seq=101, ack=1901))          # duplicate ACK
        self.feed(11.5, tcp_pkt("1.1.1.1", 443, "192.168.1.5", 5000, "PA", seq=1901, ack=101, n=1000))  # retransmission
        self.assertEqual(self.ts.window_sum("seq_gap", 5, 13), 1)
        self.assertEqual(self.ts.window_sum("dup_ack", 5, 13), 1)
        self.assertEqual(self.ts.window_sum("retrans", 5, 13), 1)

    def test_rst_and_timeout_are_failures(self):
        self.feed(10.0, tcp_pkt("192.168.1.5", 5000, "1.1.1.1", 22, "S", seq=1))
        self.feed(10.03, tcp_pkt("1.1.1.1", 22, "192.168.1.5", 5000, "RA", seq=0, ack=2))
        self.feed(20.0, tcp_pkt("192.168.1.5", 5001, "2.2.2.2", 22, "S", seq=1))
        self.ft.sweep(30.0)                                                   # never answered
        self.assertEqual(self.ts.window_sum("conn_fail", 30, 31), 2)


class HealthTests(unittest.TestCase):
    def make(self):
        ts, rtt, dns = TimeSeries(), SampleStore(), SampleStore()
        return ts, rtt, dns, HealthMonitor(ts, rtt, dns, make_ctx())

    def test_no_data_means_no_score(self):
        ts, rtt, dns, h = self.make()
        out = h.compute(100)
        self.assertIsNone(out["score"])
        self.assertEqual(out["status"], "Collecting data")

    def test_healthy_network(self):
        ts, rtt, dns, h = self.make()
        for s in range(40, 100):
            ts.add(s, "tcp_data", 20)
            if s % 10 == 0:
                rtt.add(s, 25.0)
                dns.add(s, 20.0)
        out = h.compute(100)
        self.assertGreaterEqual(out["score"], 95)
        self.assertEqual(out["status"], "Excellent")

    def test_bad_network_loses_points_with_reasons(self):
        ts, rtt, dns, h = self.make()
        for s in range(40, 100):
            ts.add(s, "tcp_data", 20)
            ts.add(s, "retrans", 2)
            ts.add(s, "seq_gap", 1)
            if s % 10 == 0:
                rtt.add(s, 300.0)
                dns.add(s, 400.0)
        out = h.compute(100)
        self.assertLess(out["score"], 60)
        self.assertTrue(any("packet loss" in i.lower() for i in out["issues"]))
        self.assertAlmostEqual(out["metrics"]["packet_loss_pct"], 15.0, places=1)


class ExplainerTests(unittest.TestCase):
    def test_sentences(self):
        syn = parse_packet(tcp_pkt("192.168.1.5", 5000, "142.250.1.1", 443, "S"), 1)
        syn.update(app_protocol="HTTPS/TLS", direction="out", domain="www.youtube.com", app="YouTube")
        self.assertIn("TCP connection", explain_packet(syn))
        self.assertIn("www.youtube.com", explain_packet(syn))
        hello = parse_packet(tcp_pkt("192.168.1.5", 5000, "142.250.1.1", 443, "PA", payload=real_client_hello("www.youtube.com")), 1)
        hello.update(app_protocol="HTTPS/TLS", direction="out", domain="www.youtube.com", app="YouTube")
        self.assertIn("encrypted", explain_packet(hello))
        arp = parse_packet(Ether(bytes(Ether() / ARP(op=1, psrc="192.168.1.8", pdst="192.168.1.1", hwsrc="da:a1:19:5c:2e:41"))), 1)
        self.assertIn("who has 192.168.1.1", explain_packet(arp))


def run_simulation(engine, sim, start, seconds, tick_every=1.0):
    last = start
    for ts, pkt in sim.stream(start, duration=seconds):
        engine.process((ts, pkt))
        if ts - last >= tick_every:
            last = ts
            engine.tick(ts)
    engine.tick(start + seconds)


class EndToEndTests(unittest.TestCase):
    T0 = 1_800_000_000.0

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(os.path.join(cls.tmp.name, "t.db"))
        ctx = NetContext(local_ips=[DEVICES["laptop"][0]], gateway_ip=DEVICES["router"][0], link_mbps=100)
        cls.engine = Engine(ctx, cls.db, mode="simulation", resolve_hostnames=False)
        cls.sim = TrafficSimulator(seed=11, scale=0.35)
        cls.sim.inject("dns_burst", 12, at=cls.T0 + 110)
        cls.sim.inject("degradation", 35, at=cls.T0 + 160)
        cls.marks = {}
        last = cls.T0
        for ts, pkt in cls.sim.stream(cls.T0, duration=215):
            cls.engine.process((ts, pkt))
            if ts - last >= 1:
                last = ts
                cls.engine.tick(ts)
                sec = int(ts - cls.T0)
                if sec in (100, 150, 190):
                    cls.marks[sec] = cls.engine.health.compute(ts)
        cls.engine.tick(cls.T0 + 215)
        cls.dash = cls.engine.dashboard()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def test_applications_detected(self):
        names = {a["name"] for a in self.dash["applications"]}
        self.assertTrue({"YouTube", "Netflix", "Zoom"} <= names, names)

    def test_devices_discovered_with_vendors(self):
        devs = {d["ip"]: d for d in self.dash["devices"]}
        self.assertGreaterEqual(len(devs), 4)
        self.assertTrue(devs["192.168.1.5"]["is_self"])
        self.assertTrue(devs["192.168.1.1"]["is_gateway"])
        self.assertEqual(devs["192.168.1.5"]["vendor"], "Intel")
        self.assertIn("Private", devs["192.168.1.8"]["vendor"])

    def test_protocol_families(self):
        fams = {f["name"] for f in self.dash["protocols"]}
        self.assertTrue({"TCP", "UDP", "DNS", "ARP"} <= fams, fams)
        self.assertAlmostEqual(sum(f["percent_packets"] for f in self.dash["protocols"]), 100.0, delta=0.5)

    def test_health_drops_during_degradation_and_is_good_before(self):
        before, during = self.marks[100], self.marks[190]
        self.assertGreaterEqual(before["score"], 90)
        self.assertLess(during["score"], before["score"] - 20)
        self.assertGreater(during["metrics"]["dns_latency_ms"], 150)

    def test_dns_burst_raises_one_alert_with_context_and_no_false_alarms(self):
        alerts = self.engine.anomaly.alerts
        self.assertEqual([a["metric"] for a in alerts if a["ts"] < self.T0 + 108], [], "false alarm during baseline")
        dns = [a for a in alerts if a["metric"] == "dns_q"]
        self.assertEqual(len(dns), 1)
        self.assertGreaterEqual(dns[0]["ratio"], 3)
        self.assertTrue(any("metrics-sync.net" in line for line in dns[0]["context"]))
        self.assertIn("Potentially unusual", dns[0]["advice"])

    def test_database_history(self):
        self.engine.flush(self.T0 + 215)
        answers = self.db.history_answers(self.T0 + 215)
        self.assertEqual(answers["top_application"]["name"], "YouTube")
        self.assertGreater(answers["traffic_today"]["total"], 1_000_000)
        timeline = self.db.history_timeline("minutes", self.T0 + 215)
        self.assertEqual(len(timeline), 60)
        self.assertGreater(sum(r["in"] for r in timeline), 0)
        self.assertGreater(self.db.total_packet_count(), 1000)
        self.assertIsNotNone(answers["slowest_minute"])

    def test_flush_is_idempotent_for_totals(self):
        self.engine.flush(self.T0 + 216)
        a = self.db.history_summary("24h", self.T0 + 216)["bytes_in"]
        self.engine.flush(self.T0 + 217)
        b = self.db.history_summary("24h", self.T0 + 217)["bytes_in"]
        self.assertEqual(a, b)

    def test_packet_feed_has_explanations(self):
        pk = self.dash["packets"]
        self.assertTrue(pk and all(p["explanation"] for p in pk))
        self.assertTrue(self.dash["insights"])


class ScenarioTests(unittest.TestCase):
    """Each injectable scenario must trip its own detector."""

    def run_scenario(self, kind, metric_expected):
        T0 = 1_800_100_000.0
        ctx = NetContext(local_ips=[DEVICES["laptop"][0]], gateway_ip=DEVICES["router"][0])
        engine = Engine(ctx, None, mode="simulation", resolve_hostnames=False)
        sim = TrafficSimulator(seed=5, scale=0.3)
        sim.inject(kind, 15, at=T0 + 100)
        run_simulation(engine, sim, T0, 130)
        fired = {a["metric"] for a in engine.anomaly.alerts}
        self.assertIn(metric_expected, fired, f"{kind}: fired {fired}")

    def test_bandwidth_spike(self):
        self.run_scenario("bandwidth_spike", "bytes")

    def test_scan(self):
        self.run_scenario("scan", "syn")

    def test_quiet_traffic_never_alerts(self):
        T0 = 1_800_200_000.0
        ctx = NetContext(local_ips=[DEVICES["laptop"][0]], gateway_ip=DEVICES["router"][0])
        engine = Engine(ctx, None, mode="simulation", resolve_hostnames=False)
        run_simulation(engine, TrafficSimulator(seed=9, scale=0.3), T0, 200)
        self.assertEqual(engine.anomaly.alerts, [])


class Phase1CompatibilityTests(unittest.TestCase):
    def test_old_phase1_database_is_upgraded(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.db")
            con = sqlite3.connect(path)
            con.executescript("""
                CREATE TABLE packets (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
                    src_mac TEXT, dst_mac TEXT, protocol TEXT, app_protocol TEXT, src_port INTEGER, dst_port INTEGER,
                    packet_size INTEGER, ttl INTEGER, tcp_flags TEXT);
                CREATE TABLE traffic_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, time_window TEXT NOT NULL, protocol TEXT,
                    packet_count INTEGER, total_bytes INTEGER);
                INSERT INTO traffic_stats (time_window, protocol, packet_count, total_bytes) VALUES ('2026-01-01T00:00:00','TCP',1,1);
            """)
            con.commit()
            con.close()
            db = Database(path)                       # must not raise
            db.flush_usage({(1, "dev", "app", "TCP", "in"): [1, 100]}, {}, 100.0)
            db.close()


if __name__ == "__main__":
    unittest.main()
