"""
test_pipeline.py
-----------------
Verifies parsing, protocol ID, queue, aggregator, and database logic
using synthetically-built packets (no live network / admin rights
needed). This is NOT part of the Phase 1 deliverable - it's just a
sanity check you can run anytime with: python test_pipeline.py
"""

from scapy.all import Ether, IP, TCP, UDP, ARP, ICMP, DNS, DNSQR

from capture.packet_parser import parse_packet
from capture.protocol_identifier import identify_application_protocol
from core.packet_queue import PacketQueue
from core.aggregator import TrafficAggregator
from db.database import Database

# Build a handful of fake packets covering different protocols
test_packets = [
    Ether() / IP(src="192.168.1.5", dst="8.8.8.8", ttl=64) / TCP(sport=51000, dport=443, flags="S"),
    Ether() / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=51001, dport=53) / DNS(qd=DNSQR(qname="youtube.com")),
    Ether() / IP(src="192.168.1.8", dst="192.168.1.5") / ICMP(),
    Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.5"),
    Ether() / IP(src="192.168.1.5", dst="142.250.1.1") / TCP(sport=51002, dport=80, flags="A"),
]

print("Step 1: Parsing + protocol identification")
records = []
for pkt in test_packets:
    record = parse_packet(pkt)
    assert record is not None, "parser should not drop a valid IP/ARP packet"
    record["app_protocol"] = identify_application_protocol(record)
    records.append(record)
    print(f"  {record['protocol']:<5} -> {record['app_protocol']:<10} "
          f"{record['src_ip']} -> {record['dst_ip']}  size={record['packet_size']}")

print("\nStep 2: Queue (producer/consumer)")
q = PacketQueue()
for r in records:
    q.put(r)
assert q.qsize() == len(records)
pulled = [q.get(timeout=0.1) for _ in records]
assert q.qsize() == 0
print(f"  Put {len(records)} records in, pulled {len(pulled)} back out. OK")

print("\nStep 3: Aggregator")
agg = TrafficAggregator()
for r in records:
    agg.add(r)
snap = agg.snapshot()
print(f"  total_packets={snap['total_packets']}  total_bytes={snap['total_bytes']}")
print(f"  protocol_packet_count={snap['protocol_packet_count']}")
print(f"  distribution%={agg.protocol_distribution_percent()}")
assert snap["total_packets"] == len(records)

print("\nStep 4: Database (SQLite)")
db = Database("test_netinsight.db")
db.insert_packets_batch(records)
count = db.total_packet_count()
print(f"  Rows in DB: {count}")
assert count == len(records)
db.flush_usage({(int(records[0]["ts"] // 60), "dev", "app", "TCP", "out"): [2, 108]}, {}, records[0]["ts"])
db.close()

print("\nALL CHECKS PASSED - Phase 1 pipeline logic is sound.")
print("(Phase 2/3 checks: python -m unittest discover -s tests -v)")
