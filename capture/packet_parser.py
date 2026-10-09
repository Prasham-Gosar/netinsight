"""
packet_parser.py
-----------------
Takes a raw Scapy packet (messy, layered) and turns it into a clean,
flat dictionary that the rest of NetInsight can work with.

Analogy: think of a raw packet like a nested set of envelopes inside
envelopes (Ethernet envelope -> IP envelope -> TCP/UDP envelope).
This module opens all the envelopes and lays the contents flat on a
table so nothing downstream has to know about Scapy's object model.
"""

from datetime import datetime
from scapy.all import IP, IPv6, TCP, UDP, ARP, ICMP, Ether


def parse_packet(packet):
    """
    Convert a raw Scapy packet into a structured dict.

    Returns None if the packet doesn't have anything useful to us
    (e.g. some non-IP link-layer noise) so the caller can just skip it.
    """
    record = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": None,
        "dst_ip": None,
        "src_mac": None,
        "dst_mac": None,
        "protocol": None,      # transport/network protocol: TCP/UDP/ICMP/ARP
        "src_port": None,
        "dst_port": None,
        "packet_size": len(packet),
        "ttl": None,
        "tcp_flags": None,
    }

    # --- Ethernet layer (MAC addresses) ---
    if packet.haslayer(Ether):
        record["src_mac"] = packet[Ether].src
        record["dst_mac"] = packet[Ether].dst

    # --- ARP is special: it has no IP layer, it's its own thing ---
    if packet.haslayer(ARP):
        record["protocol"] = "ARP"
        record["src_ip"] = packet[ARP].psrc
        record["dst_ip"] = packet[ARP].pdst
        return record

    # --- IPv4 layer ---
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        record["src_ip"] = ip_layer.src
        record["dst_ip"] = ip_layer.dst
        record["ttl"] = ip_layer.ttl
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        record["src_ip"] = ip_layer.src
        record["dst_ip"] = ip_layer.dst
        record["ttl"] = ip_layer.hlim
    else:
        # No IP layer and no ARP -> nothing we care about for Phase 1
        if record["src_ip"] is None:
            return None

    # --- Transport layer ---
    if packet.haslayer(TCP):
        record["protocol"] = "TCP"
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        record["tcp_flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        record["protocol"] = "UDP"
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        record["protocol"] = "ICMP"
    else:
        # IP packet but transport layer we don't handle yet
        if record["protocol"] is None:
            record["protocol"] = "OTHER"

    return record
