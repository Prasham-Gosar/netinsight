"""
packet_parser.py
-----------------
Turns a raw Scapy packet (nested envelopes) into one flat dictionary.

Phase 1 extracted the basics (IPs, ports, size, flags). Phase 2 adds the
extra fields the intelligence layer needs:

  seq / ack / payload_len -> spot retransmissions and duplicate ACKs
  dns                     -> DNS query/response details (domain names, IPs, latency)
  sni / http_host         -> which website an HTTPS/HTTP connection is for
  icmp_type / arp_op      -> so the explainer can say "ping request" etc.

Privacy: we keep *metadata only* (addresses, ports, sizes, domain names).
The payload bytes are looked at briefly to find a domain name and are
then thrown away.
"""

import time
from datetime import datetime

from scapy.all import IP, IPv6, TCP, UDP, ARP, ICMP, Ether, DNS
from scapy.layers.dns import DNSRR

from .tls_sni import extract_sni, extract_http_host


def _tcp_payload_len(ip_layer, tcp):
    """Exact TCP payload size, ignoring Ethernet padding bytes."""
    try:
        if isinstance(ip_layer, IP):
            return max(0, ip_layer.len - ip_layer.ihl * 4 - tcp.dataofs * 4)
        return max(0, ip_layer.plen - tcp.dataofs * 4)
    except TypeError:
        return len(bytes(tcp.payload))


def _as_list(section):
    """Scapy versions differ: DNS sections can be a list or a chain."""
    if section is None:
        return []
    if isinstance(section, (list, tuple)):
        return list(section)
    out, node = [], section
    while isinstance(node, DNSRR):
        out.append(node)
        node = node.payload
    return out


def _decode_name(value):
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="ignore")
    return str(value).rstrip(".").lower()


def _parse_dns(dns):
    """Pull the useful parts out of a DNS message."""
    info = {
        "id": dns.id,
        "qr": int(dns.qr),
        "qname": None,
        "qtype": None,
        "rcode": int(dns.rcode),
        "answers": [],   # IP addresses the name resolved to
        "cnames": [],
    }
    qd = dns.qd
    if isinstance(qd, (list, tuple)):
        qd = qd[0] if qd else None
    if qd is not None and getattr(qd, "qname", None):
        info["qname"] = _decode_name(qd.qname)
        info["qtype"] = int(qd.qtype)

    if info["qr"] == 1:
        for rr in _as_list(dns.an):
            rtype = getattr(rr, "type", None)
            if rtype in (1, 28):          # A / AAAA
                info["answers"].append(_decode_name(rr.rdata))
            elif rtype == 5:              # CNAME
                info["cnames"].append(_decode_name(rr.rdata))
    return info


def _find_icmpv6(packet):
    layer = packet
    while layer is not None and type(layer).__name__ != "NoPayload":
        if type(layer).__name__.startswith("ICMPv6"):
            return layer
        layer = layer.payload
    return None


def parse_packet(packet, ts=None):
    """
    Convert a raw Scapy packet into a structured dict.
    Returns None for packets that carry nothing we track (e.g. STP, LLDP).

    ts lets the simulator/tests supply their own timestamp; for real
    captures we use the capture-card timestamp, which is more precise
    than "now" when we later measure round-trip times.
    """
    if ts is None:
        try:
            ts = float(packet.time)
        except Exception:
            ts = time.time()

    record = {
        "ts": ts,
        "timestamp": datetime.fromtimestamp(ts).isoformat(),
        "src_ip": None, "dst_ip": None,
        "src_mac": None, "dst_mac": None,
        "protocol": None,
        "src_port": None, "dst_port": None,
        "packet_size": len(packet),
        "ttl": None,
        "tcp_flags": None,
        "seq": None, "ack": None, "payload_len": 0,
        "icmp_type": None, "arp_op": None,
        "dns": None, "sni": None, "http_host": None,
    }

    if packet.haslayer(Ether):
        record["src_mac"] = packet[Ether].src
        record["dst_mac"] = packet[Ether].dst

    # ARP has no IP layer: it asks "who has this IP?" on the local network
    if packet.haslayer(ARP):
        arp = packet[ARP]
        record["protocol"] = "ARP"
        record["src_ip"], record["dst_ip"] = arp.psrc, arp.pdst
        record["src_mac"] = arp.hwsrc          # the real sender/target hardware
        record["dst_mac"] = arp.hwdst          # addresses live inside the ARP body
        record["arp_op"] = int(arp.op)
        return record

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        record["src_ip"], record["dst_ip"], record["ttl"] = ip_layer.src, ip_layer.dst, ip_layer.ttl
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        record["src_ip"], record["dst_ip"], record["ttl"] = ip_layer.src, ip_layer.dst, ip_layer.hlim
    else:
        return None

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        record["protocol"] = "TCP"
        record["src_port"], record["dst_port"] = tcp.sport, tcp.dport
        record["tcp_flags"] = str(tcp.flags)
        record["seq"], record["ack"] = int(tcp.seq), int(tcp.ack)
        plen = _tcp_payload_len(ip_layer, tcp)
        record["payload_len"] = plen

        if plen > 5:
            payload = bytes(tcp.payload)[:min(plen, 2048)]
            if payload[:1] == b"\x16":
                record["sni"] = extract_sni(payload)
            elif record["dst_port"] in (80, 8080):
                record["http_host"] = extract_http_host(payload)

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        record["protocol"] = "UDP"
        record["src_port"], record["dst_port"] = udp.sport, udp.dport
        record["payload_len"] = max(0, udp.len - 8) if udp.len else 0

    elif packet.haslayer(ICMP):
        record["protocol"] = "ICMP"
        record["icmp_type"] = int(packet[ICMP].type)

    else:
        icmp6 = _find_icmpv6(packet)
        if icmp6 is not None:
            record["protocol"] = "ICMPv6"
            record["icmp_type"] = int(getattr(icmp6, "type", -1))
        else:
            record["protocol"] = "OTHER"

    # DNS (port 53 only; mDNS on 5353 is labelled by the protocol identifier)
    if record["protocol"] in ("UDP", "TCP") and 53 in (record["src_port"], record["dst_port"]):
        if packet.haslayer(DNS):
            try:
                record["dns"] = _parse_dns(packet[DNS])
            except Exception:
                record["dns"] = None   # malformed DNS: ignore, keep the packet

    return record
