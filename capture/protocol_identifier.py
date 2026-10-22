"""
protocol_identifier.py
-----------------------
The parser knows the *envelope type* (TCP / UDP / ICMP / ARP). This module
looks at the port number to guess what is *inside* the envelope, the way a
mail sorter reads a zip code.

Phase 2 improvement: separate tables for TCP and UDP, because the same port
number means different things on each (UDP 443 is QUIC/HTTP3, TCP 443 is
HTTPS). It is still a best-effort heuristic: a service can run on any port.
"""

TCP_PORTS = {
    80: "HTTP", 8080: "HTTP", 443: "HTTPS/TLS", 8443: "HTTPS/TLS",
    53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP", 587: "SMTP", 465: "SMTP",
    110: "POP3", 143: "IMAP", 993: "IMAP", 995: "POP3",
    3389: "RDP", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
}

UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 546: "DHCPv6", 547: "DHCPv6",
    123: "NTP", 443: "QUIC", 5353: "mDNS", 5355: "LLMNR", 1900: "SSDP",
    137: "NetBIOS", 138: "NetBIOS", 3478: "STUN",
}

FAMILIES = ("TCP", "UDP", "DNS", "ICMP", "ARP", "Other")


def identify_application_protocol(record: dict) -> str:
    """Best-guess application-level protocol name for a parsed record."""
    base = record.get("protocol")
    if base in ("ARP", "ICMP", "ICMPv6"):
        return base
    if base is None:
        return "UNKNOWN"
    if base not in ("TCP", "UDP"):
        return base

    table = TCP_PORTS if base == "TCP" else UDP_PORTS
    for port in (record.get("dst_port"), record.get("src_port")):
        if port in table:
            return table[port]
    return base


def protocol_family(record: dict) -> str:
    """
    Coarse bucket used for the protocol-distribution chart:
    TCP, UDP, DNS, ICMP, ARP (matching the project's example), else Other.
    """
    if record.get("app_protocol") == "DNS":
        return "DNS"
    proto = record.get("protocol")
    if proto in ("ICMP", "ICMPv6"):
        return "ICMP"
    if proto in ("TCP", "UDP", "ARP"):
        return proto
    return "Other"
