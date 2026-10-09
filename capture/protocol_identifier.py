"""
protocol_identifier.py
-----------------------
The parser already knows "this is TCP" or "this is UDP" — that's the
envelope type. This module looks at the *port number* to guess what's
actually inside the envelope, the way a mail sorter looks at a zip
code to guess which city a letter is headed to.

Well-known ports -> application-level protocol name.
"""

WELL_KNOWN_PORTS = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS/TLS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
}


def identify_application_protocol(record: dict) -> str:
    """
    Given a parsed packet record (from packet_parser.py), return the
    best-guess application-level protocol name.

    Falls back to the transport protocol (TCP/UDP/ICMP/ARP) if we
    can't identify anything more specific — this is intentional and
    matches the project's "best-effort" philosophy from the PS doc.
    """
    base_protocol = record.get("protocol")

    if base_protocol in ("ARP", "ICMP", None):
        return base_protocol or "UNKNOWN"

    src_port = record.get("src_port")
    dst_port = record.get("dst_port")

    for port in (dst_port, src_port):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]

    # No well-known port matched -> just label it by transport protocol
    return base_protocol
