"""
explainer.py
-------------
Rule-based "packet translator": technical header -> plain English.

Why rules and not an LLM? The project brief says the core analysis must
not depend on an LLM: rules are fast, free, work offline and always give
the same answer for the same packet (predictable and testable). An LLM
could later be added to *rephrase* these sentences or write summaries.
"""

PORT_HINT = {
    80: "unencrypted web (HTTP)", 8080: "unencrypted web (HTTP)",
    443: "secure web (HTTPS)", 8443: "secure web (HTTPS)",
    22: "remote login (SSH)", 21: "file transfer (FTP)", 25: "email sending (SMTP)",
    587: "email sending (SMTP)", 110: "email (POP3)", 143: "email (IMAP)", 993: "email (IMAP)",
    3389: "Windows Remote Desktop", 445: "Windows file sharing (SMB)",
    3306: "a MySQL database", 5432: "a PostgreSQL database", 53: "DNS",
}

ICMP_TEXT = {
    0: "Ping reply: the other host answered, so it is reachable.",
    3: "ICMP 'destination unreachable': the packet could not be delivered to its target.",
    8: "Ping request: checking whether a host is reachable and measuring the round-trip time.",
    11: "ICMP 'time exceeded': a packet's hop limit (TTL) ran out - typical of traceroute or a routing loop.",
}
ICMP6_TEXT = {
    128: "IPv6 ping request: checking whether a host is reachable.",
    129: "IPv6 ping reply: the host is reachable.",
    133: "IPv6 router solicitation: a device asks 'is there a router here?'.",
    134: "IPv6 router advertisement: the router announces the network settings.",
    135: "IPv6 neighbour solicitation: asking which device owns an IPv6 address (IPv6's version of ARP).",
    136: "IPv6 neighbour advertisement: answering which hardware address owns an IPv6 address.",
}
UDP_TEXT = {
    "QUIC": "QUIC (HTTP/3) traffic: modern encrypted web/video traffic carried over UDP - used by YouTube, Google and others.",
    "NTP": "Time synchronisation (NTP): a device is checking or setting its clock.",
    "DHCP": "DHCP: a device is asking for, or being given, a network (IP) address.",
    "mDNS": "mDNS: devices on the local network announcing/finding each other by name (printers, TVs, phones).",
    "SSDP": "SSDP: local device discovery (smart TVs, routers, media players advertising themselves).",
    "LLMNR": "LLMNR: Windows looking up a computer name on the local network.",
    "NetBIOS": "NetBIOS: legacy Windows name/file-sharing chatter on the local network.",
    "STUN": "STUN: helping a video/voice call work out how to connect through the router.",
}


def _target(rec):
    """Who the packet is addressed to (a website name when we know it)."""
    name = rec.get("domain") if rec.get("direction") == "out" else None
    return name or rec.get("dst_ip"), rec.get("dst_port")


def explain_packet(rec):
    """Return one plain-English sentence (or two) describing a packet."""
    proto = rec.get("protocol")
    src, dst = rec.get("src_ip"), rec.get("dst_ip")
    app = rec.get("app")
    app_note = f" ({app})" if app and app not in ("Unclassified", "Other", "DNS") else ""

    # ---- ARP -----------------------------------------------------------
    if proto == "ARP":
        if rec.get("arp_op") == 1:
            if src == dst:
                return f"{src} is announcing its own address on the local network (gratuitous ARP)."
            return (f"{src} is asking the local network 'who has {dst}?' so it can learn that device's "
                    f"hardware (MAC) address.")
        return f"{src} is replying to an ARP request: its hardware (MAC) address is {rec.get('src_mac')}."

    # ---- ICMP ----------------------------------------------------------
    if proto == "ICMP":
        return ICMP_TEXT.get(rec.get("icmp_type"), f"ICMP control message (type {rec.get('icmp_type')}) between {src} and {dst}.")
    if proto == "ICMPv6":
        return ICMP6_TEXT.get(rec.get("icmp_type"), "IPv6 control message used for network housekeeping.")

    # ---- DNS -----------------------------------------------------------
    dns = rec.get("dns")
    if dns and dns.get("qname"):
        name = dns["qname"]
        if dns["qr"] == 0:
            kind = "IPv6 address" if dns.get("qtype") == 28 else "IP address"
            return f"Asking the DNS server {dst} to look up the {kind} of {name}, so a connection to it can be made."
        if dns["rcode"] == 3:
            return f"The DNS server replied that '{name}' does not exist (NXDOMAIN)."
        if dns["rcode"] == 2:
            return f"The DNS server failed to answer the lookup for {name} (SERVFAIL)."
        if dns["answers"]:
            extra = f" (+{len(dns['answers']) - 1} more)" if len(dns["answers"]) > 1 else ""
            return f"The DNS server answered: {name} is at {dns['answers'][0]}{extra}."
        return f"The DNS server replied for {name} but returned no address records."

    # ---- TCP -----------------------------------------------------------
    if proto == "TCP":
        flags = rec.get("tcp_flags") or ""
        plen = rec.get("payload_len") or 0
        remote, rport = _target(rec)
        hint = PORT_HINT.get(rec.get("dst_port")) or PORT_HINT.get(rec.get("src_port"))
        hint_txt = f", a port commonly used for {hint}" if hint else ""
        if "R" in flags:
            return "The connection was reset or refused (RST): one side abruptly ended it, e.g. nothing is listening on that port."
        if "S" in flags and "A" not in flags:
            return (f"Starting a new TCP connection to {remote}:{rport}{hint_txt}{app_note}. "
                    f"This is step 1 of 3 in the TCP handshake.")
        if "S" in flags and "A" in flags:
            return f"{src} accepted the connection request (step 2 of 3 in the TCP handshake){app_note}."
        if rec.get("sni"):
            return (f"Opening a secure (TLS) session and announcing the site name '{rec['sni']}'{app_note}. "
                    f"Everything after this is encrypted - we only see the name, not the content.")
        if rec.get("http_host"):
            return f"Sending an unencrypted web request for '{rec['http_host']}'{app_note}."
        if "F" in flags:
            return "Closing the TCP connection politely (FIN): this side has finished sending."
        if plen > 0:
            enc = "encrypted " if rec.get("dst_port") in (443, 8443) or rec.get("src_port") in (443, 8443) else ""
            way = "Uploading" if rec.get("direction") == "out" else ("Receiving" if rec.get("direction") == "in" else "Carrying")
            return f"{way} {plen} bytes of {enc}data over an established connection{app_note}."
        return "Acknowledging received data (ACK). It keeps the conversation in sync and lets the sender continue."

    # ---- UDP -----------------------------------------------------------
    if proto == "UDP":
        text = UDP_TEXT.get(rec.get("app_protocol"))
        if text:
            return text + app_note
        n = rec.get("payload_len", 0)
        if rec.get("direction") == "in":
            who = rec.get("domain") or src
            head = f"Receiving a UDP datagram of {n} bytes from {who}:{rec.get('src_port')}{app_note}."
        else:
            who = rec.get("domain") or dst
            head = f"Sending a UDP datagram of {n} bytes to {who}:{rec.get('dst_port')}{app_note}."
        return head + " UDP has no connection set-up and no delivery guarantee - common for calls, games and streaming."

    return f"{proto or 'Unknown'} packet of {rec.get('packet_size')} bytes from {src} to {dst}."
