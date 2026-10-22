"""
netutil.py
-----------
Small helpers that answer "whose packet is this?".

NetContext knows which IP addresses belong to THIS computer, which subnet
we are on, and who the gateway (router) is. From that we can tell whether
a packet is going OUT to the internet, coming IN, or staying LOCAL.

Analogy: a mailroom clerk who knows the company's own address can sort
every envelope into "outgoing", "incoming" or "internal mail".
"""

import ipaddress
from functools import lru_cache


@lru_cache(maxsize=65536)
def _addr(ip):
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


class NetContext:
    def __init__(self, local_ips=(), gateway_ip=None, interface=None,
                 link_mbps=100.0, subnets=()):
        self.local_ips = {ip.split("%")[0] for ip in local_ips if ip}
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.link_mbps = float(link_mbps)
        nets = []
        for s in subnets:
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                pass
        if not nets:  # default guess: a /24 around each local IPv4 address
            for ip in self.local_ips:
                a = _addr(ip)
                if a is not None and a.version == 4 and a.is_private:
                    nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))
        self.subnets = nets

    # ---- classification helpers -------------------------------------
    def is_self(self, ip):
        return ip in self.local_ips

    @staticmethod
    def is_lan(ip):
        """True for private / link-local / multicast / broadcast addresses."""
        a = _addr(ip)
        return a is not None and (a.is_multicast or not a.is_global)

    def on_link(self, ip):
        """True if this address lives on our own network segment (same Wi-Fi/LAN)."""
        if ip in self.local_ips:
            return True
        a = _addr(ip)
        if a is None or a.is_multicast:
            return False
        if a.version == 4:
            return any(a in n for n in self.subnets)
        return a.is_link_local or a.is_private  # fe80::/10 and fc00::/7

    def direction(self, src, dst):
        """'out', 'in', 'local' or 'unknown' from the capture machine's viewpoint."""
        src_self, dst_self = src in self.local_ips, dst in self.local_ips
        src_lan, dst_lan = self.is_lan(src), self.is_lan(dst)
        if src_self and not dst_self:
            return "local" if dst_lan else "out"
        if dst_self and not src_self:
            return "local" if src_lan else "in"
        if src_lan and not dst_lan:
            return "out"      # another LAN device talking to the internet
        if dst_lan and not src_lan:
            return "in"
        if src_lan and dst_lan:
            return "local"
        return "unknown"

    def remote_ip(self, src, dst, direction):
        if direction == "out":
            return dst
        if direction == "in":
            return src
        if direction == "unknown":
            return dst
        return None


def valid_unicast_mac(mac):
    """False for missing, all-zero, broadcast and multicast MAC addresses."""
    if not mac or len(mac) != 17:
        return False
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    try:
        return (int(mac[:2], 16) & 1) == 0   # multicast bit must be 0
    except ValueError:
        return False
