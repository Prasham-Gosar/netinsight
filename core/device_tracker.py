"""
device_tracker.py
------------------
Builds a list of devices seen on the local network.

How a device is spotted:
  * any packet whose sender/receiver is on our own subnet teaches us a
    pair (IP address, MAC address);
  * ARP packets are the best source ("192.168.1.8 is at AA:BB:..");
  * optionally an ARP *sweep* actively asks every address on the subnet
    "who are you?" (only do this on a network you own).

Important honesty point (also in the project statement): DISCOVERING a
device is not the same as ATTRIBUTING all its traffic. On Wi-Fi or a
switched network your laptop normally only sees its own traffic plus
broadcasts, so another device may appear in the list with little or no
traffic volume. Capturing on a router, a mirrored port or a hotspot shows
more.
"""

import queue
import socket
import threading

from .netutil import valid_unicast_mac
from .oui import lookup_vendor, is_randomized

ACTIVE_WINDOW = 120   # seconds without traffic before a device shows as idle


class DeviceTracker:
    def __init__(self, ctx, resolve_hostnames=True):
        self.ctx = ctx
        self.devices = {}          # key -> dict
        self._ip_key = {}          # ip -> key
        self._resolve = resolve_hostnames
        self._rq = queue.Queue()
        self._self_name = None
        if resolve_hostnames:
            threading.Thread(target=self._resolver, daemon=True).start()
            try:
                self._self_name = socket.gethostname()
            except OSError:
                pass

    # ---- observation --------------------------------------------------
    def _touch(self, ip, mac, ts):
        mac = mac if valid_unicast_mac(mac) else None
        key = mac or self._ip_key.get(ip) or f"ip:{ip}"
        dev = self.devices.get(key)
        if dev is None and mac and f"ip:{ip}" in self.devices:   # upgrade an IP-only entry
            dev = self.devices.pop(f"ip:{ip}")
            dev["key"], dev["mac"] = key, mac
            self.devices[key] = dev
        if dev is None:
            dev = self.devices[key] = {
                "key": key, "mac": mac, "ips": [], "hostname": None,
                "vendor": lookup_vendor(mac) if mac else None,
                "randomized_mac": is_randomized(mac) if mac else False,
                "is_self": False, "is_gateway": False,
                "first_seen": ts, "last_seen": ts,
                "packets": 0, "bytes_in": 0, "bytes_out": 0,
            }
            if self._resolve and self.ctx.is_lan(ip) and ":" not in ip:
                self._rq.put(ip)
        if mac and not dev["mac"]:
            dev["mac"] = mac
            dev["vendor"] = lookup_vendor(mac)
            dev["randomized_mac"] = is_randomized(mac)
        if ip not in dev["ips"]:
            dev["ips"].append(ip)
            dev["ips"].sort(key=lambda x: (":" in x, x))     # IPv4 first
        self._ip_key[ip] = dev["key"]
        dev["last_seen"] = max(dev["last_seen"], ts)
        if self.ctx.is_self(ip):
            dev["is_self"] = True
            dev["hostname"] = dev["hostname"] or self._self_name
        if ip == self.ctx.gateway_ip:
            dev["is_gateway"] = True
        return dev["key"]

    def observe(self, rec, size):
        """Update device records from one packet. Returns (src_key, dst_key)."""
        ts = rec["ts"]
        keys = []
        for ip, mac in ((rec["src_ip"], rec["src_mac"]), (rec["dst_ip"], rec["dst_mac"])):
            key = None
            if ip and self.ctx.on_link(ip):
                key = self._touch(ip, mac, ts)
            keys.append(key)
        src_key, dst_key = keys
        if src_key:
            d = self.devices[src_key]
            d["bytes_out"] += size
            d["packets"] += 1
        if dst_key:
            d = self.devices[dst_key]
            d["bytes_in"] += size
            if dst_key != src_key:
                d["packets"] += 1
        return src_key, dst_key

    def add_discovered(self, ip, mac, ts):
        """Used by the active ARP sweep."""
        self._touch(ip, mac, ts)

    # ---- naming -------------------------------------------------------
    def display_name(self, dev):
        if dev["is_self"]:
            return f"This computer ({dev['hostname']})" if dev["hostname"] else "This computer"
        if dev["is_gateway"]:
            return "Router / Gateway"
        if dev["hostname"]:
            return dev["hostname"]
        if dev["vendor"]:
            return f"{dev['vendor']} device"
        if dev["randomized_mac"]:
            return "Device (private MAC)"
        return dev["ips"][0] if dev["ips"] else dev["key"]

    def label_for_key(self, key):
        dev = self.devices.get(key)
        return self.display_name(dev) if dev else "Unknown"

    def snapshot(self, now):
        out = []
        for dev in self.devices.values():
            out.append({
                "key": dev["key"],
                "name": self.display_name(dev),
                "ip": dev["ips"][0] if dev["ips"] else None,
                "ips": list(dev["ips"]),
                "mac": dev["mac"],
                "hostname": dev["hostname"],
                "vendor": dev["vendor"] or ("Private (randomised) MAC" if dev["randomized_mac"] else None),
                "is_self": dev["is_self"],
                "is_gateway": dev["is_gateway"],
                "bytes_in": dev["bytes_in"],
                "bytes_out": dev["bytes_out"],
                "bytes_total": dev["bytes_in"] + dev["bytes_out"],
                "packets": dev["packets"],
                "first_seen": dev["first_seen"],
                "last_seen": dev["last_seen"],
                "active": (now - dev["last_seen"]) <= ACTIVE_WINDOW,
            })
        out.sort(key=lambda d: d["bytes_total"], reverse=True)
        return out

    # ---- hostname resolution (background) ----------------------------
    def _resolver(self):
        while True:
            ip = self._rq.get()
            host = None
            try:
                host = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                pass
            key = self._ip_key.get(ip)
            if key and key in self.devices and host:
                self.devices[key]["hostname"] = host.split(".")[0]

    # ---- active discovery --------------------------------------------
    def arp_sweep(self, timeout=2):
        """Ask every address in our /24 'who are you?'. Needs Npcap + Administrator."""
        found = 0
        try:
            from scapy.all import Ether, ARP, srp
            import time
            for net in self.ctx.subnets:
                if net.version != 4 or net.num_addresses > 1024:
                    continue
                answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
                                  timeout=timeout, iface=self.ctx.interface, verbose=0)
                for _, reply in answered:
                    self.add_discovered(reply.psrc, reply.hwsrc, time.time())
                    found += 1
        except Exception:
            return found
        return found
