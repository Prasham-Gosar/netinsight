"""
capture_engine.py
------------------
The "loading dock". It listens on one network interface and drops every
packet, with its capture timestamp, onto the shared queue.

Phase 2 change: the capture callback now does NOTHING except timestamp and
enqueue. Parsing (DNS, SNI, ...) happens in the processing thread. That keeps
the dock fast so packets are not missed while we do heavier analysis.

On Windows this REQUIRES Npcap (WinPcap-compatible mode) and an
Administrator terminal.
"""

import threading
import time

from scapy.all import sniff, get_if_list, conf

NOISE_NAME_PARTS = ("-Npcap", "-WFP", "-QoS", "Filter Driver", "LightWeight Filter")
NOISE_DESC_PARTS = ("WAN Miniport", "Kernel Debug", "Teredo", "6to4", "IP-HTTPS", "Virtual Adapter",
                    "Bluetooth", "Loopback", "Filter Driver", "LightWeight Filter", "Npcap Packet Driver")


class CaptureEngine:
    def __init__(self, interface, packet_queue, packet_filter=None):
        self.interface = interface
        self.packet_queue = packet_queue
        self.packet_filter = packet_filter
        self.captured = 0
        self.error = None
        self._stop_event = threading.Event()
        self._thread = None

    def _handle_packet(self, packet):
        try:
            ts = float(packet.time)
        except Exception:
            ts = time.time()
        self.captured += 1
        self.packet_queue.put((ts, packet))

    def _run(self):
        try:
            sniff(iface=self.interface, prn=self._handle_packet, filter=self.packet_filter,
                  store=False, stop_filter=lambda pkt: self._stop_event.is_set())
        except Exception as exc:        # e.g. Npcap missing, or not Administrator
            self.error = str(exc)
            print(f"\n[capture error] {exc}\nIs Npcap installed and is this terminal running as Administrator?")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="capture")
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)


def list_interfaces(show_all=False):
    """
    Returns a list of dicts: display, name, ips, noisy, preferred.

    Windows exposes dozens of virtual/filter adapters. By default we hide
    the noisy ones and mark the most likely real connection as preferred.
    """
    items = []
    try:
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            name, desc = i.get("name", "Unknown"), i.get("description", "")
            ips = [ip.split("%")[0] for ip in i.get("ips", [])]
            noisy = any(p in name for p in NOISE_NAME_PARTS) or any(p in desc for p in NOISE_DESC_PARTS)
            routable = [ip for ip in ips if not ip.startswith("fe80") and ip != "::1" and not ip.startswith("169.254")]
            ip_txt = ", ".join(ips[:2]) if ips else "no IP"
            items.append({"display": f"{name} ({desc}) - {ip_txt}", "name": name, "ips": ips,
                          "noisy": noisy, "preferred": bool(routable) and not noisy})
    except ImportError:
        for name in get_if_list():
            items.append({"display": name, "name": name, "ips": [], "noisy": False, "preferred": False})
    if not show_all:
        shown = [i for i in items if not i["noisy"] and (i["ips"] or not items)]
        items = shown or items
    return items


def interface_ips_and_gateway(iface_name):
    """IP addresses of the chosen interface and the default gateway (router)."""
    ips = []
    try:
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            if i.get("name") == iface_name:
                ips = [ip.split("%")[0] for ip in i.get("ips", [])]
                break
    except ImportError:
        try:
            from scapy.all import get_if_addr
            ips = [get_if_addr(iface_name)]
        except Exception:
            pass
    gateway = None
    try:
        gw = conf.route.route("0.0.0.0")[2]
        gateway = gw if gw and gw != "0.0.0.0" else None
    except Exception:
        pass
    return ips, gateway
