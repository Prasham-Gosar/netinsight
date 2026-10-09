"""
capture_engine.py
------------------
This is the "loading dock" of NetInsight. It listens on a network
interface and, for every packet that arrives, hands it off to the
parser + protocol identifier, then drops the finished record onto
the shared queue for the processing side of the app to pick up.

On Windows this REQUIRES:
  1. Npcap installed (https://npcap.com/#download) — check
     "Install Npcap in WinPcap API-compatible mode" during setup.
  2. Running your terminal / script as Administrator.

Why a queue instead of processing packets directly here?
Network packets can arrive faster than we can analyze them. The
capture thread's only job is to grab and hand off — like a cashier
who just scans items and puts them in a bag, while someone else
(the queue consumer) actually bags and prices them. If the cashier
stopped to price-check every item, the checkout line would back up
and packets would be dropped.
"""

import threading
from scapy.all import sniff, get_if_list

from .packet_parser import parse_packet
from .protocol_identifier import identify_application_protocol


class CaptureEngine:
    def __init__(self, interface: str, packet_queue, packet_filter: str = None):
        """
        interface: the network interface name to sniff on
                    (see list_interfaces() below to find yours)
        packet_queue: a core.packet_queue.PacketQueue instance to push into
        packet_filter: optional BPF filter string, e.g. "tcp or udp"
                        (leave None to capture everything)
        """
        self.interface = interface
        self.packet_queue = packet_queue
        self.packet_filter = packet_filter
        self._stop_event = threading.Event()
        self._thread = None

    def _handle_packet(self, packet):
        record = parse_packet(packet)
        if record is None:
            return  # nothing useful in this packet, skip it
        record["app_protocol"] = identify_application_protocol(record)
        self.packet_queue.put(record)

    def _run(self):
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            filter=self.packet_filter,
            store=False,  # don't keep packets in memory, we handle them live
            stop_filter=lambda pkt: self._stop_event.is_set(),
        )

    def start(self):
        """Start capturing in a background thread so it doesn't block the app."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the capture loop to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)


def list_interfaces():
    """
    Returns a list of (display_name, scapy_interface_id) tuples.

    Why not just return get_if_list() directly? On Windows, that gives
    you cryptic device GUIDs like '\\Device\\NPF_{A1B2C3-...}' - useless
    for a human trying to pick "which one is my Wi-Fi". This function
    tries to pair each device with its friendly OS-level name
    (Wi-Fi, Ethernet, etc.) so you can actually tell them apart.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        windows_ifaces = get_windows_if_list()
        results = []
        for iface in windows_ifaces:
            friendly_name = iface.get("name", "Unknown")
            description = iface.get("description", "")
            ips = iface.get("ips", [])
            ip_str = f" - {ips[0]}" if ips else " - no IP (likely inactive)"
            display = f"{friendly_name} ({description}){ip_str}"
            # scapy's sniff() wants the friendly name on Windows
            results.append((display, friendly_name))
        return results
    except ImportError:
        # Not on Windows - fall back to the generic cross-platform list
        return [(name, name) for name in get_if_list()]
