"""
main.py
--------
Starts NetInsight (Phases 1-3).

    python main.py                  pick a network interface, capture live traffic
    python main.py --simulate       no Npcap / admin needed: demo with generated traffic
    python main.py --console        old terminal dashboard instead of the website

Live capture on Windows needs Npcap (WinPcap-compatible mode) and an
Administrator terminal. Then open http://127.0.0.1:5000
"""

import argparse
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# Scapy caches its service database under the user's profile. On some
# Windows installations that location is not readable, so use a cache
# inside the project before importing modules that load Scapy.
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(HERE, ".scapy-cache"))

from core.engine import Engine
from core.netutil import NetContext
from db.database import Database

DIST = os.path.join(HERE, "frontend", "dist")


def parse_args():
    p = argparse.ArgumentParser(description="NetInsight - network traffic analytics")
    p.add_argument("--simulate", action="store_true", help="use generated demo traffic (no admin/Npcap needed)")
    p.add_argument("--scale", type=float, default=1.0, help="simulation traffic volume multiplier (default 1.0)")
    p.add_argument("--interface", help="interface number from the list, or its exact name")
    p.add_argument("--all-interfaces", action="store_true", help="do not hide virtual/filter adapters in the list")
    p.add_argument("--host", default="127.0.0.1", help="web server address (default 127.0.0.1 = this PC only)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--db", default="netinsight.db", help="SQLite file (default netinsight.db)")
    p.add_argument("--no-db", action="store_true", help="do not write anything to disk")
    p.add_argument("--no-store-packets", action="store_true", help="store only aggregates, not per-packet rows")
    p.add_argument("--no-scan", action="store_true", help="do not run the active ARP sweep for device discovery")
    p.add_argument("--no-hostnames", action="store_true", help="do not reverse-resolve device hostnames")
    p.add_argument("--link-mbps", type=float, default=100.0, help="your link speed, for the utilisation metric")
    p.add_argument("--console", action="store_true", help="show the terminal dashboard instead of the website")
    return p.parse_args()


def choose_interface(args):
    from capture.capture_engine import list_interfaces
    items = list_interfaces(show_all=args.all_interfaces)
    if not items:
        print("No network interfaces found. Is Npcap installed?")
        sys.exit(1)
    if args.interface is not None:
        if args.interface.isdigit() and int(args.interface) < len(items):
            return items[int(args.interface)]
        for it in items:
            if it["name"] == args.interface:
                return it
        print(f"Interface '{args.interface}' not found.")
        sys.exit(1)

    print("Network interfaces (virtual/filter adapters hidden; use --all-interfaces to show them):\n")
    default = next((i for i, it in enumerate(items) if it["preferred"]), None)
    for i, it in enumerate(items):
        star = "   <- likely your active connection" if i == default else ""
        print(f"  [{i}] {it['display']}{star}")
    prompt = "\nInterface number" + (f" (Enter = {default})" if default is not None else "") + ": "
    choice = input(prompt).strip()
    if not choice and default is not None:
        return items[default]
    try:
        return items[int(choice)]
    except (ValueError, IndexError):
        print("Invalid choice.")
        sys.exit(1)


def main():
    args = parse_args()
    db = None if args.no_db else Database(args.db)

    if args.simulate:
        from capture.simulator import DEVICES, SimulatorRunner, TrafficSimulator
        ctx = NetContext(local_ips=[DEVICES["laptop"][0]], gateway_ip=DEVICES["router"][0],
                         interface="simulation", link_mbps=args.link_mbps)
        engine = Engine(ctx, db, mode="simulation", store_packets=not args.no_store_packets,
                        resolve_hostnames=False, interface_label="Simulated home network")
        sim = TrafficSimulator(seed=42, scale=args.scale)
        engine.simulator = SimulatorRunner(sim, engine.queue)
        engine.simulator.start()
    else:
        from capture.capture_engine import CaptureEngine, interface_ips_and_gateway
        it = choose_interface(args)
        ips, gateway = interface_ips_and_gateway(it["name"])
        ctx = NetContext(local_ips=ips, gateway_ip=gateway, interface=it["name"], link_mbps=args.link_mbps)
        engine = Engine(ctx, db, mode="live", store_packets=not args.no_store_packets,
                        resolve_hostnames=not args.no_hostnames, interface_label=it["name"])
        engine.capture = CaptureEngine(it["name"], engine.queue)
        engine.capture.start()
        sim = None
        print(f"\nCapturing on: {it['name']}   (this computer: {', '.join(ips) or 'unknown'}, gateway: {gateway or 'unknown'})")
        if not args.no_scan:
            threading.Thread(target=_scan_loop, args=(engine,), daemon=True).start()

    engine.start()
    try:
        if args.console:
            from monitor import console_monitor
            console_monitor.run_loop(engine.aggregator, engine.queue)
        else:
            from api.server import create_app
            app = create_app(engine, static_dir=DIST, simulator=sim)
            print(f"\nNetInsight dashboard: http://{args.host}:{args.port}   (Ctrl+C to stop)\n")
            app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping NetInsight and saving data...")
        engine.stop()
        print("Stopped cleanly.")


def _scan_loop(engine):
    """Active ARP sweep for device discovery - only on YOUR OWN network."""
    time.sleep(3)
    while True:
        found = engine.devices.arp_sweep()
        if found:
            print(f"[device discovery] ARP sweep found {found} device(s)")
        time.sleep(300)


if __name__ == "__main__":
    main()
