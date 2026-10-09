"""
main.py
-------
The conductor of the orchestra. This file doesn't do any real work
itself - it just wires together the pieces built in the other files
and starts them running together:

    CaptureEngine  --(puts packets on)-->  PacketQueue
    PacketQueue    --(read by)-->          processing thread
    processing thread --(updates)-->        TrafficAggregator
    processing thread --(writes to)-->      Database
    console_monitor   --(reads from)-->     TrafficAggregator  (main thread, live display)

Run with:  python main.py
MUST be run as Administrator on Windows (packet capture needs raw
socket access), with Npcap installed: https://npcap.com/#download
"""

import sys
import threading
import time

from capture.capture_engine import CaptureEngine, list_interfaces
from core.packet_queue import PacketQueue
from core.aggregator import TrafficAggregator
from db.database import Database
from monitor import console_monitor
from monitor import web_monitor

DB_WRITE_BATCH_SIZE = 50       # write to disk every 50 packets
DB_SNAPSHOT_INTERVAL = 30      # save an aggregated stats snapshot every 30s


def processing_loop(packet_queue: PacketQueue, aggregator: TrafficAggregator,
                     database: Database, stop_event: threading.Event):
    """
    Consumer side of the queue. Pulls parsed packet records off the
    belt, updates the running totals, and batches them to the database.

    Batching (instead of one INSERT per packet) matters here: SQLite
    writes are relatively slow one at a time, and packets can arrive
    fast. It's like a cashier bagging 10 items at once instead of
    walking to the storeroom after every single item.
    """
    batch = []
    last_snapshot_time = time.time()

    while not stop_event.is_set():
        record = packet_queue.get(timeout=1.0)
        if record is None:
            continue  # nothing arrived this second, just loop and check stop_event again

        aggregator.add(record)
        batch.append(record)

        if len(batch) >= DB_WRITE_BATCH_SIZE:
            database.insert_packets_batch(batch)
            batch.clear()

        if time.time() - last_snapshot_time >= DB_SNAPSHOT_INTERVAL:
            snapshot = aggregator.snapshot()
            database.save_traffic_snapshot(
                snapshot["protocol_packet_count"], snapshot["protocol_byte_count"]
            )
            last_snapshot_time = time.time()

    # flush any remaining packets before shutting down
    if batch:
        database.insert_packets_batch(batch)


def main():
    interfaces = list_interfaces()
    print("Available network interfaces:")
    for i, (display_name, _) in enumerate(interfaces):
        print(f"  [{i}] {display_name}")
    print("\nTip: pick the one showing an IP address like 192.168.x.x -")
    print("that's the connection you're actually browsing through right now.")

    choice = input("\nEnter the number of the interface to monitor: ").strip()
    try:
        _, interface = interfaces[int(choice)]
    except (ValueError, IndexError):
        print("Invalid choice.")
        sys.exit(1)

    packet_queue = PacketQueue()
    aggregator = TrafficAggregator()
    database = Database("netinsight.db")
    stop_event = threading.Event()

    engine = CaptureEngine(interface=interface, packet_queue=packet_queue)

    processing_thread = threading.Thread(
        target=processing_loop,
        args=(packet_queue, aggregator, database, stop_event),
        daemon=True,
    )

    mode = input("\nMonitor mode - [1] Terminal  [2] Website (default 1): ").strip()

    print(f"\nStarting capture on: {interface}")
    engine.start()
    processing_thread.start()

    try:
        if mode == "2":
            web_monitor.run_web_monitor(aggregator, packet_queue)
        else:
            console_monitor.run_loop(aggregator, packet_queue)
    finally:
        stop_event.set()
        engine.stop()
        processing_thread.join(timeout=3)
        database.close()
        print("NetInsight stopped cleanly.")


if __name__ == "__main__":
    main()
