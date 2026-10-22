"""
console_monitor.py
-------------------
Phase 1's "basic monitoring interface" — a live-updating terminal
view. No React dashboard yet (that's Phase 3), just proof that the
whole pipeline works end-to-end, matching the PS doc's example output:

    NETINSIGHT
    Packets Captured: 15,832
    Total Traffic: 1.82 GB
    TCP       62%
    UDP       25%
    ...
    Capture Status: RUNNING
"""

import os
import time


def format_bytes(num_bytes: int) -> str:
    """Turn raw byte counts into human-readable sizes (KB/MB/GB)."""
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def render(aggregator, queue_size: int):
    """Print one frame of the live dashboard."""
    snapshot = aggregator.snapshot()
    distribution = aggregator.protocol_distribution_percent()

    clear_screen()
    print("=" * 40)
    print("   NETINSIGHT - Live Network Monitor")
    print("=" * 40)
    print(f"Packets Captured : {snapshot['total_packets']:,}")
    print(f"Total Traffic    : {format_bytes(snapshot['total_bytes'])}")
    print(f"Queue Backlog    : {queue_size}")
    print("-" * 40)
    print("Protocol Distribution:")
    for protocol, pct in sorted(distribution.items(), key=lambda kv: -kv[1]):
        bar = "#" * int(pct / 4)
        print(f"  {protocol:<10} {pct:>5.1f}%  {bar}")
    print("-" * 40)
    print("Capture Status: RUNNING   (Ctrl+C to stop)")
    print("=" * 40)


def run_loop(aggregator, packet_queue, refresh_seconds: float = 1.0):
    """Keep re-rendering the dashboard until the user hits Ctrl+C."""
    try:
        while True:
            render(aggregator, packet_queue.qsize())
            time.sleep(refresh_seconds)
    except KeyboardInterrupt:
        print("\nStopping NetInsight...")
