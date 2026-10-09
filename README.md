# NetInsight — Phase 1: Network Traffic Foundation

Phase 1 pipeline: **Capture → Parse → Identify Protocol → Queue → Aggregate → Store (SQLite) → Basic Monitor**

## What each file does

| File | Role | Analogy |
|---|---|---|
| `capture/capture_engine.py` | Sniffs live packets off your network card | Loading dock |
| `capture/packet_parser.py` | Extracts clean fields from a raw packet | Quality control |
| `capture/protocol_identifier.py` | Labels the packet's application protocol using port numbers | Labeling station |
| `core/packet_queue.py` | Thread-safe hand-off between capture and processing | Conveyor belt |
| `core/aggregator.py` | Running totals (packet counts, bytes, protocol %) | Tally clerk |
| `db/database.py` | SQLite storage for packet metadata + periodic stats snapshots | Filing cabinet |
| `monitor/console_monitor.py` | Live-updating terminal dashboard | Factory floor display |
| `monitor/web_monitor.py` | Live-updating website (Flask) as an alternative to the terminal | TV screen in the lobby |
| `main.py` | Wires everything together and runs it | Conductor |
| `test_pipeline.py` | Sanity-checks all logic using fake packets (no admin rights needed) | Dress rehearsal |

## Setup (Windows)

1. **Install Npcap** (lets Scapy capture raw packets on Windows):
   https://npcap.com/#download
   During install, check **"Install Npcap in WinPcap API-compatible mode."**

2. **Install Python dependencies:**
   ```
   pip install -r requirements.txt
   ```

3. **Sanity-check the logic first (no admin needed):**
   ```
   python test_pipeline.py
   ```
   You should see `ALL CHECKS PASSED` at the end.

4. **Run the real thing — as Administrator:**
   - Right-click Command Prompt / PowerShell → "Run as Administrator"
   - Navigate to this folder
   - Run:
     ```
     python main.py
     ```
   - It'll list your network interfaces with friendly names and IPs, e.g.:
     ```
     [0] Wi-Fi (Intel Wireless-AC 9560) - 192.168.1.5
     [1] Ethernet (Realtek PCIe GbE) - no IP (likely inactive)
     ```
     Pick the one showing an IP address that matches how you're actually connected — that's your active connection.
   - You'll then be asked to choose a monitor mode: **[1] Terminal** or **[2] Website**.
     - Terminal mode shows a live-updating dashboard right in the command window.
     - Website mode starts a local site at `http://127.0.0.1:5000` — open that in your browser for a nicer live view (auto-refreshes every second).
   - Open a few websites, run `ping google.com` in another terminal, stream a video — watch the packet counts climb either way.
   - Press `Ctrl+C` to stop. A `netinsight.db` SQLite file will be sitting in this folder with everything captured.

## Verifying it worked (for your demo)

```
python -c "
import sqlite3
conn = sqlite3.connect('netinsight.db')
print('Total packets:', conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0])
print('By protocol:', conn.execute('SELECT protocol, COUNT(*) FROM packets GROUP BY protocol').fetchall())
"
```

## Known Phase 1 limitations (worth mentioning in your report/viva)

- Application detection (YouTube, Zoom, etc.) isn't built yet — that's Phase 2. Right now we only identify protocols (TCP/UDP/DNS/HTTPS...), not specific apps.
- No health score, anomaly detection, or dashboard UI yet — those are Phases 2–3.
- We deliberately **don't** store packet payloads, only header metadata (source/dest IP, ports, size, protocol) — this matches the PS doc's privacy guidance in section 30.
- Requires Administrator privileges + Npcap on Windows, since raw packet capture is an OS-level permission.

## Next steps toward Phase 2

- Add a `applications` table + DNS-based app detection (map resolved domains to known services)
- Add a `devices` table via ARP scanning
- Start computing a basic health score from packet loss / retransmission counts
