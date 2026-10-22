# NetInsight - Network Traffic Intelligence (Phases 1-3)

Captures live network traffic, understands it, and shows it on a live web dashboard.

```
CAPTURE -> PARSE -> IDENTIFY -> QUEUE -> ANALYSE -> STORE -> DASHBOARD
                                           |
   app detection | devices | flows & TCP health | DNS latency | bandwidth
   health score  | anomaly detection | insights | packet explanations
```

| Phase | What it adds |
|---|---|
| 1 | Packet capture, parsing, protocol identification, queue, aggregation, SQLite |
| 2 | Application detection (DNS + TLS SNI), device discovery, bandwidth analytics, TCP-based network health (latency, retransmissions, loss estimate), health score |
| 3 | Plain-English packet explanations, insights, statistical anomaly detection, React dashboard, history & "ask your network" answers |

## Quick start (Windows)

1. Install **Python 3.10+** (tick "Add Python to PATH").
2. In this folder: `pip install -r requirements.txt`
3. **Try it with no setup at all (simulated traffic):**
   ```
   python main.py --simulate
   ```
   Open http://127.0.0.1:5000 . Use the demo buttons ("DNS burst", "Bad network", ...) to trigger alerts
   and watch the health score react. Anomaly alerts need ~70 s of "learning normal" first.
4. **Real traffic:** install [Npcap](https://npcap.com/#download) (tick *WinPcap API-compatible mode*), open
   Command Prompt **as Administrator**, then:
   ```
   python main.py
   ```
   Press Enter to accept the suggested interface (virtual adapters are hidden; `--all-interfaces` shows everything).

Useful options: `--console` (terminal view), `--no-scan` (skip the active ARP sweep), `--no-store-packets`
(aggregates only), `--link-mbps 50` (your real link speed, for the utilisation metric), `--port 5001`, `--db file.db`.

The dashboard is already built in `frontend/dist`, so **Node.js is not needed to run the project**.

## Tests

```
python test_pipeline.py                       # Phase 1 sanity check
python -m unittest discover -s tests -v       # Phase 2/3 (33 checks; ~70 s)
cd frontend && npm install && npm test        # dashboard smoke tests
```
Tests use the built-in simulator (real Scapy packets, fast-forwarded time) so they need no Npcap or admin rights.

## Project layout

```
main.py                    entry point
capture/   capture_engine  thin "loading dock": timestamp + enqueue only
           packet_parser   raw packet -> flat dict (TCP seq/ack, DNS, TLS SNI, ARP, ICMP ...)
           protocol_identifier, tls_sni, simulator (demo/test traffic generator)
core/      engine          the pipeline; owns all analysers; periodic tasks
           app_detector    IP<->domain memory + suffix rules (YouTube, Netflix, Zoom ...)
           device_tracker  devices via ARP/observed traffic, vendor (OUI), hostnames
           flow_tracker    conversations; RTT, retransmissions, gaps, dup ACKs, failures
           dns_tracker     DNS latency (question/answer matching)
           bandwidth       per app/protocol/destination/direction + live per-second series
           health          0-100 score from measured metrics
           anomaly         baseline vs now (ratio + z-score) alerts with context
           explainer       packet -> plain English (rule based, no LLM)
           insights        measured numbers -> sentences
           timeseries, netutil, oui, aggregator, packet_queue
db/        database        SQLite tables + history queries
api/       server          Flask REST API + serves the dashboard
frontend/  src/            React (Vite + Recharts) source;  dist/ = built app
docs/      PHASE2_3_GUIDE.md   deep explanation for viva/report
```

## REST API (try in the browser or Postman)

Live: `/api/dashboard` (everything), `/api/overview`, `/api/health`, `/api/bandwidth?seconds=`, `/api/protocols`,
`/api/applications`, `/api/devices`, `/api/top-ips`, `/api/flows`, `/api/packets?limit=`, `/api/alerts`, `/api/insights`.
History: `/api/history/summary?range=today|24h|7d|30d`, `/api/history/timeline?granularity=minutes|hours|days`,
`/api/history/health?granularity=...`, `/api/history/answers`.
Simulation only: `POST /api/demo/{dns_burst|degradation|bandwidth_spike|scan}?duration=30`.

## Working on the dashboard (teammates)

```
python main.py --simulate        # terminal 1: backend on :5000
cd frontend && npm install
npm run dev                      # terminal 2: hot-reloading dashboard on :5173 (proxies /api to :5000)
npm run build                    # when done: regenerates frontend/dist, then commit it
```

## Honest limitations (say these proactively in a viva)

- **Passive capture sees what reaches this PC.** On Wi-Fi/switched networks you mostly see your own traffic plus
  broadcasts; other devices are *discovered* (ARP) but their traffic volume may be tiny. A router, mirrored port or
  hotspot shows more.
- **Application detection is best effort.** CDNs share IPs between sites, QUIC hides the server name, Encrypted
  Client Hello is spreading. Accuracy is never claimed as 100%.
- **Packet loss is an estimate** (retransmissions + sequence gaps over data segments); a sniffer cannot see packets
  lost before they reach it. Latency is TCP handshake round-trip time.
- **Anomaly detection says "potentially unusual", never "attack".** It is statistics over the last few minutes.
- **Privacy:** only metadata is stored (addresses, ports, sizes, domain names). Payloads are never stored.
- The ARP sweep and capture should only be used on networks you own or are authorised to monitor.
- OUI vendor table is a small built-in sample; drop the full IEEE list in `data/oui.csv` (`AABBCC,Vendor`) for accuracy.
