# NetInsight Phase 2 + 3 - Deep-Dive Guide (viva preparation)

Opening line: *"Phase 1 captured and counted packets. Phases 2 and 3 turn those packets into understanding:
which applications and devices use the network, how healthy it is (from real TCP/DNS measurements), what looks
unusual, and what it all means in plain English - shown on a live React dashboard."*

## 1. Architecture in one picture

```
Npcap/Scapy sniff (capture thread)           Simulator (demo/test)
        | (timestamp, packet)                        |
        +------------------ PacketQueue -------------+      bounded FIFO, drops are COUNTED
                              |
                  processing thread (Engine)
   parse -> protocol -> direction -> app -> device -> DNS -> flow/TCP -> bandwidth
                              |                                   \
                  TimeSeries (per-second tallies) + SampleStore    SQLite (every 10 s, UPSERT)
                              |
     health score | anomaly detector | insights | explainer
                              |
                Flask REST API  <--polls every 1 s--  React dashboard
```
Key design choice: the capture thread only timestamps and enqueues; all analysis runs in a second thread, so capture
is never slowed by heavy work (producer-consumer). One re-entrant lock guards shared state so the web thread never
reads half-updated numbers.

## 2. Phase 2 modules - what, how, why

**Packet parser (extended).** Adds TCP `seq`, `ack`, exact payload length (from IP length fields, so Ethernet
padding is ignored), DNS fields, TLS SNI, HTTP Host, ICMP type, ARP opcode. Uses the capture card's timestamp, which is
more accurate for round-trip timing than "time of processing".

**Application detection** (`app_detector.py`). Encrypted traffic still leaks labels:
1. DNS answers: `youtube.com -> 142.250.x.x`; later packets to that IP are attributed to YouTube.
2. TLS SNI: the website name sent in clear text at the start of an HTTPS connection (we parse a real ClientHello).
3. HTTP Host header (port 80).
4. A few known public ranges (8.8.8.8 = Google DNS). 5. Ports (weakest).
Domains match a rule table by **longest suffix** (`meet.google.com` beats `google.com`; `*.googlevideo.com` = YouTube).
SNI evidence overrides DNS evidence. IP->domain memory is an LRU (OrderedDict, 20k entries).
*Limitations:* shared CDN IPs, QUIC hides SNI, ECH. Result carries a `method` and `confidence` (high/medium/low).

**Device discovery** (`device_tracker.py`). Devices keyed by MAC. IP<->MAC pairs learned from ARP and from packets
on our own subnet (never from packets routed via the gateway - that MAC belongs to the router). Vendor from the OUI
(first 3 MAC bytes); the "locally administered" bit marks randomised private MACs (modern phones). Hostnames via
background reverse DNS. Optional active ARP sweep of the /24. *Discovery != traffic attribution.*

**Flow tracking** (`flow_tracker.py`). A flow = same 5-tuple. TCP measurements from headers only:
- **RTT**: time from SYN to SYN/ACK.
- **Retransmission**: a data segment whose sequence number is behind what we already saw (32-bit wrap-safe).
- **Sequence gap**: a segment that skips ahead (something earlier went missing).
- **Duplicate ACK**: same ACK number repeated while data is outstanding.
- **Failed connection**: SYN answered by RST, or unanswered for 5 s.
Flows expire after 120 s idle; max 5000 tracked (oldest evicted).

**DNS latency** (`dns_tracker.py`). Matches question to answer by (ID, client IP, name) like a coat-check ticket;
unanswered after 5 s counts as a 5000 ms timeout sample.

**Bandwidth analytics** (`bandwidth.py`). Dictionary tallies (O(1) per packet) by app, protocol, family, remote IP,
direction; per-second series in `TimeSeries`; per-minute accumulators flushed to the DB. Direction (in/out/local) comes
from `NetContext` (which addresses are ours).

**Health score** (`health.py`). Start at 100, lose points per metric linearly between "fine" and "bad":

| metric | weight | fine -> bad |
|---|---|---|
| latency (median TCP RTT) | 20 | 50 -> 400 ms |
| packet loss (est.) | 25 | 0.5 -> 5 % |
| retransmissions | 10 | 1 -> 8 % |
| duplicate ACKs | 5 | 1 -> 10 % |
| DNS latency (p75) | 15 | 50 -> 500 ms |
| connection failures | 15 | 2 -> 30 % |
| bandwidth utilisation | 10 | 70 -> 100 % of link |

Loss estimate = (retransmissions + sequence gaps) / data segments. Metrics with too few samples are skipped (never
fake a number). Bands: >=90 Excellent, >=75 Good, >=50 Fair, else Poor. Weights are a documented design choice, not a
standard - say so.

## 3. Phase 3 modules

**Explainer** (`explainer.py`): deterministic rules map header fields to sentences ("Starting a new TCP connection
to youtube.com:443 ... step 1 of 3 in the handshake"). Rule-based on purpose: fast, offline, testable, no hallucination.

**Insights** (`insights.py`): each sentence is generated from a measured value (top app share, direction split,
loss/latency/DNS thresholds, latency trend vs earlier baseline, busiest device, encrypted share, peak throughput).

**Anomaly detection** (`anomaly.py`): for metrics (DNS rate, packet rate, bytes/s, new connections, resets, distinct
destinations): `ratio = mean(last 10 s) / mean(previous 300 s)` and `z = (now - mean) / std`. Alert only if
ratio >= 3 AND z >= 3 AND rate >= a per-metric minimum (avoids "0.1 -> 0.5 queries/s" noise). Needs 70 s of history.
Hysteresis: resolves after 10 quiet seconds, 30 s cool-down. Each alert carries context (e.g. top queried
domains, busiest app/device) and wording "potentially unusual traffic ... further investigation may be required".
Optional future work: Isolation Forest (scikit-learn) once statistics are validated.

**Storage** (`database.py`): tables `packets`, `traffic_stats` (per minute by device/app/protocol/direction),
`devices`, `applications`, `health_metrics`, `alerts`. UPSERT keeps `traffic_stats` at one row per combination per
minute no matter how often we flush. Old Phase 1 databases are migrated automatically. History questions (today's
traffic, top app/device, slowest minute, loss peak) are SQL over the small aggregate tables.

**Dashboard** (`frontend/`): React + Recharts; polls `/api/dashboard` every second (AJAX polling); history cards poll
every 15 s. Components: health gauge, live bandwidth area chart, protocol donut, top apps/devices/destinations,
timeline (minutes/hours/days), alerts, insights, live packet feed with explanations, flows, "ask your network".

## 4. Subjects used

- **Computer Networks:** layered protocols, TCP handshake/seq/ack/flags, retransmission & congestion signals, DNS, ARP,
  ICMP, TLS ClientHello/SNI, QUIC, ports, MAC/OUI, TTL, subnets, NAT/gateway, latency & loss.
- **Operating Systems:** threads, producer-consumer, bounded queue/backpressure, locks (RLock), privileges (raw capture).
- **DSA/DAA:** hash maps O(1), deque/LRU (OrderedDict), per-second bucket arrays, sorting for top-N, sliding windows,
  linear scoring, mean/std/z-score; complexity: O(1) per packet.
- **DBMS:** normalised tables, indexes, UPSERT, aggregation tables vs raw rows, retention (prune), schema migration.
- **Statistics:** baseline, standard deviation, z-score, median/percentile (p75).
- **Software engineering/Web:** REST API, JSON, React components/state/hooks, polling, separation of concerns, testing.
- **Security & privacy:** metadata-only, no payload storage, ethical capture, honest limits.

## 5. Packages

Scapy (capture, packet build/parse), Flask (REST API + static hosting), sqlite3/threading/queue/collections/ipaddress/
ssl/heapq (standard library; `ssl` is used by the simulator to make real ClientHellos), React 18, Recharts, Vite,
Vitest + jsdom + Testing Library (frontend tests), Npcap (Windows capture driver, not a Python package).

## 6. Likely questions

**How do you know which app it is if HTTPS is encrypted?** The content is encrypted but the DNS lookup and the TLS
server name are not. We remember IP->domain and match domains to rules. It is best effort; CDNs and QUIC limit it.

**How is packet loss measured?** It is estimated: retransmitted segments plus sequence gaps over data segments.
A passive sniffer cannot directly see packets lost before it.

**How is latency measured?** TCP handshake RTT (SYN to SYN/ACK), from the capture timestamps.

**Why is the score trustworthy?** Every input is measured; thresholds/weights are documented; metrics lacking
samples are skipped; the formula is shown on the dashboard.

**Why z-score AND ratio AND a minimum rate?** z alone fires on tiny changes of a flat series; ratio alone fires on
0.1->0.5; the minimum avoids trivial alerts. All three together cut false alarms (tests confirm quiet traffic never alerts).

**Why not machine learning?** Statistics are explainable and need no training data; ML (Isolation Forest) is future work.

**Why not an LLM for explanations?** Rules are deterministic, offline, free and testable. An LLM could later rephrase.

**Why one lock?** Simplicity and correctness: all shared analytics are touched by two threads (processing + web).

**Can it see passwords/content?** No. Only metadata; HTTPS payload is encrypted and we never store payloads.

**Why can't I see my phone's traffic?** Wi-Fi/switches deliver other devices' traffic only to them. Capture on a
router/mirror/hotspot. We still *discover* the phone through ARP.

**How did you test without a real network?** A simulator builds genuine Scapy packets (real OpenSSL ClientHellos,
DNS with delays, TCP handshakes, loss/retransmission patterns) and runs them through the same pipeline; 33 backend
tests + 4 frontend tests cover parsing, detection, health, anomalies, DB history and the dashboard.

**Throughput?** About 9,500 packets/s in a single processing thread in our benchmark (home Wi-Fi is far lower).
