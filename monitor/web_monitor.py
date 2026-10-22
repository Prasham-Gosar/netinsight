"""
web_monitor.py
---------------
An alternative to console_monitor.py: instead of printing to the
terminal, this spins up a tiny local website showing the same live
stats, refreshing automatically every second.

Analogy: console_monitor.py is like a chalkboard update in a back
office - only someone standing right there sees it. web_monitor.py
is more like a TV screen mounted in the lobby - anyone with a
browser pointed at http://127.0.0.1:5000 can watch it, and later
(Phase 3) this is the same idea a full React dashboard replaces.

How the live-refresh actually works:
  1. Flask serves one HTML page with a bit of JavaScript.
  2. That JavaScript calls /api/stats every second using fetch().
  3. /api/stats returns the aggregator's current snapshot as JSON.
  4. The JavaScript rewrites the numbers on the page - no reload needed.
This is the same pattern real dashboards use, just simplified.
"""

from flask import Flask, jsonify, render_template_string

from .console_monitor import format_bytes

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>NetInsight - Live Network Monitor</title>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e6e6e6;
           max-width: 700px; margin: 40px auto; padding: 0 20px; }
    h1 { color: #4fc3f7; }
    .card { background: #1a1d29; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
    .stat { font-size: 28px; font-weight: bold; }
    .label { color: #8a8f9c; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
    .bar-row { display: flex; align-items: center; margin: 8px 0; }
    .bar-label { width: 100px; }
    .bar-track { flex: 1; background: #2a2e3e; border-radius: 4px; height: 18px; overflow: hidden; }
    .bar-fill { background: #4fc3f7; height: 100%; transition: width 0.5s ease; }
    .bar-pct { width: 50px; text-align: right; }
    .status { color: #4caf50; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; color: #8a8f9c; font-weight: normal; padding: 6px 8px;
         border-bottom: 1px solid #2a2e3e; }
    td { padding: 6px 8px; border-bottom: 1px solid #1f2230; font-family: 'Consolas', monospace; }
    .proto-tag { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .proto-TCP { background: #1e3a5f; color: #64b5f6; }
    .proto-UDP { background: #3f2e5c; color: #ba68c8; }
    .proto-DNS { background: #1e5c3f; color: #66bb6a; }
    .proto-ICMP { background: #5c3f1e; color: #ffb74d; }
    .proto-ARP { background: #5c1e3f; color: #f06292; }
    .proto-other { background: #333744; color: #b0b6c3; }
  </style>
</head>
<body>
  <h1>NetInsight</h1>
  <div class="card">
    <div class="label">Packets Captured</div>
    <div class="stat" id="packets">-</div>
  </div>
  <div class="card">
    <div class="label">Total Traffic</div>
    <div class="stat" id="bytes">-</div>
  </div>
  <div class="card">
    <div class="label">Protocol Distribution</div>
    <div id="protocols"></div>
  </div>
  <div class="card">
    <span class="status">● RUNNING</span> &nbsp; Queue backlog: <span id="queue">-</span>
  </div>
  <div class="card">
    <div class="label">Live Packet Feed</div>
    <table>
      <thead>
        <tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Size</th><th>Flags</th></tr>
      </thead>
      <tbody id="packet-feed"></tbody>
    </table>
  </div>

  <script>
    async function refresh() {
      const res = await fetch('/api/stats');
      const data = await res.json();
      document.getElementById('packets').innerText = data.total_packets.toLocaleString();
      document.getElementById('bytes').innerText = data.total_bytes_formatted;
      document.getElementById('queue').innerText = data.queue_backlog;

      const protocolsDiv = document.getElementById('protocols');
      protocolsDiv.innerHTML = '';
      const entries = Object.entries(data.protocol_distribution).sort((a, b) => b[1] - a[1]);
      for (const [proto, pct] of entries) {
        protocolsDiv.innerHTML += `
          <div class="bar-row">
            <div class="bar-label">${proto}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
            <div class="bar-pct">${pct}%</div>
          </div>`;
      }

      const pktRes = await fetch('/api/packets');
      const packets = await pktRes.json();
      const feedBody = document.getElementById('packet-feed');
      feedBody.innerHTML = '';
      for (const p of packets) {
        const tagClass = ['TCP','UDP','DNS','ICMP','ARP'].includes(p.protocol) ? p.protocol : 'other';
        const src = p.src_port ? `${p.src_ip}:${p.src_port}` : (p.src_ip || '-');
        const dst = p.dst_port ? `${p.dst_ip}:${p.dst_port}` : (p.dst_ip || '-');
        feedBody.innerHTML += `
          <tr>
            <td>${p.packet_number}</td>
            <td>${p.time}</td>
            <td>${src}</td>
            <td>${dst}</td>
            <td><span class="proto-tag proto-${tagClass}">${p.app_protocol}</span></td>
            <td>${p.packet_size} B</td>
            <td>${p.tcp_flags || '-'}</td>
          </tr>`;
      }
    }
    refresh();
    setInterval(refresh, 1000);
  </script>
</body>
</html>
"""


def create_app(aggregator, packet_queue):
    """Builds the Flask app. Kept as a factory function so tests could
    spin up a fresh app instance without global state getting in the way."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(HTML_PAGE)

    @app.route("/api/stats")
    def stats():
        snapshot = aggregator.snapshot()
        return jsonify({
            "total_packets": snapshot["total_packets"],
            "total_bytes": snapshot["total_bytes"],
            "total_bytes_formatted": format_bytes(snapshot["total_bytes"]),
            "protocol_distribution": aggregator.protocol_distribution_percent(),
            "queue_backlog": packet_queue.qsize(),
        })

    @app.route("/api/packets")
    def packets():
        recent = aggregator.get_recent_packets(50)
        # timestamp is stored as a full ISO string (e.g. "2026-08-17T19:42:31.123456") -
        # trim it down to just HH:MM:SS for a clean display, like the "Time: 19:42:31" example
        for p in recent:
            ts = p.get("timestamp") or ""
            p["time"] = ts.split("T")[1].split(".")[0] if "T" in ts else ts
        return jsonify(recent)

    return app


def run_web_monitor(aggregator, packet_queue, host="127.0.0.1", port=5000):
    """Starts the website. Blocks until Ctrl+C, just like console_monitor.run_loop()."""
    app = create_app(aggregator, packet_queue)
    print(f"\nOpen this in your browser: http://{host}:{port}\n")
    app.run(host=host, port=port, debug=False, use_reloader=False)
