"""
server.py
----------
The web layer. A small Flask app that

  1. exposes the engine's data as JSON (a REST API you can also test in
     Postman or the browser: /api/dashboard, /api/health, ...), and
  2. serves the React dashboard (the built files in frontend/dist).

The dashboard polls /api/dashboard once a second - the same pattern real
monitoring tools use. Flask here is only a thin window onto the Engine: it
never touches packets itself.
"""

import os
from datetime import datetime
from flask import session

from flask import Flask, abort, jsonify, request, send_from_directory, make_response

DEMO_KINDS = {"dns_burst": 30, "degradation": 45, "bandwidth_spike": 25, "scan": 20}

FALLBACK_PAGE = """<!doctype html><title>NetInsight API</title>
<body style="font-family:system-ui;background:#0b1020;color:#dbe4ff;padding:40px;max-width:700px">
<h1>NetInsight API is running</h1>
<p>The React dashboard has not been built yet (no <code>frontend/dist</code> folder).</p>
<p>Run <code>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</code>, then restart.
Meanwhile the data is available at
<a style="color:#7aa2ff" href="/api/dashboard">/api/dashboard</a>.</p></body>"""


def _int(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def create_app(engine, static_dir=None, simulator=None):
    app = Flask(__name__, static_folder=None)
    app.secret_key = os.environ.get("NETINSIGHT_SECRET_KEY", "netinsight-development-key")

    @app.after_request
    def no_cache(resp):
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---- live data ---------------------------------------------------------
    @app.get("/api/dashboard")
    def dashboard():
        return jsonify(engine.dashboard(bandwidth_seconds=_int("seconds", 120, 10, 600),
                                        packets=_int("packets", 30, 1, 200), flows=_int("flows", 12, 1, 100)))

    @app.get("/api/overview")
    def overview():
        d = engine.dashboard(bandwidth_seconds=10, packets=1, flows=1)
        return jsonify({"meta": d["meta"], "totals": d["totals"], "rate": d["rate"],
                        "health": {k: d["health"][k] for k in ("score", "status", "color")}})

    @app.get("/api/health")
    def health():
        return jsonify(engine.health_view())

    @app.get("/api/bandwidth")
    def bandwidth():
        with engine.lock:
            return jsonify(engine.bandwidth.rates(_int("seconds", 120, 10, 600), engine.now()))

    @app.get("/api/protocols")
    def protocols():
        with engine.lock:
            return jsonify({"families": engine.bandwidth.families(), "protocols": engine.bandwidth.protocols(20)})

    @app.get("/api/applications")
    def applications():
        with engine.lock:
            return jsonify(engine.bandwidth.top_apps(_int("limit", 15, 1, 100)))

    @app.get("/api/devices")
    def devices():
        with engine.lock:
            return jsonify(engine.devices.snapshot(engine.now()))

    @app.get("/api/top-ips")
    def top_ips():
        with engine.lock:
            return jsonify(engine.bandwidth.top_remotes(_int("limit", 15, 1, 100)))

    @app.get("/api/flows")
    def flows():
        with engine.lock:
            return jsonify(engine.flows.top_flows(_int("limit", 25, 1, 200)))

    @app.get("/api/packets")
    def packets():
        return jsonify(engine.packets_view(_int("limit", 50, 1, 200)))

    @app.get("/api/alerts")
    def alerts():
        return jsonify(engine.alerts_view(_int("limit", 30, 1, 100)))

    @app.get("/api/insights")
    def insights():
        return jsonify(engine.insights_view())

    @app.get("/api/graph/topology")
    def graph_topology():
        """Return a bounded live topology snapshot for the knowledge graph."""
        with engine.lock:
            now = engine.now()
            devices = [d for d in engine.devices.snapshot(now) if not d["is_gateway"]][:5]
            remotes = engine.bandwidth.top_remotes(8)
            flows = engine.flows.top_flows(24)
            alerts = engine.alerts_view(30)
            active_alerts = [a for a in alerts if not a.get("resolved")]
            anomalous_ips = {
                endpoint.rsplit(":", 1)[0]
                for flow in flows
                if flow["state"] in ("TIMEOUT", "RESET")
                for endpoint in (flow["client"], flow["server"])
            }
            nodes = [{
                "id": "gateway",
                "label": engine.interface_label or "Gateway / Router",
                "type": "gateway",
                "ip": engine.ctx.gateway_ip,
                "mac": None,
                "bytes": sum(d["bytes_total"] for d in devices),
                "packets": sum(d["packets"] for d in devices),
                "status": "anomalous" if active_alerts else "normal",
                "anomalies": len(active_alerts),
                "health_status": "Anomalous" if active_alerts else "Normal",
                "fx": 0, "fy": 0, "fz": 0,
            }]
            for device in devices[:20]:
                node_id = f"device:{device['key']}"
                nodes.append({
                    "id": node_id, "label": device["name"], "type": "device",
                    "ip": device.get("ip"), "mac": device.get("mac"),
                    "bytes": device["bytes_total"], "packets": device["packets"],
                    "status": "normal", "active": device["active"],
                    "vendor": device.get("vendor"), "anomalies": 0,
                    "health_status": "Normal" if device["active"] else "Idle",
                })
            remote_ids = {}
            for remote in remotes:
                node_id = f"cloud:{remote['ip']}"
                remote_ids[remote["ip"]] = node_id
                label = remote.get("app") or remote.get("domain") or remote["ip"]
                nodes.append({
                    "id": node_id, "label": label, "type": "cloud",
                    "ip": remote["ip"], "mac": None, "domain": remote.get("domain"),
                    "application": remote.get("app"), "bytes": remote["bytes"],
                    "packets": remote["packets"],                     "status": "anomalous" if remote["ip"] in anomalous_ips else "normal",
                    "anomalies": 1 if remote["ip"] in anomalous_ips else 0,
                    "health_status": "Anomalous" if remote["ip"] in anomalous_ips else "Normal",
                })
            links = []
            for flow in flows:
                server_ip = flow["server"].rsplit(":", 1)[0]
                client_ip = flow["client"].rsplit(":", 1)[0]
                target = remote_ids.get(server_ip)
                source = next((n["id"] for n in nodes if n.get("ip") == client_ip), "gateway")
                if target:
                    links.append({
                        "source": source, "target": target, "bytes": flow["bytes"],
                        "packets": flow["packets"], "app": flow["app"],
                        "active": flow["state"] not in ("TIMEOUT", "RESET"),
                        "anomalous": flow["state"] in ("TIMEOUT", "RESET") or bool(active_alerts),
                    })
            if not links:
                links = [{"source": n["id"], "target": "gateway", "bytes": n["bytes"],
                          "packets": n["packets"], "active": n.get("active", True),
                          "anomalous": n["status"] == "anomalous"} for n in nodes[1:]]
            return jsonify({"nodes": nodes, "links": links,
                            "generated_at": now, "active_alerts": len(active_alerts)})

    # ---- history (from SQLite) ---------------------------------------------------
    def need_db():
        if not engine.db:
            abort(503, description="Database is disabled")
        engine.flush()                    # make sure the newest minute is included

    def current_user():
        if not engine.db:
            abort(503, description="Database is disabled")
        user_id = session.get("user_id")
        if user_id:
            user = engine.db.user_by_id(user_id)
            if user:
                return user
        abort(401, description="Authentication required")

    @app.post("/api/auth/signup")
    def signup():
        need_db()
        payload = request.get_json(silent=True) or {}
        try:
            user = engine.db.create_user(payload.get("email", ""), payload.get("password", ""))
        except ValueError as exc:
            abort(400, description=str(exc))
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                abort(409, description="An account with that email already exists")
            raise
        session["user_id"] = user["id"]
        session.pop("guest_user_id", None)
        return jsonify({"user": user}), 201

    @app.post("/api/auth/login")
    def login():
        need_db()
        payload = request.get_json(silent=True) or {}
        user = engine.db.authenticate_user(payload.get("email", ""), payload.get("password", ""))
        if not user:
            abort(401, description="Invalid email or password")
        session["user_id"] = user["id"]
        session.pop("guest_user_id", None)
        return jsonify({"user": user})

    @app.post("/api/auth/logout")
    def logout():
        session.clear()
        return jsonify({"ok": True})

    @app.get("/api/auth/session")
    def auth_session():
        user_id = session.get("user_id")
        user = engine.db.user_by_id(user_id) if engine.db and user_id else None
        return jsonify({"user": user})

    def report_snapshot():
        data = engine.dashboard(bandwidth_seconds=120, packets=1, flows=1)
        historical_now = engine.now()
        historical = {
            "range": "30d",
            "summary": engine.db.history_summary("30d", historical_now),
            "timeline": engine.db.history_timeline("hours", historical_now),
            "health": engine.db.history_health("days", historical_now),
            "anomalies": engine.db.history_alerts("30d", historical_now),
        }
        return {
            "health": data["health"],
            "traffic": data["rate"],
            "totals": data["totals"],
            "applications": data["applications"][:10],
            "anomalies": data["alerts"][:10],
            "insights": data["insights"][:10],
            "historical": historical,
            "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }

    @app.post("/api/reports")
    def generate_report():
        need_db()
        report = engine.db.create_report(current_user()["id"], report_snapshot())
        return jsonify(report), 201

    @app.get("/api/reports")
    def reports():
        need_db()
        return jsonify(engine.db.list_reports(current_user()["id"]))

    @app.get("/api/reports/<report_id>")
    def report_detail(report_id):
        need_db()
        report = engine.db.get_report(current_user()["id"], report_id)
        if not report:
            abort(404, description="Report not found")
        return jsonify(report)

    @app.get("/api/reports/<report_id>/pdf")
    def report_pdf(report_id):
        need_db()
        report = engine.db.get_report(current_user()["id"], report_id)
        if not report:
            abort(404, description="Report not found")
        snapshot = report["snapshot"]
        lines = [
            "NetInsight Network Report", f"Report: {report['report_id']}",
            f"Generated: {report['generated_at']}",
            f"Health score: {snapshot.get('health', {}).get('score', 'N/A')}",
            f"Traffic in/out: {snapshot.get('traffic', {}).get('in_bps', 0)} / "
            f"{snapshot.get('traffic', {}).get('out_bps', 0)} bps",
            "", "Applications:",
        ] + [f"- {a.get('name', 'Unknown')}: {a.get('bytes', 0)} bytes" for a in snapshot.get("applications", [])]
        text = "\\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 11 Tf 50 760 Td ({text.replace(chr(10), ') Tj 0 -16 Td (')}) Tj ET"
        objects = [
            "<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            f"<< /Length {len(stream.encode('latin-1'))} >>\\nstream\\n{stream}\\nendstream",
        ]
        pdf = "%PDF-1.4\\n"
        offsets = [0]
        for i, obj in enumerate(objects, 1):
            offsets.append(len(pdf.encode("latin-1")))
            pdf += f"{i} 0 obj\\n{obj}\\nendobj\\n"
        xref = len(pdf.encode("latin-1"))
        pdf += f"xref\\n0 {len(objects) + 1}\\n0000000000 65535 f \\n"
        pdf += "".join(f"{offset:010d} 00000 n \\n" for offset in offsets[1:])
        pdf += f"trailer\\n<< /Size {len(objects) + 1} /Root 1 0 R >>\\nstartxref\\n{xref}\\n%%EOF"
        response = make_response(pdf.encode("latin-1"))
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"attachment; filename={report['report_id']}.pdf"
        return response

    @app.get("/api/history/summary")
    def h_summary():
        need_db()
        return jsonify(engine.db.history_summary(request.args.get("range", "today"), engine.now()))

    @app.get("/api/history/timeline")
    def h_timeline():
        need_db()
        g = request.args.get("granularity", "minutes")
        if g not in ("minutes", "hours", "days"):
            abort(400, description="granularity must be minutes, hours or days")
        return jsonify(engine.db.history_timeline(g, engine.now()))

    @app.get("/api/history/health")
    def h_health():
        need_db()
        g = request.args.get("granularity", "minutes")
        if g not in ("minutes", "hours", "days"):
            abort(400, description="granularity must be minutes, hours or days")
        return jsonify(engine.db.history_health(g, engine.now()))

    @app.get("/api/history/answers")
    def h_answers():
        need_db()
        return jsonify(engine.db.history_answers(engine.now()))

    # ---- demo controls (simulation mode only) ---------------------------------------
    @app.post("/api/demo/<kind>")
    def demo(kind):
        if simulator is None:
            abort(404, description="Demo controls are only available in --simulate mode")
        if kind not in DEMO_KINDS:
            abort(400, description=f"kind must be one of {sorted(DEMO_KINDS)}")
        duration = _int("duration", DEMO_KINDS[kind], 5, 300)
        simulator.inject(kind, duration)
        return jsonify({"ok": True, "kind": kind, "duration": duration})

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(503)
    def api_error(err):
        if request.path.startswith("/api/"):
            return jsonify({"error": err.description}), err.code
        return err

    # ---- React dashboard -----------------------------------------------------------------
    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def spa(path):
        if path.startswith("api/"):
            abort(404, description="Unknown API endpoint")
        if static_dir and os.path.isdir(static_dir):
            full = os.path.join(static_dir, path)
            if path and os.path.isfile(full):
                return send_from_directory(static_dir, path)
            index = os.path.join(static_dir, "index.html")
            if os.path.isfile(index):
                return send_from_directory(static_dir, "index.html")
        return FALLBACK_PAGE

    return app
