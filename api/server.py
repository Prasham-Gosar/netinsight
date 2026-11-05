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
from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape
from flask import session

from flask import Flask, abort, jsonify, request, send_from_directory, make_response
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

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


def _report_table(rows):
    table = Table(rows, colWidths=[4.7 * inch, 1.4 * inch], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dce8f2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#15324b")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b7c8d6")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


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
        def text(value, default="—"):
            return escape(str(default if value is None else value))

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER,
                                  textColor=colors.HexColor("#15324b"), spaceAfter=12))
        styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading2"], textColor=colors.HexColor("#15324b"),
                                  spaceBefore=10, spaceAfter=7))
        styles.add(ParagraphStyle(name="BodySafe", parent=styles["BodyText"], leading=14, spaceAfter=5))
        styles.add(ParagraphStyle(name="Warning", parent=styles["BodyText"], textColor=colors.HexColor("#9a5b00"),
                                  leading=14, spaceAfter=5))
        styles.add(ParagraphStyle(name="Critical", parent=styles["BodyText"], textColor=colors.HexColor("#a52222"),
                                  leading=14, spaceAfter=5))

        story = [
            Paragraph("NetInsight Network Report", styles["ReportTitle"]),
            Paragraph(f"<b>Report:</b> {text(report.get('report_id'))}", styles["BodySafe"]),
            Paragraph(f"<b>Generated:</b> {text(report.get('generated_at'))}", styles["BodySafe"]),
            Spacer(1, 0.12 * inch),
            Paragraph("Network summary", styles["SectionTitle"]),
        ]
        health = snapshot.get("health") or {}
        traffic = snapshot.get("traffic") or {}
        story.extend([
            Paragraph(f"<b>Health score:</b> {text(health.get('score'), 'N/A')} "
                      f"({text(health.get('status'), 'Unknown')})", styles["BodySafe"]),
            Paragraph(f"<b>Traffic in/out:</b> {text(traffic.get('in_bps'), 0)} / "
                      f"{text(traffic.get('out_bps'), 0)} bps", styles["BodySafe"]),
        ])

        applications = snapshot.get("applications") or []
        story.extend([Spacer(1, 0.08 * inch), Paragraph("Top applications", styles["SectionTitle"])])
        app_rows = [["Application", "Traffic"]]
        app_rows.extend([[text(app.get("name"), "Unknown"), f"{text(app.get('bytes'), 0)} bytes"]
                         for app in applications])
        if len(app_rows) == 1:
            app_rows.append(["No application data", "—"])
        story.append(_report_table(app_rows))

        story.extend([Spacer(1, 0.14 * inch), Paragraph("Anomalies & insights", styles["SectionTitle"])])
        anomalies = snapshot.get("anomalies") or []
        insights = snapshot.get("insights") or []
        if not anomalies and not insights:
            story.append(Paragraph("No anomalies or insights were recorded for this snapshot.", styles["BodySafe"]))
        for anomaly in anomalies:
            if isinstance(anomaly, dict):
                severity = str(anomaly.get("severity") or anomaly.get("level") or "warning").upper()
                title = text(anomaly.get("title"), "Anomaly")
                description = text(anomaly.get("message") or anomaly.get("text"), "No description available.")
            else:
                severity, title, description = "WARNING", "Anomaly", text(anomaly)
            style = styles["Critical"] if severity == "CRITICAL" else styles["Warning"]
            story.append(Paragraph(f"<b>{title}</b> · <b>{text(severity)}</b><br/>{description}", style))
        for insight in insights:
            if isinstance(insight, dict):
                title = text(insight.get("title"), "Insight")
                description = text(insight.get("text") or insight.get("message"), "No description available.")
                level = text(insight.get("level"), "info").upper()
                story.append(Paragraph(f"<b>{title}</b> · <b>{level}</b><br/>{description}", styles["BodySafe"]))
            else:
                story.append(Paragraph(f"<b>Insight</b><br/>{text(insight)}", styles["BodySafe"]))

        historical = snapshot.get("historical") or {}
        summary = historical.get("summary") or {}
        historical_anomalies = historical.get("anomalies") or []
        historical_health = historical.get("health") or []
        stored_traffic = sum((summary.get(key) or 0) for key in ("bytes_in", "bytes_out", "bytes_local"))
        story.extend([Spacer(1, 0.14 * inch), Paragraph("Historical context · last 30 days", styles["SectionTitle"])])
        history_rows = [
            ["Stored metric", "Value"],
            ["Stored traffic", f"{text(stored_traffic, 0)} bytes"],
            ["Stored health samples", text(len(historical_health), 0)],
            ["Stored historical anomalies", text(len(historical_anomalies), 0)],
        ]
        story.append(_report_table(history_rows))

        buffer = BytesIO()
        document = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.65 * inch,
                                     leftMargin=0.65 * inch, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
        document.build(story)
        response = make_response(buffer.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = 'attachment; filename="report.pdf"'
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
