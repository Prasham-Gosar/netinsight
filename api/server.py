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

from flask import Flask, abort, jsonify, request, send_from_directory

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

    # ---- history (from SQLite) ---------------------------------------------------
    def need_db():
        if not engine.db:
            abort(503, description="Database is disabled")
        engine.flush()                    # make sure the newest minute is included

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
