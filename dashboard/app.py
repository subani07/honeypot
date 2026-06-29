"""
Flask + SocketIO dashboard — real-time honeypot monitoring at http://localhost:5000
"""

import os
import sys
import threading

from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from core import logger

app     = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Register live-event listener ──────────────────────────────────────────────
def _on_new_event(event: dict):
    """Called by logger whenever a new event is stored — push to all dashboard clients."""
    socketio.emit("new_event", event)

logger.add_listener(_on_new_event)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(logger.get_stats())


@app.route("/api/events")
def api_events():
    return jsonify(logger.get_recent_events(100))


@app.route("/api/credentials")
def api_credentials():
    return jsonify(logger.get_credentials(100))


# ── SocketIO events ───────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    # Send initial stats snapshot on connection
    socketio.emit("stats_update", logger.get_stats(), to=None)


def run(host: str = None, port: int = None):
    h = host or config.DASHBOARD_HOST
    p = port or config.DASHBOARD_PORT
    print(f"[Dashboard] Running at http://127.0.0.1:{p}")
    socketio.run(app, host=h, port=p, debug=False, use_reloader=False, log_output=False, allow_unsafe_werkzeug=True)
