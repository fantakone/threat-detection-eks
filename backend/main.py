"""
main.py — FastAPI backend with WebSocket for real-time threat detection.
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Optional
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from collector import PrometheusCollector, CloudWatchCollector, LocalFileCollector
from detector import AnomalyDetector
from simulator import generate_batch


# ─────────────────────────────────────────
# APP
# ─────────────────────────────────────────

app = FastAPI(title="Threat Detection EKS", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


# ─────────────────────────────────────────
# STATE
# ─────────────────────────────────────────

detector      = AnomalyDetector(window_size=200, contamination=0.05)
event_history = deque(maxlen=500)   # last 500 enriched events
ws_clients: list[WebSocket] = []

# Configurable sources (set via /api/config)
config = {
    "mode":             "simulator",   # "simulator" | "local" | "prometheus" | "cloudwatch"
    "prometheus_url":   "http://localhost:9090",
    "cloudwatch_group": "/aws/eks/webservice-cluster",
    "cloudwatch_region": "eu-west-3",
    "local_file":       "data/sample_logs.jsonl",
    "interval_seconds": 3,
    "running":          False,
}

collectors = {}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def build_collectors():
    collectors.clear()
    mode = config["mode"]

    if mode == "simulator":
        pass  # handled inline

    elif mode == "local":
        collectors["local"] = LocalFileCollector(config["local_file"])

    elif mode == "prometheus":
        collectors["prometheus"] = PrometheusCollector(config["prometheus_url"])

    elif mode == "cloudwatch":
        collectors["cloudwatch"] = CloudWatchCollector(
            log_group=config["cloudwatch_group"],
            region=config["cloudwatch_region"],
        )

    elif mode == "all":
        collectors["prometheus"] = PrometheusCollector(config["prometheus_url"])
        collectors["cloudwatch"] = CloudWatchCollector(
            log_group=config["cloudwatch_group"],
            region=config["cloudwatch_region"],
        )
        collectors["local"] = LocalFileCollector(config["local_file"])


def get_stats() -> dict:
    total     = len(event_history)
    anomalies = sum(1 for e in event_history if e.get("is_anomaly"))
    critical  = sum(1 for e in event_history if e.get("anomaly_label") == "critical")
    suspicious = sum(1 for e in event_history if e.get("anomaly_label") == "suspicious")

    by_type: dict = {}
    for e in event_history:
        t = e.get("event_type", "other")
        by_type[t] = by_type.get(t, 0) + 1

    return {
        "total_events":  total,
        "anomalies":     anomalies,
        "critical":      critical,
        "suspicious":    suspicious,
        "normal":        total - anomalies,
        "model_trained": detector.model_trained,
        "buffer_size":   detector.buffer_size,
        "by_type":       by_type,
    }


async def broadcast(message: dict):
    dead = []
    for ws in ws_clients:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.remove(ws)


# ─────────────────────────────────────────
# BACKGROUND DETECTION LOOP
# ─────────────────────────────────────────

async def detection_loop():
    while config["running"]:
        try:
            # Collect raw events
            raw_events = []

            if config["mode"] == "simulator":
                raw_events = generate_batch(batch_size=8)
            else:
                for name, col in collectors.items():
                    try:
                        raw_events.extend(col.collect())
                    except Exception as e:
                        print(f"[{name}] Collection error: {e}")

            # Score each event
            for event in raw_events:
                enriched = detector.score(event)
                event_history.append(enriched)

                # Broadcast to all WebSocket clients
                await broadcast({
                    "type":  "event",
                    "data":  enriched,
                    "stats": get_stats(),
                })

                # Small delay between events for smooth UI
                await asyncio.sleep(0.05)

        except Exception as e:
            print(f"[Loop] Error: {e}")

        await asyncio.sleep(config["interval_seconds"])


# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>Threat Detection API</h1>")


@app.get("/health")
async def health():
    return {"status": "ok", "running": config["running"]}


@app.get("/api/stats")
async def stats():
    return get_stats()


@app.get("/api/events")
async def get_events(limit: int = 100, anomalies_only: bool = False):
    events = list(event_history)
    if anomalies_only:
        events = [e for e in events if e.get("is_anomaly")]
    return events[-limit:]


@app.post("/api/start")
async def start_detection():
    if config["running"]:
        return {"status": "already_running"}
    config["running"] = True
    build_collectors()
    asyncio.create_task(detection_loop())
    return {"status": "started", "mode": config["mode"]}


@app.post("/api/stop")
async def stop_detection():
    config["running"] = False
    return {"status": "stopped"}


@app.post("/api/reset")
async def reset():
    config["running"] = False
    event_history.clear()
    return {"status": "reset"}


class Config(BaseModel):
    mode:               Optional[str] = None
    prometheus_url:     Optional[str] = None
    cloudwatch_group:   Optional[str] = None
    cloudwatch_region:  Optional[str] = None
    local_file:         Optional[str] = None
    interval_seconds:   Optional[int] = None


@app.post("/api/config")
async def update_config(body: Config):
    if body.mode:             config["mode"]               = body.mode
    if body.prometheus_url:   config["prometheus_url"]     = body.prometheus_url
    if body.cloudwatch_group: config["cloudwatch_group"]   = body.cloudwatch_group
    if body.cloudwatch_region:config["cloudwatch_region"]  = body.cloudwatch_region
    if body.local_file:       config["local_file"]         = body.local_file
    if body.interval_seconds: config["interval_seconds"]   = body.interval_seconds
    return config


# ─────────────────────────────────────────
# WEBSOCKET
# ─────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)

    # Send current state immediately
    await websocket.send_text(json.dumps({
        "type":   "init",
        "events": list(event_history)[-50:],
        "stats":  get_stats(),
        "config": config,
    }))

    try:
        while True:
            # Keep alive — listen for client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        if websocket in ws_clients:
            ws_clients.remove(websocket)
