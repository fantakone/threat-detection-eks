"""
simulator.py — Generates realistic EKS/WordPress log events for testing.
Injects occasional anomalies (attacks, crashes, traffic spikes).
"""

import random
import json
import os
import time
from datetime import datetime, timezone


PODS = [
    "wordpress-chart-6d9f8b-xk2lp",
    "wordpress-chart-6d9f8b-mn7qr",
    "prometheus-kube-stack-abc12",
    "grafana-7f9d6c-zp3xt",
]

PATHS = ["/", "/wp-login.php", "/wp-admin/", "/api/v1/posts",
         "/wp-content/uploads/", "/xmlrpc.php", "/sitemap.xml"]

NORMAL_STATUSES = [200, 200, 200, 200, 200, 301, 304]
ERROR_STATUSES  = [400, 401, 403, 404, 500, 502, 503]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def normal_request() -> dict:
    return {
        "timestamp":  _ts(),
        "event":      "http_request",
        "method":     random.choice(["GET", "GET", "GET", "POST"]),
        "path":       random.choice(PATHS),
        "status":     random.choice(NORMAL_STATUSES),
        "latency_ms": random.randint(20, 400),
        "pod":        random.choice(PODS),
        "source":     "simulator",
    }


def brute_force_attack() -> list:
    """Burst of 401/403 on wp-login."""
    events = []
    for _ in range(random.randint(15, 30)):
        events.append({
            "timestamp":  _ts(),
            "event":      "http_request",
            "method":     "POST",
            "path":       "/wp-login.php",
            "status":     random.choice([401, 403]),
            "latency_ms": random.randint(50, 200),
            "pod":        random.choice(PODS),
            "source":     "simulator",
        })
    return events


def traffic_spike() -> list:
    """Sudden burst of high-latency requests."""
    events = []
    for _ in range(random.randint(20, 40)):
        events.append({
            "timestamp":  _ts(),
            "event":      "http_request",
            "method":     "GET",
            "path":       random.choice(PATHS),
            "status":     random.choice([200, 200, 500, 503]),
            "latency_ms": random.randint(3000, 8000),
            "pod":        random.choice(PODS),
            "source":     "simulator",
        })
    return events


def pod_crash() -> dict:
    return {
        "timestamp": _ts(),
        "event":     "OOMKilled",
        "pod":       random.choice(PODS),
        "source":    "simulator",
        "latency_ms": 0,
        "status":    0,
    }


def crash_loop() -> dict:
    return {
        "timestamp": _ts(),
        "event":     "CrashLoopBackOff",
        "pod":       random.choice(PODS),
        "source":    "simulator",
        "latency_ms": 0,
        "status":    0,
    }


def unexpected_deployment() -> dict:
    return {
        "timestamp": _ts(),
        "event":     "unexpected_deployment",
        "message":   f"Deployment wordpress-chart updated by unknown user at {_ts()}",
        "pod":       "kube-system",
        "source":    "simulator",
        "latency_ms": 0,
        "status":    0,
    }


def server_errors() -> list:
    events = []
    for _ in range(random.randint(5, 12)):
        events.append({
            "timestamp":  _ts(),
            "event":      "http_request",
            "method":     random.choice(["GET", "POST"]),
            "path":       random.choice(PATHS),
            "status":     random.choice(ERROR_STATUSES[4:]),
            "latency_ms": random.randint(500, 2000),
            "pod":        random.choice(PODS),
            "source":     "simulator",
        })
    return events


# ─────────────────────────────────────────
# STREAM GENERATOR
# ─────────────────────────────────────────

ANOMALY_SCENARIOS = [
    ("brute_force",           brute_force_attack,      0.08),
    ("traffic_spike",         traffic_spike,            0.06),
    ("pod_crash",             lambda: [pod_crash()],    0.04),
    ("crash_loop",            lambda: [crash_loop()],   0.03),
    ("unexpected_deployment", lambda: [unexpected_deployment()], 0.02),
    ("server_errors",         server_errors,            0.07),
]


def generate_batch(batch_size: int = 10) -> list:
    """
    Generate a mixed batch of normal + occasional anomalous events.
    """
    events = []

    # Normal traffic
    for _ in range(batch_size):
        events.append(normal_request())

    # Maybe inject an anomaly
    for name, fn, prob in ANOMALY_SCENARIOS:
        if random.random() < prob:
            anomaly_events = fn()
            events.extend(anomaly_events)
            break  # one anomaly type per batch

    random.shuffle(events)
    return events


def write_sample_file(path: str = "data/sample_logs.jsonl", n: int = 500):
    """Write a sample JSONL log file for offline testing."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for i in range(n):
            batch = generate_batch(5)
            for ev in batch:
                f.write(json.dumps(ev) + "\n")
    print(f"✅ Sample log file written → {path} ({n * 5} events approx.)")


if __name__ == "__main__":
    write_sample_file()
