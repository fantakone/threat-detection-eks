"""
collector.py — Fetches logs/metrics from Prometheus, CloudWatch, and local files.
"""

import boto3
import requests
import json
import re
import os
from datetime import datetime, timezone, timedelta
from typing import Optional


# ─────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────

def make_event(
    source: str,
    event_type: str,
    message: str,
    severity: str = "info",
    metadata: dict = None
) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "metadata": metadata or {},
    }


# ─────────────────────────────────────────
# PROMETHEUS COLLECTOR
# ─────────────────────────────────────────

class PrometheusCollector:
    """Pulls metrics from a Prometheus endpoint."""

    def __init__(self, url: str = "http://localhost:9090"):
        self.url = url.rstrip("/")

    def query(self, promql: str) -> Optional[list]:
        try:
            res = requests.get(
                f"{self.url}/api/v1/query",
                params={"query": promql},
                timeout=5
            )
            data = res.json()
            if data.get("status") == "success":
                return data["data"]["result"]
        except Exception as e:
            print(f"[Prometheus] Query failed: {e}")
        return None

    def collect(self) -> list:
        events = []

        # HTTP 4xx / 5xx error rate
        error_queries = [
            ('http_requests_total{status=~"4.."}', "http_4xx", "HTTP 4xx errors"),
            ('http_requests_total{status=~"5.."}', "http_5xx", "HTTP 5xx errors"),
        ]
        for promql, etype, label in error_queries:
            results = self.query(promql)
            if results:
                for r in results:
                    val = float(r["value"][1])
                    if val > 0:
                        events.append(make_event(
                            source="prometheus",
                            event_type=etype,
                            message=f"{label}: {val:.0f} requests",
                            severity="warning" if etype == "http_4xx" else "error",
                            metadata={"value": val, "labels": r.get("metric", {})}
                        ))

        # Pod restarts
        results = self.query('kube_pod_container_status_restarts_total > 0')
        if results:
            for r in results:
                val = float(r["value"][1])
                pod = r.get("metric", {}).get("pod", "unknown")
                events.append(make_event(
                    source="prometheus",
                    event_type="pod_restart",
                    message=f"Pod '{pod}' has restarted {val:.0f} time(s)",
                    severity="warning" if val < 5 else "critical",
                    metadata={"restarts": val, "pod": pod}
                ))

        # OOMKilled
        results = self.query('kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}')
        if results:
            for r in results:
                pod = r.get("metric", {}).get("pod", "unknown")
                events.append(make_event(
                    source="prometheus",
                    event_type="oom_killed",
                    message=f"Pod '{pod}' was OOMKilled",
                    severity="critical",
                    metadata={"pod": pod}
                ))

        # High CPU usage (> 80%)
        results = self.query(
            '(sum(rate(container_cpu_usage_seconds_total[5m])) by (pod) / '
            'sum(kube_pod_container_resource_limits{resource="cpu"}) by (pod)) > 0.8'
        )
        if results:
            for r in results:
                pod = r.get("metric", {}).get("pod", "unknown")
                val = float(r["value"][1]) * 100
                events.append(make_event(
                    source="prometheus",
                    event_type="high_cpu",
                    message=f"Pod '{pod}' CPU usage at {val:.1f}%",
                    severity="warning",
                    metadata={"cpu_pct": val, "pod": pod}
                ))

        return events


# ─────────────────────────────────────────
# CLOUDWATCH COLLECTOR
# ─────────────────────────────────────────

class CloudWatchCollector:
    """Fetches recent log events from AWS CloudWatch."""

    def __init__(
        self,
        log_group: str = "/aws/eks/webservice-cluster",
        region: str = "eu-west-3",
        profile: str = None,
        lookback_minutes: int = 5
    ):
        self.log_group = log_group
        self.lookback_minutes = lookback_minutes
        session = boto3.Session(profile_name=profile, region_name=region)
        self.client = session.client("logs")

    def collect(self) -> list:
        events = []
        start_time = int(
            (datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes))
            .timestamp() * 1000
        )

        # Patterns to detect
        patterns = [
            (r'\b(403|401)\b',           "access_denied",        "warning"),
            (r'\b(500|502|503|504)\b',   "server_error",         "error"),
            (r'OOMKilled',               "oom_killed",           "critical"),
            (r'CrashLoopBackOff',        "crash_loop",           "critical"),
            (r'Deployment.*created|'
             r'deployment.*updated',     "unexpected_deployment","warning"),
            (r'latency.*([0-9]{4,})ms',  "high_latency",         "warning"),
        ]

        try:
            # List log streams
            streams_resp = self.client.describe_log_streams(
                logGroupName=self.log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=5
            )
            streams = [s["logStreamName"] for s in streams_resp.get("logStreams", [])]

            for stream in streams:
                try:
                    resp = self.client.get_log_events(
                        logGroupName=self.log_group,
                        logStreamName=stream,
                        startTime=start_time,
                        limit=100
                    )
                    for ev in resp.get("events", []):
                        msg = ev.get("message", "")
                        for pattern, etype, severity in patterns:
                            if re.search(pattern, msg, re.IGNORECASE):
                                events.append(make_event(
                                    source="cloudwatch",
                                    event_type=etype,
                                    message=msg[:200],
                                    severity=severity,
                                    metadata={
                                        "log_group": self.log_group,
                                        "log_stream": stream,
                                    }
                                ))
                                break
                except Exception:
                    pass

        except Exception as e:
            print(f"[CloudWatch] Collection failed: {e}")

        return events


# ─────────────────────────────────────────
# LOCAL FILE COLLECTOR
# ─────────────────────────────────────────

class LocalFileCollector:
    """
    Reads a JSONL log file for testing without AWS/Prometheus.
    Each line: {"timestamp": "...", "status": 200, "latency_ms": 45, ...}
    """

    def __init__(self, path: str = "data/sample_logs.jsonl"):
        self.path = path
        self._position = 0

    def collect(self) -> list:
        events = []
        if not os.path.exists(self.path):
            return events

        with open(self.path, "r") as f:
            f.seek(self._position)
            lines = f.readlines()
            self._position = f.tell()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue

            status   = entry.get("status", 200)
            latency  = entry.get("latency_ms", 0)
            path_    = entry.get("path", "/")
            method   = entry.get("method", "GET")
            pod      = entry.get("pod", "unknown")
            event_   = entry.get("event", "")

            # HTTP errors
            if status in (401, 403):
                events.append(make_event(
                    source="local_file",
                    event_type="access_denied",
                    message=f"{method} {path_} → {status}",
                    severity="warning",
                    metadata=entry
                ))
            elif status >= 500:
                events.append(make_event(
                    source="local_file",
                    event_type="server_error",
                    message=f"{method} {path_} → {status}",
                    severity="error",
                    metadata=entry
                ))

            # High latency (> 2000ms)
            if latency > 2000:
                events.append(make_event(
                    source="local_file",
                    event_type="high_latency",
                    message=f"{method} {path_} latency={latency}ms",
                    severity="warning",
                    metadata=entry
                ))

            # K8s events
            if event_ in ("OOMKilled", "CrashLoopBackOff"):
                events.append(make_event(
                    source="local_file",
                    event_type=event_.lower(),
                    message=f"Pod '{pod}': {event_}",
                    severity="critical",
                    metadata=entry
                ))

        return events
