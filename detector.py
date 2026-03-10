"""
detector.py — Isolation Forest anomaly detection on log events.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from collections import deque
from datetime import datetime, timezone
import hashlib


# ─────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────

SEVERITY_MAP = {"info": 0, "warning": 1, "error": 2, "critical": 3}

EVENT_TYPE_MAP = {
    "http_4xx":              0,
    "http_5xx":              1,
    "access_denied":         2,
    "server_error":          3,
    "pod_restart":           4,
    "oom_killed":            5,
    "crash_loop":            6,
    "high_cpu":              7,
    "high_latency":          8,
    "unexpected_deployment": 9,
    "other":                 10,
}

SOURCE_MAP = {
    "prometheus":  0,
    "cloudwatch":  1,
    "local_file":  2,
    "simulator":   3,
}


def extract_features(event: dict) -> np.ndarray:
    """Convert a log event to a numeric feature vector."""
    severity   = SEVERITY_MAP.get(event.get("severity", "info"), 0)
    etype      = EVENT_TYPE_MAP.get(event.get("event_type", "other"), 10)
    source     = SOURCE_MAP.get(event.get("source", "local_file"), 2)
    meta       = event.get("metadata", {})

    # Numeric metadata features
    value      = float(meta.get("value", 0))
    restarts   = float(meta.get("restarts", 0))
    cpu_pct    = float(meta.get("cpu_pct", 0))
    latency_ms = float(meta.get("latency_ms", 0))
    status     = float(meta.get("status", 200))
    status_err = 1.0 if status >= 400 else 0.0

    return np.array([
        severity,
        etype,
        source,
        value,
        restarts,
        cpu_pct,
        latency_ms / 1000.0,   # normalise to seconds
        status_err,
    ], dtype=float)


# ─────────────────────────────────────────
# ANOMALY DETECTOR
# ─────────────────────────────────────────

class AnomalyDetector:
    """
    Sliding-window Isolation Forest detector.
    Trains on a rolling buffer of recent events and scores each new event.
    """

    def __init__(self, window_size: int = 200, contamination: float = 0.05):
        self.window_size   = window_size
        self.contamination = contamination
        self.buffer        = deque(maxlen=window_size)
        self.model         = None
        self._event_count  = 0

    def _train(self):
        if len(self.buffer) < 20:
            return
        X = np.array(list(self.buffer))
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self.model.fit(X)

    def score(self, event: dict) -> dict:
        """
        Score a single event.
        Returns the event enriched with anomaly info.
        """
        features = extract_features(event)
        self.buffer.append(features)
        self._event_count += 1

        # Retrain every 20 events
        if self._event_count % 20 == 0:
            self._train()

        anomaly_score = 0.0
        is_anomaly    = False

        if self.model is not None:
            raw_score     = self.model.score_samples([features])[0]
            # Convert to 0–1 (higher = more anomalous)
            anomaly_score = float(np.clip(1 - (raw_score + 0.5), 0, 1))
            is_anomaly    = self.model.predict([features])[0] == -1

        # Always flag critical events as anomalies
        if event.get("severity") == "critical":
            is_anomaly    = True
            anomaly_score = max(anomaly_score, 0.85)

        enriched = dict(event)
        enriched["anomaly_score"]   = round(anomaly_score, 3)
        enriched["is_anomaly"]      = is_anomaly
        enriched["anomaly_label"]   = _label(anomaly_score, is_anomaly)
        enriched["id"]              = _event_id(event)
        return enriched

    def batch_score(self, events: list) -> list:
        return [self.score(e) for e in events]

    @property
    def buffer_size(self) -> int:
        return len(self.buffer)

    @property
    def model_trained(self) -> bool:
        return self.model is not None


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _label(score: float, is_anomaly: bool) -> str:
    if not is_anomaly:
        return "normal"
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "suspicious"
    return "unusual"


def _event_id(event: dict) -> str:
    key = f"{event.get('timestamp','')}{event.get('event_type','')}{event.get('message','')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]
