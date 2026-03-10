# 🔍 Threat Detection — EKS

> Real-time anomaly detection on Kubernetes/WordPress logs using Isolation Forest ML — live dashboard with WebSocket.

---

## Overview

A Python + FastAPI application that continuously ingests logs from Prometheus, CloudWatch or local files, runs an **Isolation Forest** ML model to detect anomalies, and streams results to a real-time dark-themed dashboard via WebSocket.

**Anomalies detected:**

| Type | Description |
|---|---|
| 🔴 Access denied | Bursts of 401/403 — brute force attempts |
| 🔴 Traffic spike | Sudden latency increase (> 2000ms) |
| 🟠 Pod crash | OOMKilled, CrashLoopBackOff |
| 🟠 Server errors | HTTP 5xx bursts |
| 🟡 High CPU | Pod CPU > 80% |
| 🟡 Unexpected deployment | Unplanned rollouts detected |

---

## Quick Start

```bash
# Clone
git clone https://github.com/fantakone/threat-detection-eks
cd threat-detection-eks

# Install dependencies
pip install -r requirements.txt

# (Optional) Generate sample log file for testing
python backend/simulator.py

# Start the server
uvicorn backend.main:app --reload --port 8000

# Open dashboard
open http://localhost:8000
```

### Docker

```bash
docker build -t threat-detection-eks .
docker run -p 8000:8000 threat-detection-eks
```

---

## Usage

1. **Open the dashboard** at `http://localhost:8000`
2. **Select a source mode** in the Configuration panel:
   - `Simulator` — generates realistic log events with injected anomalies (no AWS needed)
   - `Local` — reads a JSONL file
   - `Prometheus` — connects to your Prometheus endpoint
   - `CloudWatch` — connects to AWS CloudWatch Logs
3. **Press ▶ start** — the Isolation Forest model trains automatically on the first 20 events
4. **Watch anomalies appear** in real-time — filtered by All / Anomalies / Critical

---

## Architecture

```
threat-detection-eks/
├── backend/
│   ├── main.py        # FastAPI + WebSocket server
│   ├── collector.py   # Prometheus / CloudWatch / Local collectors
│   ├── detector.py    # Isolation Forest anomaly scoring
│   └── simulator.py   # Realistic log generator with injected anomalies
├── frontend/
│   └── index.html     # Real-time dashboard (WebSocket)
├── requirements.txt
├── Dockerfile
└── README.md
```

**How the ML works:** A sliding window of the last 200 events is used to train an Isolation Forest every 20 new events. Each event is encoded as a feature vector (severity, event type, source, latency, status code, restart count…) and scored in real-time. Anomaly score > threshold → flagged as suspicious/critical.

---

## Connecting to your EKS cluster

```bash
# Configure AWS profile
aws configure --profile my-profile

# Set CloudWatch log group (update in dashboard config panel)
# Default: /aws/eks/webservice-cluster

# Or point to your Prometheus endpoint
# Default: http://localhost:9090
# For EKS: use kubectl port-forward
kubectl port-forward svc/prometheus-operated 9090:9090 -n monitoring
```

---

## Author

**Fanta Koné** — Cloud & Security Engineer | DevOps | AI

- 🌐 [fantakone.com](https://fantakone.com)
- 💼 [Malt](https://www.malt.fr/profile/fantadeazevedo)
