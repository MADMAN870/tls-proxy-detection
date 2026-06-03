# Architecture

## Overview

```
                  +-----------+
                  |  Mobile / |
                  |  Client   |
                  +-----+-----+
                        |
              HTTPS via proxy (port 8082)
                        |
                  +-----v------+
                  |   Proxy    |  mitmproxy + addon
                  | (mitmproxy)|  Intercepts TLS traffic
                  +-----+------+  Forwards to API via HTTP
                        |
              POST /api/v1/traffic  (JSON)
                        |
                  +-----v------+
                  |  API /     |  FastAPI + Uvicorn
                  |  Analyzer  |  Pydantic validation
                  +-----+------+  Rate-limited (slowapi)
                        |
              +---------+---------+
              |                   |
        +-----v-----+     +------v------+
        |  SQLite   |     |  Web UI     |
        |  Alerts   |     |  Jinja2     |
        |  Entities |     |  Dashboard  |
        +-----------+     +-------------+
```

## Components

### 1. Proxy (`proxy/addon.py`)
- mitmproxy addon intercepting HTTP/HTTPS traffic.
- Extracts request/response metadata and content.
- Exponential backoff retry (3 attempts) if API is unreachable.
- Sends `X-API-Key` header for authenticated communication.
- Forwards data to Analyzer API via HTTP POST.

### 2. Analyzer (`analyzer/`)
- **`patterns.py`** — Compiles regex patterns from `config.yaml` at startup:
  - Credit cards, SSNs, emails, passwords, API keys, JWTs.
  - Suspicious file extensions (.exe, .zip, .ps1, etc.) — configurable.
  - Suspicious domains (pastebin, raw IPs, etc.) — configurable.
  - High-volume transfers threshold — configurable.
- **`engine.py`** — Scoring engine computing risk from matched patterns.

### 3. Alert Manager (`alerts/manager.py`)
- **SQLite** persistence (WAL mode, thread-safe).
- Alert CRUD: trigger, acknowledge, clear.
- Entity tracking: hosts with request/alert counts and risk scores.
- Optional file logging (JSON lines) to `/data/alerts.log`.

### 4. Web Dashboard (`web/`)
- FastAPI serving Jinja2 templates.
- Pages: Dashboard, Alerts (filterable), Traffic log, Entities, Rules, Settings.
- REST API for external integration (`/api/v1/*`).
- **API key authentication** middleware on all `/api/*` routes (configurable).
- **Rate limiting** via `slowapi` (per-endpoint limits).

## Data Flow

1. Client → Proxy (mitmproxy on port 8082)
2. Proxy addon inspects request/response content
3. Traffic metadata sent to Analyzer API (`POST /api/v1/traffic`)
4. API validates payload (Pydantic), stores in traffic buffer
5. Analyzer scans content for sensitive patterns (from config)
6. Alert generated if risk score exceeds threshold
7. Alert persisted to SQLite database
8. Dashboard displays alerts and traffic in real time

## Risk Scoring

Risk score = sum(severity weights of all matched patterns)

| Severity | Threshold | Default |
|----------|-----------|---------|
| Low      | < 1.0     |         |
| Medium   | >= 1.0    |         |
| High     | >= 2.0    |         |
| Critical | >= 3.0    |         |

Thresholds are configurable in `config.yaml` under `risk_scoring.thresholds`.

## Pattern Weights

Configured in `config.yaml`. Defaults:

| Pattern           | Weight |
|-------------------|--------|
| Credit Card       | 0.30   |
| SSN               | 0.30   |
| API Key           | 0.25   |
| Password          | 0.25   |
| JWT Token         | 0.20   |
| Suspicious Domain | 0.20   |
| Suspicious File   | 0.15   |
| High Volume       | 0.15   |
| Email             | 0.10   |

## Persistence

| Data      | Storage | Location        |
|-----------|---------|-----------------|
| Alerts    | SQLite  | `/data/alerts.db` |
| Entities  | SQLite  | `/data/alerts.db` |
| Traffic   | Memory  | (200-entry buffer) |
| Logs      | File    | `/data/alerts.log` |
| App Logs  | File    | `/data/app.log` (rotated) |

## Security

- **Auth**: Optional API key via `auth.enabled` in config + `X-API-Key` header.
- **Rate limiting**: 200 req/min default, per-endpoint overrides.
- **Input validation**: Pydantic models on all API endpoints.
- **Health checks**: Docker HEALTHCHECK on api (HTTP) and proxy (TCP).
- **Startup ordering**: Proxy waits for API health check via `condition: service_healthy`.
