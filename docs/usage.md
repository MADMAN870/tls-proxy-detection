# Usage Guide

## Web Dashboard

Access `http://localhost:8000`

### Dashboard (`/`)
- **Stats cards**: Total traffic, total alerts, unacknowledged count, active rules.
- **Recent alerts**: Latest 8 alerts with severity, host, risk score, and time.
- **Severity breakdown**: Bar chart showing alert distribution by level.
- **Quick actions**: Open test site, trigger a test leak, clear all alerts, view live traffic.

### Alerts (`/alerts`)
- Filter by severity: Critical, High, Medium, Low, or All.
- Each alert shows: ID, severity badge, host, path, risk score, matched findings, timestamp.
- **Acknowledge** individual alerts to track response status.
- Findings display up to 3 matched patterns (e.g., "credit_card", "password").

### Traffic (`/traffic`)
- Real-time view of all intercepted requests and responses (last 200 entries).
- Shows method, host, path, status code, content type, and content size.
- Timestamps converted to ISO format for readability.

### Entities (`/entities`)
- Tracked hosts sorted by risk score (highest first).
- Columns: Host, request count, alert count, risk score, last seen, status badge.
- Status: Clean (risk=0), Monitored (risk>0), Suspicious (risk>=2.0).

### Detection Rules (`/rules`)
- All active patterns grouped by category:
  - **Data Leak Patterns**: Credit card, email, API key, password, JWT, SSN.
  - **Suspicious Files**: Executable and archive extensions.
  - **Suspicious Destinations**: Known exfiltration domains (pastebin, etc.).
  - **Data Exfiltration**: Large payload detection.
- Each rule shows the full regex with a copy-to-clipboard button.
- Rules are loaded from `config/config.yaml` — no hardcoded values.

### Settings (`/settings`)
- View proxy configuration (listen address, SSL interception mode, upstream verify).
- View risk thresholds for each severity level.
- **Clear All Data**: Deletes all alerts, entities, and traffic from the database.

## REST API

All `/api/*` endpoints accept JSON. If auth is enabled, include `X-API-Key` header.

### Receive Traffic
```http
POST /api/v1/traffic
Content-Type: application/json
X-API-Key: <your-api-key>   # if auth enabled

{
  "type": "request",
  "method": "POST",
  "host": "example.com",
  "port": 443,
  "path": "/api/login",
  "url": "https://example.com/api/login",
  "content_type": "application/json",
  "content_length": 45,
  "content": "{\"password\": \"secret123\"}"
}
```

Response:
```json
{
  "analyzed": true,
  "risk_score": 0.25,
  "severity": "low"
}
```

### Get Alerts
```http
GET /api/v1/alerts?severity=high&limit=50
```

Response:
```json
{
  "alerts": [
    {
      "id": "ALERT-000001",
      "risk_score": 2.5,
      "severity": "high",
      "findings": [...],
      "host": "evil.com",
      "path": "/leak",
      "timestamp": "2026-06-03T19:30:00",
      "acknowledged": false
    }
  ],
  "count": 1
}
```

### Acknowledge Alert
```http
POST /api/v1/alerts/ALERT-000001/acknowledge
```

### Get Statistics
```http
GET /api/v1/stats
```

Response:
```json
{
  "total_traffic": 150,
  "total_alerts": 12,
  "unacknowledged": 3,
  "active_rules": 9,
  "by_severity": {"low": 5, "medium": 4, "high": 2, "critical": 1}
}
```

### Health Check
```http
GET /health
```

Response:
```json
{"status": "ok", "alerts": 12, "traffic": 150}
```

### Clear All Data
```http
POST /api/v1/clear
```

### Trigger Test Leak
```http
POST /api/v1/test/trigger-leak
```

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/api/v1/traffic` | 1000/minute |
| `/api/v1/alerts` | 60/minute |
| `/api/v1/alerts/*/acknowledge` | 60/minute |
| `/api/v1/clear` | 30/minute |
| `/api/v1/test/trigger-leak` | 10/minute |

On rate limit hit, returns `429 Too Many Requests`.

## Pattern Detection

The proxy detects the following patterns in HTTP/HTTPS traffic. All patterns are configurable in `config/config.yaml`.

| Category            | Examples                            | Default Weight |
|---------------------|-------------------------------------|----------------|
| Credit Cards        | 4111111111111111                    | 0.30           |
| SSN                 | 123-45-6789                         | 0.30           |
| Email Addresses     | user@example.com                    | 0.10           |
| API Keys            | `api_key=sk-abc...`, Bearer tokens  | 0.25           |
| Passwords           | `password=secret123`                | 0.25           |
| JWT Tokens          | `eyJ...payload...signature`         | 0.20           |
| Suspicious Files    | `.exe`, `.dll`, `.ps1`, `.zip`      | 0.15           |
| Suspicious Domains  | pastebin.com, raw IPs               | 0.20           |
| High Volume         | Transfers > 5 MB                    | 0.15           |

## Testing

Run the test suite inside the container:

```bash
docker exec tls-inspection-api pip install pytest
docker exec tls-inspection-api python -m pytest tests/ -v
```

Or add pytest to `requirements.txt` and rebuild:

```bash
echo "pytest>=8.0" >> requirements.txt
docker compose up -d --build api
docker exec tls-inspection-api python -m pytest tests/ -v
```
