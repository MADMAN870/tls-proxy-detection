# Setup Guide

## Prerequisites

- Docker & Docker Compose v2 (or later)
- Git

## Quick Start

```bash
# Clone the repository
git clone <repo-url> tls-inspection-proxy
cd tls-inspection-proxy

# Start all services
docker compose up -d

# Check services are healthy
docker compose ps
```

All services should show `Up` and `(healthy)` within ~15 seconds.

## Services

| Service   | URL                     | Description                        |
|-----------|-------------------------|------------------------------------|
| Web UI    | http://localhost:8000   | Dashboard, alerts, traffic viewer  |
| Proxy     | http://localhost:8082   | mitmproxy (HTTP/HTTPS intercept)   |
| Test Site | http://localhost:9000   | LeakyBank test application         |

## Authentication (Optional)

By default, auth is **disabled**. To enable:

```bash
# Generate an API key
python -c "import secrets; print(secrets.token_hex(32))"

# Create .env file with your key
echo "API_KEY=<your-generated-key>" > .env

# Restart the API
docker compose up -d --build api
```

Then configure the proxy to use the key:

```bash
docker compose up -d --build proxy
```

All `/api/*` endpoints will now require an `X-API-Key` header.

## Configure Mobile Device

### Android
1. Connect device to same network as the Docker host.
2. Set Wi-Fi proxy to `<docker-host-ip>:8082`.
3. Install mitmproxy CA certificate:
   ```bash
   docker cp tls-inspection-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca.pem .
   ```
   Transfer the file to device and install as trusted CA (Settings → Security → Install certificate).

### iOS
1. Set Wi-Fi proxy to `<docker-host-ip>:8082`.
2. Visit `http://mitm.it` on the device to install the CA profile.
3. Go to Settings → General → About → Certificate Trust Settings, enable mitmproxy.

## Generate Test Traffic

```bash
# Run built-in test traffic generator (15 requests with simulated leaks)
docker compose --profile test run test-traffic
```

This sends requests with embedded credit cards, passwords, API keys through the proxy. Check the results at http://localhost:8000.

## View Logs

```bash
# API server logs
docker compose logs -f api

# Proxy logs
docker compose logs -f proxy

# Test site logs
docker compose logs -f testsite
```

## Stop Services

```bash
# Stop all services (data persists in Docker volume)
docker compose down

# Stop and delete all data (alerts, entities, logs)
docker compose down -v
```

## Configuration

Edit `config/config.yaml` and restart the API:

```bash
docker compose restart api
```

Key settings:

| Section | Key | Description |
|---------|-----|-------------|
| `auth.enabled` | `true/false` | Enable API key authentication |
| `auth.api_key` | string | API key value (supports `${ENV_VAR}`) |
| `patterns.*.enabled` | `true/false` | Enable/disable specific detection rules |
| `patterns.*.severity` | float (0.0-1.0) | Weight for risk scoring |
| `risk_scoring.thresholds` | floats | Severity level boundaries |
| `suspicious.extensions` | list | File extensions to flag |
| `suspicious.domains` | list | Domain keywords to flag |
| `suspicious.high_volume_threshold` | bytes | Payload size threshold (default: 5MB) |
