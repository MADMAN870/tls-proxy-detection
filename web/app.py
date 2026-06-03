from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, Query, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from analyzer.engine import AnalysisEngine, TrafficRecord
from alerts.manager import AlertManager
from storage.log_writer import TrafficLogger

env = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    auto_reload=False,
)


class TrafficPayload(BaseModel):
    type: str
    method: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: int = 0
    content: Optional[str] = None
    timestamp: Optional[float] = None


def verify_api_key(config: dict, request: Request):
    auth_config = config.get("auth", {})
    if not auth_config.get("enabled", False):
        return True
    expected = auth_config.get("api_key", "")
    if not expected:
        return True
    provided = request.headers.get("X-API-Key", "")
    if provided == expected:
        return True
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")


def create_app(
    alert_manager: AlertManager,
    analyzer: AnalysisEngine,
    config: dict,
    traffic_logger: Optional[TrafficLogger] = None,
) -> FastAPI:
    limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
    app = FastAPI(title="TLS Inspection Proxy", version="2.0.0", docs_url=None, redoc_url=None)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    traffic_buffer: list = []

    def _render(name: str, **context) -> str:
        template = env.get_template(name)
        return template.render(**context)

    def _build_stats():
        s = alert_manager.stats()
        return {
            "total_traffic": len(traffic_buffer),
            "total_alerts": s["total_alerts"],
            "unacknowledged": s["unacknowledged"],
            "active_rules": len(analyzer.patterns),
            "by_severity": s.get("by_severity", {}),
        }

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if config.get("auth", {}).get("enabled", False) and request.url.path.startswith("/api/"):
            try:
                verify_api_key(config, request)
            except HTTPException:
                return HTMLResponse(status_code=401, content='{"error":"unauthorized"}')
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        alerts = alert_manager.get_alerts(limit=20)
        stats = _build_stats()
        html = _render("index.html", request=request, alerts=alerts, stats=stats)
        return HTMLResponse(html)

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts_page(request: Request, severity: str = Query(None)):
        alerts = alert_manager.get_alerts(severity=severity, limit=200)
        html = _render("alerts.html", request=request, alerts=alerts, severity=severity)
        return HTMLResponse(html)

    @app.post("/alerts")
    async def alerts_acknowledge(request: Request):
        form = await request.form()
        alert_id = form.get("acknowledge")
        if alert_id:
            alert_manager.acknowledge(alert_id)
        return RedirectResponse(url="/alerts", status_code=303)

    @app.post("/dashboard/acknowledge-all")
    async def dashboard_acknowledge_all():
        alert_manager.clear()
        return RedirectResponse(url="/", status_code=303)

    @app.post("/dashboard/trigger-leak")
    async def dashboard_trigger_leak():
        alert_manager.trigger({
            "risk_score": 3.5,
            "severity": "critical",
            "findings": [{"pattern_name": "ssn", "pattern_type": "data_leak", "matches": ["123-45-6789"], "severity": 0.3, "location": "body"}],
            "url": "http://test.example.com/api/leak",
            "host": "test.example.com",
            "path": "/api/leak",
            "method": "POST",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return RedirectResponse(url="/", status_code=303)

    @app.get("/traffic", response_class=HTMLResponse)
    async def traffic_page(request: Request):
        records = []
        for r in reversed(traffic_buffer[-200:]):
            rec = dict(r)
            ts = rec.get("timestamp")
            if isinstance(ts, (int, float)):
                rec["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            records.append(rec)
        html = _render("traffic.html", request=request, records=records)
        return HTMLResponse(html)

    @app.get("/entities", response_class=HTMLResponse)
    async def entities_page(request: Request):
        entities = alert_manager.get_entities()
        html = _render("entities.html", request=request, entities=entities)
        return HTMLResponse(html)

    @app.get("/rules", response_class=HTMLResponse)
    async def rules_page(request: Request):
        rules_list = list(analyzer.patterns)
        html = _render("rules.html", request=request, rules=rules_list)
        return HTMLResponse(html)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        html = _render("settings.html", request=request)
        return HTMLResponse(html)

    @app.get("/about", response_class=HTMLResponse)
    async def about_page(request: Request):
        html = _render("about.html", request=request)
        return HTMLResponse(html)

    from web.docs_content import DOCS, DOC_CONTENT

    def _get_lang(request: Request) -> str:
        return request.cookies.get("docs_lang", "en")

    @app.get("/docs", response_class=HTMLResponse)
    async def docs_landing(request: Request):
        stats = _build_stats()
        lang = _get_lang(request)
        html = _render("docs.html", request=request, stats=stats, docs=DOCS, doc_content=None, section=None, page=None, lang=lang)
        return HTMLResponse(html)

    @app.get("/docs/{section}/{page_name}", response_class=HTMLResponse)
    async def docs_page(request: Request, section: str, page_name: str):
        stats = _build_stats()
        lang = _get_lang(request)
        key = f"{section}/{page_name}"
        content = DOC_CONTENT.get(key)
        if not content:
            from fastapi.responses import HTMLResponse as HR
            return HR(status_code=404, content="Documentation page not found" if lang == "en" else "Page de documentation introuvable")
        html = _render("docs.html", request=request, stats=stats, docs=DOCS, doc_content=content, section=section, page=page_name, lang=lang)
        return HTMLResponse(html)

    @app.get("/api/v1/alerts")
    @limiter.limit("60/minute")
    async def get_alerts(request: Request, severity: str = Query(None), limit: int = Query(100)):
        alerts = alert_manager.get_alerts(severity=severity, limit=limit)
        return {"alerts": [a.__dict__ for a in alerts], "count": len(alerts)}

    @app.post("/api/v1/alerts/{alert_id}/acknowledge")
    @limiter.limit("60/minute")
    async def acknowledge_alert(request: Request, alert_id: str):
        ok = alert_manager.acknowledge(alert_id)
        return {"success": ok, "alert_id": alert_id}

    @app.post("/api/v1/alerts/acknowledge-all")
    @limiter.limit("30/minute")
    async def acknowledge_all(request: Request):
        count = 0
        for a in alert_manager.get_alerts(limit=500):
            if not a.acknowledged:
                alert_manager.acknowledge(a.id)
                count += 1
        return {"success": True, "acknowledged": count}

    @app.get("/api/v1/stats")
    async def stats(request: Request):
        return _build_stats()

    @app.post("/api/v1/traffic")
    @limiter.limit("1000/minute")
    async def receive_traffic(request: Request, payload: TrafficPayload):
        record = payload.model_dump()
        traffic_buffer.append(record)
        if traffic_logger:
            traffic_logger.write(record)
        result = analyzer.analyze(TrafficRecord(**record))
        return {"analyzed": True, "risk_score": result.risk_score, "severity": result.severity}

    @app.post("/api/v1/test/trigger-leak")
    @limiter.limit("10/minute")
    async def trigger_leak(request: Request):
        alert_manager.trigger({
            "risk_score": 3.5,
            "severity": "critical",
            "findings": [{"pattern_name": "ssn", "pattern_type": "data_leak", "matches": ["123-45-6789"], "severity": 0.3, "location": "body"}],
            "url": "http://test.example.com/api/leak",
            "host": "test.example.com",
            "path": "/api/leak",
            "method": "POST",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"success": True}

    @app.post("/settings/clear")
    async def settings_clear():
        traffic_buffer.clear()
        alert_manager.clear()
        return RedirectResponse(url="/settings", status_code=303)

    @app.post("/api/v1/clear")
    @limiter.limit("30/minute")
    async def clear_all(request: Request):
        traffic_buffer.clear()
        alert_manager.clear()
        return {"success": True}

    @app.get("/health")
    async def health():
        return {"status": "ok", "alerts": alert_manager.stats()["total_alerts"], "traffic": len(traffic_buffer)}

    @app.get("/ca.pem")
    async def download_ca():
        ca_path = Path(__file__).parent / "static" / "mitmproxy-ca.pem"
        if ca_path.exists():
            return FileResponse(str(ca_path), media_type="application/x-pem-file", filename="mitmproxy-ca.pem")
        return HTMLResponse("CA certificate not found. Run: docker cp tls-inspection-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca.pem web/static/", status_code=404)

    @app.on_event("shutdown")
    async def shutdown():
        alert_manager.close()
        if traffic_logger:
            traffic_logger.close()

    return app
