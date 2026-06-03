import json
import os
import time
import urllib.request
import urllib.error

API_URL = os.getenv("ANALYZER_API_URL", "http://api:8000")
API_KEY = os.getenv("API_KEY", "")
MAX_CONTENT = 5 * 1024 * 1024
MAX_CONTENT_RESPONSE = 1024 * 1024
MAX_RETRIES = 3
BACKOFF_BASE = 0.5


class TLSInspector:
    def __init__(self):
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _send(self, data: dict):
        payload = json.dumps(data).encode()
        req = urllib.request.Request(
            f"{API_URL}/api/v1/traffic",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": API_KEY,
            },
            method="POST",
        )
        last_exc = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self._opener.open(req, timeout=5)
                if resp.status == 429:
                    time.sleep(BACKOFF_BASE * attempt)
                    continue
                return
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < MAX_RETRIES:
                    time.sleep(BACKOFF_BASE * attempt)
                    continue
                last_exc = e
                break
            except Exception as e:
                last_exc = e
                if attempt < MAX_RETRIES:
                    time.sleep(BACKOFF_BASE * attempt)
                continue
        if last_exc:
            import sys
            print(f"Failed to send traffic data after {MAX_RETRIES} retries: {last_exc}", file=sys.stderr)

    def _decode(self, data: bytes, max_size: int) -> str:
        if data and len(data) < max_size:
            try:
                return data.decode("utf-8", errors="replace")
            except Exception:
                pass
        return None

    def request(self, flow):
        try:
            req = flow.request
            self._send({
                "type": "request",
                "method": req.method,
                "host": req.host,
                "port": req.port,
                "path": req.path,
                "url": req.pretty_url,
                "content_type": req.headers.get("content-type", ""),
                "content_length": len(req.content) if req.content else 0,
                "content": self._decode(req.content, MAX_CONTENT),
                "timestamp": getattr(flow, "timestamp_start", time.time()),
            })
        except Exception as e:
            import sys
            print(f"Addon request error: {e}", file=sys.stderr)

    def response(self, flow):
        try:
            resp = flow.response
            self._send({
                "type": "response",
                "method": flow.request.method,
                "host": flow.request.host,
                "path": flow.request.path,
                "url": flow.request.pretty_url,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "content_length": len(resp.content) if resp.content else 0,
                "content": self._decode(resp.content, MAX_CONTENT_RESPONSE),
                "timestamp": getattr(flow, "timestamp_end", time.time()),
            })
        except Exception as e:
            import sys
            print(f"Addon response error: {e}", file=sys.stderr)


addons = [TLSInspector()]
