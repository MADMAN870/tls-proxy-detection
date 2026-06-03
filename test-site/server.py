from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import time
from urllib.request import Request, urlopen
from urllib.error import URLError

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "9000"))
ANALYZER_API = os.getenv("ANALYZER_API_URL", "http://api:8000")


def forward_to_api(path: str, body: str, method: str = "POST"):
    payload = json.dumps({
        "type": "request",
        "method": method,
        "host": "testsite",
        "path": path,
        "url": f"http://testsite:{PORT}{path}",
        "content": body,
        "content_length": len(body),
        "timestamp": time.time(),
    }).encode()
    req = Request(
        f"{ANALYZER_API}/api/v1/traffic",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urlopen(req, timeout=5)
    except URLError:
        pass


class Handler(BaseHTTPRequestHandler):
    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self._send_cors()
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open(os.path.join(os.path.dirname(__file__), "index.html")) as f:
                self.wfile.write(f.read().encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"{}")

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length).decode() if length else "{}"

        print(f"[{self.path}] received: {body[:200]}")

        forward_to_api(self.path, body, "POST")

        self.send_response(200)
        self._send_cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {"raw": body}

        response = {"status": "ok", "path": self.path, "received": data}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Test site running on http://{HOST}:{PORT}")
    server.serve_forever()
