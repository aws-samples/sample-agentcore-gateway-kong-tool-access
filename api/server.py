# SPDX-License-Identifier: MIT-0
"""Synthetic Sites API (stdlib only). Runs as a sidecar next to Kong in one Fargate task.

Binds 127.0.0.1:9100, so only Kong (same task, shared localhost) can reach it; Kong enforces
key-auth in front. State is in memory and resets when the task restarts.

  GET /sites/{siteId}         -> getSite
  PUT /sites/{siteId}/status  -> setSiteStatus  body: {"status": "active"|"paused"|"closed"}
"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SITES = {
    "SITE-001": {"name": "Example Site A", "status": "active"},
    "SITE-002": {"name": "Example Site B", "status": "active"},
}
STATUSES = {"active", "paused", "closed"}
SITE = re.compile(r"^/sites/([A-Za-z0-9-]{1,32})$")
STATUS = re.compile(r"^/sites/([A-Za-z0-9-]{1,32})/status$")
MAX_BODY = 1024


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        m = SITE.match(self.path.split("?", 1)[0])
        site = SITES.get(m.group(1).upper()) if m else None
        if site is None:
            return self._send(404, {"error": "unknown site"})
        return self._send(200, {"siteId": m.group(1).upper(), **site})

    def do_PUT(self) -> None:  # noqa: N802
        m = STATUS.match(self.path.split("?", 1)[0])
        site = SITES.get(m.group(1).upper()) if m else None
        if site is None:
            return self._send(404, {"error": "unknown site"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(length, MAX_BODY)) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        status = body.get("status") if isinstance(body, dict) else None
        if status not in STATUSES:
            return self._send(400, {"error": f"status must be one of {sorted(STATUSES)}"})
        site["status"] = status
        return self._send(200, {"siteId": m.group(1).upper(), **site})

    def log_message(self, fmt: str, *args) -> None:
        print("api " + (fmt % args), flush=True)  # method, path, status only; no headers


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 9100), Handler).serve_forever()
