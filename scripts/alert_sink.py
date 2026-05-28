from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class AlertSink(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        payload = self.rfile.read(length)
        try:
            body = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            body = {"raw": payload.decode("utf-8", errors="replace")}

        print("[alert-log]", json.dumps(body, sort_keys=True), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), AlertSink).serve_forever()
