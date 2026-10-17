#!/usr/bin/env python3
"""Local proxy for the Tabby Shop monitor UI."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import json
import os

ROOT = Path(__file__).resolve().parent
TARGET = "https://game.tabby.meme/api/shop"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/shop":
            authorization = self.headers.get("Authorization", "")
            headers = {
                "sec-ch-ua-platform": '"macOS"',
                "Authorization": authorization,
                "Referer": "https://game.tabby.meme/",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
                "sec-ch-ua": '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
                "Content-Type": "application/json",
                "sec-ch-ua-mobile": "?0",
            }
            req = Request(TARGET, headers=headers, method="GET")
            try:
                with urlopen(req, timeout=20) as upstream:
                    body = upstream.read()
                    status = upstream.status
                    content_type = upstream.headers.get("Content-Type", "application/json")
            except HTTPError as exc:
                body = exc.read()
                status = exc.code
                content_type = exc.headers.get("Content-Type", "application/json")
            except (URLError, TimeoutError) as exc:
                body = json.dumps({"error": str(exc)}).encode()
                status = 502
                content_type = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        relative = "index.html" if self.path == "/" else self.path.lstrip("/")
        path = (ROOT / relative).resolve()
        if ROOT not in path.parents or not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        content_type = "application/json" if path.suffix == ".json" else "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Avoid printing request headers, which include the bearer token.
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    port = int(os.environ.get("TABBY_PORT", "8766"))
    print(f"Tabby Shop monitor: http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
