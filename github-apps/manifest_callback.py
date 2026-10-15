#!/usr/bin/env python3
"""Serve the GitHub App manifest form and capture its one-time conversion code."""

from __future__ import annotations

import argparse
import html
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, quote, urlparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--code-file", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--registration-url", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = args.manifest.read_text(encoding="utf-8")
    action = f"{args.registration_url}?state={quote(args.state)}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_html(self, status: int, body: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            request = urlparse(self.path)
            if request.path == "/start":
                self.send_html(
                    200,
                    "<!doctype html><meta charset='utf-8'>"
                    "<title>Register GitHub App</title>"
                    f"<form id='manifest' method='post' action='{html.escape(action, quote=True)}'>"
                    f"<input type='hidden' name='manifest' value='{html.escape(manifest, quote=True)}'>"
                    "</form><p>GitHub App 등록 페이지로 이동합니다.</p>"
                    "<script>document.getElementById('manifest').submit()</script>",
                )
                return

            if request.path == "/callback":
                query = parse_qs(request.query)
                if query.get("state", [""])[0] != args.state:
                    self.send_html(400, "<h1>state 검증 실패</h1><p>터미널에서 다시 시도하세요.</p>")
                    return
                code = query.get("code", [""])[0]
                if not code:
                    self.send_html(400, "<h1>code가 없습니다</h1><p>터미널에서 다시 시도하세요.</p>")
                    return

                descriptor = os.open(args.code_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    output.write(code)
                    output.write("\n")
                self.send_html(200, "<h1>등록 정보를 받았습니다.</h1><p>터미널로 돌아가세요.</p>")
                Thread(target=self.server.shutdown, daemon=True).start()
                return

            self.send_html(404, "<h1>Not found</h1>")

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    args.ready_file.write_text(str(args.port), encoding="utf-8")
    args.ready_file.chmod(0o600)
    server.serve_forever()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
