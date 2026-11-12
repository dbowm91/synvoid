#!/usr/bin/env python3
"""Stdlib HTTP upstream for the multi-service benchmark harness.

Serves a small dynamic response and a deterministic 64 KiB static response.
Handles Content-Length and chunked request bodies, HTTP/1.1 keep-alive.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATIC_BODY = (b"synvoid-bench-static-payload\n" * 2560)[:65536]
DYNAMIC_BODY = json.dumps({"ok": True, "upstream": "dynamic"}).encode() + b"\n"


def read_request_body(handler: BaseHTTPRequestHandler) -> bytes:
    transfer_encoding = (handler.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in transfer_encoding:
        parts: list[bytes] = []
        while True:
            line = handler.rfile.readline(65537).strip()
            if not line:
                break
            size = int(line.split(b";", 1)[0], 16)
            if size == 0:
                while True:
                    trailer = handler.rfile.readline(65537)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            parts.append(handler.rfile.read(size))
            handler.rfile.read(2)
        return b"".join(parts)

    length = int(handler.headers.get("Content-Length") or "0")
    return handler.rfile.read(length) if length else b""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "synvoid-bench-upstream/1"
    disable_nagle_algorithm = True

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._send(200, b"", "text/plain")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.startswith("/static/"):
            self._send(200, STATIC_BODY, "application/octet-stream")
        else:
            self._send(200, DYNAMIC_BODY, "application/json")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = read_request_body(self)
        payload = json.dumps({"ok": True, "received_bytes": len(body)}).encode() + b"\n"
        self._send(200, payload, "application/json")

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D401
        if self.server.verbose:  # type: ignore[attr-defined]
            sys.stderr.write("upstream: " + fmt % args + "\n")


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr: tuple[str, int], verbose: bool = False) -> None:
        super().__init__(addr, Handler)
        self.verbose = verbose


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    server = Server((args.host, args.port), verbose=args.verbose)
    print(f"upstream listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
