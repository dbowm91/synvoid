#!/usr/bin/env python3
"""Stdlib TCP/UDP echo upstream for the multi-service benchmark harness."""

from __future__ import annotations

import argparse
import socket
import socketserver
import sys


class TcpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn: socket.socket = self.request
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)


class TcpEchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_tcp(host: str, port: int) -> None:
    with TcpEchoServer((host, port), TcpEchoHandler) as server:
        print(f"tcp echo listening on {host}:{port}", flush=True)
        server.serve_forever(poll_interval=0.2)


def run_udp(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"udp echo listening on {host}:{port}", flush=True)
    while True:
        data, peer = sock.recvfrom(65536)
        sock.sendto(data, peer)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("tcp", "udp"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "tcp":
            run_tcp(args.host, args.port)
        else:
            run_udp(args.host, args.port)
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        sys.stderr.write(f"echo upstream failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
