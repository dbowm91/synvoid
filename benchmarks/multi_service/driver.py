#!/usr/bin/env python3
"""Manual-only multi-service benchmark driver (Phase 10).

This harness starts SynVoid from a built binary, starts local upstreams, runs
load through external tools (oha/h2load) or a stdlib Python client, samples the
subject process tree, and writes dated JSON + Markdown evidence.

It is deliberately not part of CI. Read README.md before changing a workload.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import http.client
import json
import math
import os
import pathlib
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCHEMA_VERSION = "synvoid.multi-service-benchmark.v1"
CLIENT_COMMANDS: List[List[str]] = []

ALL_WORKLOADS = [
    "vhost-1",
    "vhost-100",
    "vhost-1000",
    "h1-keepalive",
    "h1-concurrent",
    "tls-h2",
    "h3",
    "mixed-static-proxy",
    "waf-small",
    "waf-body",
    "chunked-upload",
    "tcp-echo",
    "tcp-multi-port",
    "udp-echo",
    "udp-multi-port",
    "multi-listener",
    "soak",
]

SIZE_BODY = 32 * 1024
CHUNKED_CHUNK = 64 * 1024
BENCH_UA = "Mozilla/5.0 (X11; Linux x86_64) SynVoidBench/1.0"
SECOND = 1.0
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_stamp() -> str:
    return utc_now().strftime("%Y-%m-%dT%H%M%SZ")


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def run_capture(cmd: Sequence[str], timeout: float = 10.0) -> Tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        return proc.returncode, (proc.stdout or "").strip()
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        return 127, f"{type(exc).__name__}: {exc}"


def tool_version(cmd: Sequence[str]) -> Optional[str]:
    code, out = run_capture(list(cmd) + ["--version"], timeout=5)
    if code == 0 and out:
        return out.splitlines()[0]
    return None


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def harness_sha() -> str:
    digest = hashlib.sha256()
    skip_dirs = {"results", "__pycache__", ".work"}
    for path in sorted(HERE.rglob("*")):
        if path.is_dir():
            continue
        if any(part in skip_dirs for part in path.relative_to(HERE).parts):
            continue
        if path.suffix in {".pyc"}:
            continue
        relative = path.relative_to(HERE).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def free_port(kind: str = "tcp") -> int:
    family = socket.AF_INET
    sock_type = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def allocate_ports() -> Dict[str, Any]:
    ports: Dict[str, Any] = {}
    for name in (
        "http",
        "admin",
        "metrics",
        "tls",
        "dynamic_upstream",
        "static_upstream",
        "tcp_single",
        "tcp_upstream",
        "udp_single",
        "udp_upstream",
    ):
        ports[name] = free_port("tcp")
    ports["h3"] = free_port("udp")
    ports["extra"] = [free_port("tcp") for _ in range(1)]
    ports["tcp_multi"] = [free_port("tcp") for _ in range(4)]
    ports["udp_multi"] = [free_port("udp") for _ in range(4)]
    # Keep generated ports distinct; collisions are unlikely but cheap to fix.
    seen = set()
    for key, value in list(ports.items()):
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item in seen:
                raise RuntimeError(f"port collision while allocating {key}={item}")
            seen.add(item)
    return ports


def cpu_model() -> str:
    try:
        for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def memory_bytes() -> Optional[int]:
    try:
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def read_proc_stat(pid: int) -> Optional[Dict[str, int]]:
    try:
        text = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    close = text.rfind(")")
    if close < 0:
        return None
    fields = text[close + 2 :].split()
    if len(fields) < 22:
        return None
    try:
        return {
            "state": fields[0].encode()[0],
            "pgrp": int(fields[2]),
            "utime": int(fields[11]),
            "stime": int(fields[12]),
            "rss_pages": int(fields[21]),
        }
    except (ValueError, IndexError):
        return None


def read_proc_status_rss(pid: int) -> int:
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def process_tree(pgid: int) -> List[int]:
    pids: List[int] = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        stat = read_proc_stat(pid)
        if stat and stat["pgrp"] == pgid and stat["state"] != ord("Z"):
            pids.append(pid)
    return pids


def count_fds(pid: int) -> int:
    try:
        return len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
    except OSError:
        return 0


class ProcessSampler:
    def __init__(self, pgid: int, interval: float = 0.5) -> None:
        self.pgid = pgid
        self.interval = interval
        self.samples: List[Dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self.sample()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sample()

    def sample(self) -> None:
        pids = process_tree(self.pgid)
        rss = 0
        fds = 0
        ticks = 0
        for pid in pids:
            stat = read_proc_stat(pid)
            if stat is None:
                continue
            ticks += stat["utime"] + stat["stime"]
            rss += stat["rss_pages"] * PAGE_SIZE
            fds += count_fds(pid)
        self.samples.append(
            {
                "at": time.monotonic(),
                "pids": pids,
                "rss_bytes": rss,
                "fds": fds,
                "cpu_ticks": ticks,
            }
        )

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.sample()

    def summary(self) -> Dict[str, Any]:
        if not self.samples:
            return {
                "process_count": 0,
                "rss_bytes_start": 0,
                "rss_bytes_end": 0,
                "rss_bytes_peak": 0,
                "fd_start": 0,
                "fd_end": 0,
                "fd_peak": 0,
                "cpu_seconds": 0.0,
                "cpu_percent": 0.0,
            }
        first = self.samples[0]
        last = self.samples[-1]
        wall = max(last["at"] - first["at"], 1e-9)
        cpu_seconds = max(0.0, (last["cpu_ticks"] - first["cpu_ticks"]) / CLK_TCK)
        return {
            "process_count": max(len(sample["pids"]) for sample in self.samples),
            "rss_bytes_start": first["rss_bytes"],
            "rss_bytes_end": last["rss_bytes"],
            "rss_bytes_peak": max(sample["rss_bytes"] for sample in self.samples),
            "fd_start": first["fds"],
            "fd_end": last["fds"],
            "fd_peak": max(sample["fds"] for sample in self.samples),
            "cpu_seconds": round(cpu_seconds, 6),
            "cpu_percent": round(100.0 * cpu_seconds / wall, 3),
        }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def http_get(
    port: int,
    path: str = "/",
    host: Optional[str] = None,
    timeout: float = 2.0,
    scheme: str = "http",
) -> Tuple[int, bytes]:
    if scheme == "https":
        context = ssl._create_unverified_context()
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=timeout, context=context
        )
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.putrequest("GET", path, skip_host=True)
        conn.putheader("Host", host or "127.0.0.1")
        conn.putheader("Connection", "close")
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_http_ready(port: int, host: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no attempt"
    while time.monotonic() < deadline:
        try:
            status, _body = http_get(port, "/", host=host)
            if status == 200:
                return
            last_error = f"status {status}"
        except Exception as exc:  # noqa: BLE001 - readiness polling
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(0.2)
    raise RuntimeError(f"SynVoid did not become ready on 127.0.0.1:{port}: {last_error}")


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scrape_prometheus(port: int) -> Optional[Dict[str, float]]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3) as response:
            text = response.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - best-effort diagnostics
        return None
    values: Dict[str, float] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}]*\})?\s+([-+0-9.eE]+)$", line)
        if not match:
            continue
        name, raw = match.groups()
        try:
            values[name] = float(raw)
        except ValueError:
            continue
    return values


def scrape_admin(port: int, token: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"summary": None, "sites": None, "attacks": None, "errors": []}
    for key, path in (
        ("summary", "/api/stats/summary"),
        ("sites", "/api/stats/sites"),
        ("attacks", "/api/stats/attacks"),
    ):
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                value = json.loads(response.read().decode())
                if key == "sites" and isinstance(value, list):
                    active = [
                        site
                        for site in value
                        if any(
                            site.get(field)
                            for field in (
                                "requests_per_second",
                                "blocked_requests",
                                "challenged_requests",
                                "proxied_requests",
                                "errors",
                            )
                        )
                    ]
                    result["sites_total"] = len(value)
                    result["sites_truncated"] = len(active) > 20
                    result[key] = active[:20]
                else:
                    result[key] = value
        except Exception as exc:  # noqa: BLE001 - best-effort diagnostics
            result["errors"].append(f"{path}: {type(exc).__name__}: {exc}")
    return result


# ---------------------------------------------------------------------------
# load clients
# ---------------------------------------------------------------------------


def latency_summary(values: List[float]) -> Dict[str, Optional[float]]:
    if not values:
        return {"p50": None, "p95": None, "p99": None}
    ordered = sorted(values)

    def pct(percent: float) -> float:
        index = int(math.ceil(percent / 100.0 * len(ordered))) - 1
        return ordered[max(0, min(index, len(ordered) - 1))]

    return {
        "p50": round(pct(50) * 1000.0, 3),
        "p95": round(pct(95) * 1000.0, 3),
        "p99": round(pct(99) * 1000.0, 3),
    }


def oha_load(
    url: str,
    *,
    duration: float,
    concurrency: int,
    host: Optional[str] = None,
    method: str = "GET",
    body_file: Optional[pathlib.Path] = None,
    http_version: Optional[str] = None,
    insecure: bool = False,
    urls_file: Optional[pathlib.Path] = None,
    connect_to: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], List[str], str]:
    oha = shutil.which("oha")
    if not oha:
        raise RuntimeError("oha not found")
    cmd = [
        oha,
        "--no-tui",
        "--output-format",
        "json",
        "--ipv4",
        "-z",
        f"{duration}s",
        "-c",
        str(concurrency),
    ]
    cmd += ["-H", f"User-Agent: {BENCH_UA}"]
    if host:
        cmd += ["--host", host]
    if method != "GET":
        cmd += ["-m", method]
    if body_file is not None:
        cmd += ["-D", str(body_file), "-T", "application/octet-stream"]
    if http_version:
        cmd += ["--http-version", http_version]
    if insecure:
        cmd.append("--insecure")
    if urls_file is not None:
        cmd += ["--urls-from-file", str(urls_file)]
    else:
        cmd.append(url)
    for mapping in connect_to or []:
        cmd += ["--connect-to", mapping]

    CLIENT_COMMANDS.append(list(cmd))
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=duration + 60,
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"oha exited {proc.returncode}: {proc.stderr.strip()[-500:]}")
    payload = json.loads(proc.stdout)
    metrics = payload.get("metrics", {})
    latency = metrics.get("latency_ms") or {}
    status_codes = {
        str(k): int(v) for k, v in (payload.get("statusCodeDistribution") or {}).items()
    }
    errors = int(sum(int(v) for v in (payload.get("errorDistribution") or {}).values()))
    total = sum(status_codes.values()) + errors
    result = {
        "requests": total,
        "requests_per_sec": round(
            float(
                metrics.get(
                    "requests_per_sec", payload.get("summary", {}).get("requestsPerSec", 0.0)
                )
            ),
            3,
        ),
        "latency_ms": {
            "p50": latency.get("p50"),
            "p95": latency.get("p95"),
            "p99": latency.get("p99"),
        },
        "errors": errors,
        "error_rate": round(errors / total, 6) if total else 0.0,
        "status_codes": status_codes,
        "error_distribution": payload.get("errorDistribution") or {},
        "success_rate": payload.get("metrics", {}).get("success_rate"),
        "bytes_total": payload.get("summary", {}).get("totalData"),
    }
    return result, cmd, proc.stderr


class PythonHttpLoad:
    def __init__(
        self,
        *,
        port: int,
        scheme: str,
        host: Optional[str],
        path: str,
        concurrency: int,
        duration: float,
        method: str = "GET",
        body: Optional[bytes] = None,
        chunked: bool = False,
        rotate_hosts: Optional[List[str]] = None,
        rotate_paths: Optional[List[str]] = None,
    ) -> None:
        self.port = port
        self.scheme = scheme
        self.host = host
        self.path = path
        self.concurrency = max(1, concurrency)
        self.duration = duration
        self.method = method
        self.body = body
        self.chunked = chunked
        self.rotate_hosts = rotate_hosts or ([host] if host else ["127.0.0.1"])
        self.rotate_paths = rotate_paths or [path]
        self._stop = time.monotonic() + duration
        self._lock = threading.Lock()
        self.latencies: List[float] = []
        self.status_codes: collections.Counter = collections.Counter()
        self.errors = 0
        self.bytes_sent = 0
        self._counter = 0

    def _next(self) -> Tuple[str, str]:
        with self._lock:
            host = self.rotate_hosts[self._counter % len(self.rotate_hosts)]
            path = self.rotate_paths[self._counter % len(self.rotate_paths)]
            self._counter += 1
            return host, path

    def _connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            context = ssl._create_unverified_context()
            return http.client.HTTPSConnection("127.0.0.1", self.port, timeout=15, context=context)
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)

    def _request(self, conn: http.client.HTTPConnection, host: str, path: str) -> None:
        start = time.perf_counter()
        conn.putrequest(self.method, path, skip_host=True)
        conn.putheader("Host", host)
        conn.putheader("User-Agent", BENCH_UA)
        conn.putheader("Connection", "keep-alive")
        if self.chunked:
            conn.putheader("Transfer-Encoding", "chunked")
            conn.putheader("Content-Type", "application/octet-stream")
            conn.endheaders()
            payload = self.body or b""
            for offset in range(0, len(payload), CHUNKED_CHUNK):
                chunk = payload[offset : offset + CHUNKED_CHUNK]
                conn.send(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
                with self._lock:
                    self.bytes_sent += len(chunk)
            conn.send(b"0\r\n\r\n")
        else:
            payload = self.body or b""
            if payload:
                conn.putheader("Content-Length", str(len(payload)))
            conn.endheaders()
            if payload:
                conn.send(payload)
                with self._lock:
                    self.bytes_sent += len(payload)
        response = conn.getresponse()
        body = response.read()
        elapsed = time.perf_counter() - start
        with self._lock:
            self.latencies.append(elapsed)
            self.status_codes[str(response.status)] += 1
            self.bytes_sent += len(body)

    def _worker(self) -> None:
        conn = self._connection()
        try:
            while time.monotonic() < self._stop:
                host, path = self._next()
                try:
                    self._request(conn, host, path)
                    if conn.sock is None:
                        conn = self._connection()
                except Exception:  # noqa: BLE001 - load client records failures
                    with self._lock:
                        self.errors += 1
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                    conn = self._connection()
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def run(self) -> Dict[str, Any]:
        threads = [
            threading.Thread(target=self._worker, daemon=True) for _ in range(self.concurrency)
        ]
        started = time.perf_counter()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        elapsed = max(time.perf_counter() - started, 1e-9)
        total = sum(self.status_codes.values()) + self.errors
        return {
            "requests": total,
            "requests_per_sec": round(total / elapsed, 3),
            "latency_ms": latency_summary(self.latencies),
            "errors": self.errors,
            "error_rate": round(self.errors / total, 6) if total else 0.0,
            "status_codes": dict(self.status_codes),
            "bytes_total": self.bytes_sent,
        }


def h2load_load(
    url: str,
    *,
    requests: int,
    concurrency: int,
    host: Optional[str],
) -> Tuple[Dict[str, Any], List[str], str]:
    h2load = shutil.which("h2load")
    if not h2load:
        raise RuntimeError("h2load not found")
    cmd = [h2load, "-n", str(requests), "-c", str(concurrency), "-t", "2"]
    cmd += ["-H", f"user-agent: {BENCH_UA}"]
    if host:
        cmd += ["-H", f"host: {host}"]
    cmd.append(url)
    CLIENT_COMMANDS.append(list(cmd))
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"h2load exited {proc.returncode}: {proc.stderr.strip()[-500:]}")
    text = proc.stdout + "\n" + proc.stderr
    rps = 0.0
    match = re.search(r"([0-9.]+)\s+req/s", text)
    if match:
        rps = float(match.group(1))
    total = 0
    succeeded = 0
    failed = 0
    status_codes: Dict[str, int] = {}
    match = re.search(r"requests:\s+(\d+)\s+total", text)
    if match:
        total = int(match.group(1))
    match = re.search(r"(\d+)\s+succeeded", text)
    if match:
        succeeded = int(match.group(1))
    match = re.search(r"(\d+)\s+failed", text)
    if match:
        failed = int(match.group(1))
    for count, bucket in re.findall(r"(\d+)\s+([1-5]xx)", text):
        status_codes[bucket] = int(count)
    errors = max(failed, total - succeeded) if total else failed
    return (
        {
            "requests": total,
            "requests_per_sec": round(rps, 3),
            "latency_ms": {"p50": None, "p95": None, "p99": None},
            "errors": errors,
            "error_rate": round(errors / total, 6) if total else 0.0,
            "status_codes": status_codes,
            "bytes_total": None,
        },
        cmd,
        text[-500:],
    )


def tcp_load(port: int, duration: float, concurrency: int, payload: bytes) -> Dict[str, Any]:
    stop = time.monotonic() + duration
    latencies: List[float] = []
    lock = threading.Lock()
    sent = received = flows = errors = 0

    def worker() -> None:
        nonlocal sent, received, flows, errors
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:
            with lock:
                errors += 1
            return
        with lock:
            flows += 1
        try:
            while time.monotonic() < stop:
                start = time.perf_counter()
                try:
                    sock.sendall(payload)
                    data = b""
                    while len(data) < len(payload):
                        chunk = sock.recv(len(payload) - len(data))
                        if not chunk:
                            raise ConnectionError("peer closed")
                        data += chunk
                    elapsed = time.perf_counter() - start
                    with lock:
                        sent += 1
                        received += 1
                        latencies.append(elapsed)
                except OSError:
                    with lock:
                        errors += 1
                    break
        finally:
            sock.close()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, concurrency))]
    start = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = max(time.perf_counter() - start, 1e-9)
    return {
        "packets_sent": sent,
        "packets_received": received,
        "bytes_sent": sent * len(payload),
        "bytes_received": received * len(payload),
        "flows": flows,
        "errors": errors,
        "packets_per_sec": round(sent / elapsed, 3),
        "bytes_per_sec": round(sent * len(payload) / elapsed, 3),
        "latency_ms": latency_summary(latencies),
    }


def udp_load(port: int, duration: float, concurrency: int, payload: bytes) -> Dict[str, Any]:
    stop = time.monotonic() + duration
    latencies: List[float] = []
    lock = threading.Lock()
    sent = received = errors = 0

    def worker() -> None:
        nonlocal sent, received, errors
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            while time.monotonic() < stop:
                start = time.perf_counter()
                try:
                    sock.sendto(payload, ("127.0.0.1", port))
                    data, _peer = sock.recvfrom(65536)
                    elapsed = time.perf_counter() - start
                    if data != payload:
                        raise ValueError("echo payload mismatch")
                    with lock:
                        sent += 1
                        received += 1
                        latencies.append(elapsed)
                except socket.timeout:
                    with lock:
                        sent += 1
                        errors += 1
                except OSError:
                    with lock:
                        sent += 1
                        errors += 1
                    break
        finally:
            sock.close()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, concurrency))]
    start = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = max(time.perf_counter() - start, 1e-9)
    return {
        "packets_sent": sent,
        "packets_received": received,
        "bytes_sent": sent * len(payload),
        "bytes_received": received * len(payload),
        "flows": concurrency,
        "lost": max(0, sent - received),
        "errors": errors,
        "packets_per_sec": round(sent / elapsed, 3),
        "bytes_per_sec": round(sent * len(payload) / elapsed, 3),
        "latency_ms": latency_summary(latencies),
    }


# ---------------------------------------------------------------------------
# config generation and server lifecycle
# ---------------------------------------------------------------------------


def render_template(template: pathlib.Path, replacements: Dict[str, str]) -> str:
    text = template.read_text()
    for key, value in replacements.items():
        text = text.replace(key, value)
    leftovers = sorted(set(re.findall(r"@@[A-Z0-9_]+@@", text)))
    if leftovers:
        raise RuntimeError(f"unsubstituted placeholders in {template}: {leftovers}")
    return text


def domain_for(index: int) -> str:
    return f"bench-{index:04d}.local"


def write_config(
    work: pathlib.Path,
    *,
    ports: Dict[str, Any],
    worker_threads: int,
    workers: int,
    allow_multi_worker: bool,
    site_count: int,
    waf_profile: str,
    tls_enabled: bool,
    extra_listen: bool,
) -> Dict[str, Any]:
    config_dir = work / "config"
    sites_dir = config_dir / "sites"
    sites_dir.mkdir(parents=True, exist_ok=True)
    for stale in sites_dir.glob("*.toml"):
        stale.unlink()
    data_dir = work / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    tls_section = (
        "[tls]\n"
        "enabled = true\n"
        f'cert_path = "{work.parent / "certs" / "bench-cert.pem"}"\n'
        f'key_path = "{work.parent / "certs" / "bench-key.pem"}"\n'
        f"port = {ports['tls']}\n"
        "tls_1_3_only = true\n"
        if tls_enabled
        else "[tls]\nenabled = false\n"
    )
    http3_section = (
        f"[http3]\nenabled = true\nport = {ports['h3']}\n"
        if tls_enabled
        else "[http3]\nenabled = false\n"
    )
    listener_section = ""
    if extra_listen:
        lines = [
            "",
            "[[http.listeners]]",
            'name = "bench-public"',
            'address = "127.0.0.1"',
            f"port = {ports['http']}",
            "",
        ]
        for index, port in enumerate(ports["extra"]):
            lines.extend([
                "[[http.listeners]]",
                f'name = "bench-extra-{index}"',
                'address = "127.0.0.1"',
                f"port = {port}",
                "",
            ])
        listener_section = "\n".join(lines)
    main_text = render_template(
        HERE / "config" / "templates" / "main.toml.tpl",
        {
            "@@HTTP_PORT@@": str(ports["http"]),
            "@@ADMIN_PORT@@": str(ports["admin"]),
            "@@METRICS_PORT@@": str(ports["metrics"]),
            "@@WORKER_THREADS@@": str(worker_threads),
            "@@WORKERS@@": str(workers),
            "@@ALLOW_MULTI_WORKER@@": "true" if allow_multi_worker else "false",
            "@@DATA_DIR@@": str(data_dir),
            "@@TLS_SECTION@@": tls_section,
            "@@HTTP3_SECTION@@": http3_section,
            "@@HTTP_LISTENER_SECTION@@": listener_section,
            "@@TCP_ENABLED@@": "true",
            "@@TCP_SINGLE_PORT@@": str(ports["tcp_single"]),
            "@@TCP_MULTI_PORTS@@": ", ".join(str(p) for p in ports["tcp_multi"]),
            "@@TCP_UPSTREAM_PORT@@": str(ports["tcp_upstream"]),
            "@@UDP_ENABLED@@": "true",
            "@@UDP_SINGLE_PORT@@": str(ports["udp_single"]),
            "@@UDP_MULTI_PORTS@@": ", ".join(str(p) for p in ports["udp_multi"]),
            "@@UDP_UPSTREAM_PORT@@": str(ports["udp_upstream"]),
        },
    )
    (config_dir / "main.toml").write_text(main_text)

    attack_enabled = waf_profile != "off"
    attack_action = "block" if waf_profile == "block" else "log"
    site_template = (HERE / "config" / "templates" / "site.toml.tpl").read_text()
    domains: List[str] = []
    for index in range(site_count):
        domain = domain_for(index)
        text = site_template
        replacements = {
            "@@SITE_COUNT@@": str(site_count),
            "@@DOMAIN@@": domain,
            "@@DYNAMIC_UPSTREAM_PORT@@": str(ports["dynamic_upstream"]),
            "@@STATIC_UPSTREAM_PORT@@": str(ports["static_upstream"]),
            "@@ATTACK_ENABLED@@": "true" if attack_enabled else "false",
            "@@ATTACK_ACTION@@": attack_action,
            "@@PARANOIA_LEVEL@@": "2",
        }
        for key, value in replacements.items():
            text = text.replace(key, value)
        (sites_dir / f"site-{index:05d}-{domain}.toml").write_text(text)
        domains.append(domain)
    return {"config_dir": config_dir, "domains": domains, "tls_enabled": tls_enabled}


def generate_cert(work: pathlib.Path) -> bool:
    openssl = shutil.which("openssl")
    if not openssl:
        return False
    cert_dir = work / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert = cert_dir / "bench-cert.pem"
    key = cert_dir / "bench-key.pem"
    cmd = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-days",
        "1",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    code, _out = run_capture(cmd, timeout=30)
    return code == 0 and cert.exists() and key.exists()


class ServerHandle:
    def __init__(
        self,
        *,
        popen: subprocess.Popen,
        work: pathlib.Path,
        ports: Dict[str, Any],
        domains: List[str],
        config: Dict[str, Any],
        log_path: pathlib.Path,
        admin_token: str,
        cleanup_dirs: List[pathlib.Path],
    ) -> None:
        self.popen = popen
        self.work = work
        self.ports = ports
        self.domains = domains
        self.config = config
        self.log_path = log_path
        self.admin_token = admin_token
        self.cleanup_dirs = cleanup_dirs
        self.pgid = popen.pid

    def cleanup(self) -> None:
        for directory in self.cleanup_dirs:
            shutil.rmtree(directory, ignore_errors=True)

    def log_tail(self, lines: int = 40) -> str:
        try:
            text = self.log_path.read_text(errors="replace").splitlines()
            return "\n".join(text[-lines:])
        except OSError:
            return ""


def start_upstreams(
    work: pathlib.Path, ports: Dict[str, Any], commands: List[List[str]]
) -> List[subprocess.Popen]:
    logs = work / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    processes: List[subprocess.Popen] = []
    specs = [
        (
            "http-dynamic",
            [
                sys.executable,
                str(HERE / "upstreams" / "http_upstream.py"),
                "--port",
                str(ports["dynamic_upstream"]),
            ],
        ),
        (
            "http-static",
            [
                sys.executable,
                str(HERE / "upstreams" / "http_upstream.py"),
                "--port",
                str(ports["static_upstream"]),
            ],
        ),
        (
            "tcp-echo",
            [
                sys.executable,
                str(HERE / "upstreams" / "echo.py"),
                "--mode",
                "tcp",
                "--port",
                str(ports["tcp_upstream"]),
            ],
        ),
        (
            "udp-echo",
            [
                sys.executable,
                str(HERE / "upstreams" / "echo.py"),
                "--mode",
                "udp",
                "--port",
                str(ports["udp_upstream"]),
            ],
        ),
    ]
    for name, cmd in specs:
        log = (logs / f"{name}.log").open("w")
        proc = subprocess.Popen(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=str(work),
            start_new_session=True,
        )
        processes.append(proc)
        commands.append(cmd)
    deadline = time.monotonic() + 10
    for port in (ports["dynamic_upstream"], ports["static_upstream"]):
        while time.monotonic() < deadline and not port_open(port):
            time.sleep(0.1)
        if not port_open(port):
            raise RuntimeError(f"upstream on 127.0.0.1:{port} did not start")
    return processes


def stop_process(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def start_synvoid(
    *,
    binary: pathlib.Path,
    work: pathlib.Path,
    config: Dict[str, Any],
    ports: Dict[str, Any],
    commands: List[List[str]],
) -> ServerHandle:
    logs = work / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / "synvoid.log"
    admin_token = secrets.token_hex(32)
    ipc_key = secrets.token_hex(32)
    # Unix-domain socket paths are limited to ~108 bytes. Keep the isolated
    # XDG roots short even when the working directory is deep, otherwise bind
    # fails before the supervisor can log anything.
    xdg_data = pathlib.Path(tempfile.mkdtemp(prefix="svms-data-", dir="/tmp"))
    xdg_runtime = pathlib.Path(tempfile.mkdtemp(prefix="svms-run-", dir="/tmp"))
    env = os.environ.copy()
    env["XDG_DATA_HOME"] = str(xdg_data)
    env["XDG_RUNTIME_DIR"] = str(xdg_runtime)
    env["SYNVOID_ADMIN_TOKEN"] = admin_token
    env["SYNVOID_IPC_KEY"] = ipc_key
    cmd = [str(binary), "--config-path", str(config["config_dir"]), "--foreground"]
    commands.append(cmd)
    log = log_path.open("w")
    popen = subprocess.Popen(
        cmd,
        stdout=log,
        stderr=subprocess.STDOUT,
        cwd=str(work),
        env=env,
        start_new_session=True,
    )
    handle = ServerHandle(
        popen=popen,
        work=work,
        ports=ports,
        domains=config["domains"],
        config=config,
        log_path=log_path,
        admin_token=admin_token,
        cleanup_dirs=[xdg_data, xdg_runtime],
    )
    try:
        wait_http_ready(ports["http"], config["domains"][0], timeout=45)
    except Exception:
        handle.log_tail()
        stop_process(popen)
        handle.cleanup()
        raise
    return handle


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------


class ResultWriter:
    def __init__(self, results_dir: pathlib.Path, metadata: Dict[str, Any]) -> None:
        self.results_dir = results_dir
        self.metadata = metadata
        self.results: List[Dict[str, Any]] = []

    def _path(self, stem: str) -> pathlib.Path:
        candidate = self.results_dir / f"{stem}.json"
        suffix = 1
        while candidate.exists():
            candidate = self.results_dir / f"{stem}-{suffix:02d}.json"
            suffix += 1
        return candidate

    def write(
        self,
        *,
        workload: str,
        process_profile: str,
        process_meta: Dict[str, Any],
        supported: bool,
        result: Dict[str, Any],
        unsupported_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        stamp = self.metadata["run_id"]
        stem = f"{stamp}-{process_profile}-{workload}"
        result = dict(result)
        if isinstance(result.get("command"), list) and len(result["command"]) > 40:
            result["command_truncated"] = True
            result["command"] = result["command"][:20] + ["..."] + result["command"][-5:]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": stamp,
            "generated_at": iso_now(),
            "workload": workload,
            "supported": supported,
            "unsupported_reason": unsupported_reason,
            "subject": self.metadata["subject"],
            "toolchain": self.metadata["toolchain"],
            "host": self.metadata["host"],
            "topology": self.metadata["topology"],
            "process_profile": process_meta,
            "build_profile": self.metadata["subject"]["build_profile"],
            **result,
        }
        path = self._path(stem)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        self.results.append(payload)
        return payload


# ---------------------------------------------------------------------------
# workload execution
# ---------------------------------------------------------------------------


def common_process_meta(
    name: str, workers: int, worker_threads: int, waf_profile: str
) -> Dict[str, Any]:
    return {
        "name": name,
        "worker_processes": workers,
        "worker_threads": worker_threads,
        "waf_profile": waf_profile,
    }


def http_result(
    *,
    server: ServerHandle,
    url: str,
    host: str,
    concurrency: int,
    duration: float,
    result: Dict[str, Any],
    command: List[str],
    method: str = "GET",
) -> Dict[str, Any]:
    return {
        "command": command,
        "http": {
            "url": url,
            "method": method,
            "host_header": host,
            "concurrency": concurrency,
            "duration_secs": duration,
        },
        "metrics": result,
    }


def choose_client(name: str, requested: str) -> str:
    """Pick the load client for a workload.

    ``oha`` is preferred where its output and connection model are stable in
    this harness. The Python client is used for the keep-alive/mixed/soak
    lanes, where oha's fixed-duration connection teardown produces client-side
    resets that would be reported as a subject error rather than a client
    artifact. Explicit ``--tool oha|python`` always wins.
    """
    if requested != "auto":
        return requested
    python_workloads = {
        "h1-keepalive",
        "h1-concurrent",
        "mixed-static-proxy",
        "waf-small",
        "chunked-upload",
        "soak",
        "multi-listener",
    }
    if name in python_workloads:
        return "python"
    return "oha" if shutil.which("oha") else "python"


def result_is_usable(result: Dict[str, Any]) -> Tuple[bool, str]:
    metrics = result.get("metrics") or {}
    total = metrics.get("requests") or 0
    rate = metrics.get("error_rate") or 0.0
    if total == 0:
        return False, "workload produced zero requests"
    if rate >= 0.99:
        distribution = metrics.get("error_distribution") or {}
        statuses = metrics.get("status_codes") or {}
        return (
            False,
            f"all or nearly all requests failed (error rate {rate:.4f}; "
            f"errors={distribution or 'n/a'}; statuses={statuses or 'n/a'})",
        )
    return True, ""


def run_http_workload(
    *,
    name: str,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
    duration: float,
    concurrency: int,
    tool: str,
    waf_profile: str,
    commands: List[List[str]],
) -> None:
    tool = choose_client(name, tool)
    host = server.domains[0]
    url = f"http://127.0.0.1:{server.ports['http']}/"
    method = "GET"
    body: Optional[bytes] = None
    urls_file: Optional[pathlib.Path] = None
    connect_to: Optional[List[str]] = None

    if name.startswith("vhost-"):
        count = int(name.split("-", 1)[1])
        hosts = server.domains[:count]
        url_file = server.work / f"{name}-urls.txt"
        url_file.write_text("".join(f"http://{h}/\n" for h in hosts))
        urls_file = url_file
        connect_to = [f"{h}:80:127.0.0.1:{server.ports['http']}" for h in hosts]
        host = hosts[0]
    elif name == "mixed-static-proxy":
        url_file = server.work / "mixed-static-proxy-urls.txt"
        lines = []
        for _ in range(50):
            lines.append(f"http://{host}/\n")
            lines.append(f"http://{host}/static/asset.bin\n")
        url_file.write_text("".join(lines))
        urls_file = url_file
        connect_to = [f"{host}:80:127.0.0.1:{server.ports['http']}"]
    elif name == "waf-small":
        url = f"http://127.0.0.1:{server.ports['http']}/products?q=wireless+keyboard&page=2"
        concurrency = max(concurrency, 32)
    elif name == "waf-body":
        method = "POST"
        payload = b"field=" + (b"A" * SIZE_BODY) + b"&id=1"
        if waf_profile == "block":
            payload += b"%27%20OR%20%271%27%3D%271"
        body_path = server.work / "waf-body.bin"
        body_path.write_bytes(payload)
        url = f"http://127.0.0.1:{server.ports['http']}/submit"
        concurrency = max(16, concurrency // 2)
        body = payload

    if name in {"h1-keepalive", "h1-concurrent"}:
        concurrency = 1 if name == "h1-keepalive" else max(concurrency, 64)
        url_file = server.work / f"{name}-urls.txt"
        url_file.write_text(f"http://{host}/\n")
        urls_file = url_file
        connect_to = [f"{host}:80:127.0.0.1:{server.ports['http']}"]

    sampler = ProcessSampler(server.pgid)
    metrics_before = scrape_prometheus(server.ports["metrics"])
    sampler.start()
    try:
        result: Dict[str, Any]
        command: List[str] = []
        if tool == "oha":
            try:
                result, command, stderr = oha_load(
                    url,
                    duration=duration,
                    concurrency=concurrency,
                    host=None if urls_file is not None else host,
                    method=method,
                    body_file=server.work / "waf-body.bin" if name == "waf-body" else None,
                    urls_file=urls_file,
                    connect_to=connect_to,
                )
                if stderr.strip():
                    result["diagnostics"] = stderr.strip()[-1000:]
            except Exception as exc:  # noqa: BLE001 - fall back with a recorded reason
                result = {
                    "requests": 0,
                    "requests_per_sec": 0.0,
                    "latency_ms": {"p50": None, "p95": None, "p99": None},
                    "errors": 0,
                    "error_rate": 0.0,
                    "status_codes": {},
                    "diagnostics": f"oha failed, fell back to python: {exc}",
                }
                tool = "python"
        if tool == "python" or result.get("requests") == 0:
            load = PythonHttpLoad(
                port=server.ports["http"],
                scheme="http",
                host=host,
                path="/"
                if not name.startswith("waf")
                else ("/products?q=wireless+keyboard" if name == "waf-small" else "/submit"),
                concurrency=concurrency,
                duration=duration,
                method=method,
                body=body,
                rotate_hosts=server.domains[: int(name.split("-", 1)[1])]
                if name.startswith("vhost-")
                else None,
            )
            result = load.run()
            command = [sys.executable, "benchmarks/multi_service/driver.py", "python-http-client"]
        sampler.stop()
        metrics_after = scrape_prometheus(server.ports["metrics"])
        admin_stats = scrape_admin(server.ports["admin"], server.admin_token)
        system = sampler.summary()
        payload = http_result(
            server=server,
            url=url if not urls_file else f"<urls-file:{urls_file.name}>",
            host=host,
            concurrency=concurrency,
            duration=duration,
            result=result,
            command=command,
            method=method,
        )
        payload["system"] = system
        payload["synvoid_metrics"] = {
            "before": metrics_before,
            "after": metrics_after,
        }
        payload["admin_stats"] = admin_stats
        payload["client"] = {"tool": "oha" if command and command[0].endswith("oha") else "python"}
        ok, reason = result_is_usable(payload)
        writer.write(
            workload=name,
            process_profile=process_profile,
            process_meta=process_meta,
            supported=ok,
            result=payload,
            unsupported_reason=None if ok else reason,
        )
    finally:
        sampler.stop()


def alpn_protocol(port: int, server_hostname: str = "localhost") -> Optional[str]:
    context = ssl._create_unverified_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                return tls.selected_alpn_protocol()
    except Exception:  # noqa: BLE001 - unsupported is a valid benchmark outcome
        return None


def run_tls_h2(
    *,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
    duration: float,
    concurrency: int,
    commands: List[List[str]],
) -> None:
    if not server.config.get("tls_enabled"):
        writer.write(
            workload="tls-h2",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason="TLS disabled: openssl unavailable or certificate generation failed",
        )
        return
    url = f"https://127.0.0.1:{server.ports['tls']}/"
    host = server.domains[0]
    negotiated = alpn_protocol(server.ports["tls"])
    if negotiated != "h2":
        writer.write(
            workload="tls-h2",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason=(
                f"TLS endpoint did not negotiate ALPN h2 (selected {negotiated!r}); "
                "the inbound HTTP/2 path is not available for this build/config"
            ),
        )
        return
    oha = shutil.which("oha")
    sampler = ProcessSampler(server.pgid)
    metrics_before = scrape_prometheus(server.ports["metrics"])
    sampler.start()
    h2load_error = "h2load not found"
    try:
        h2load = shutil.which("h2load")
        if h2load:
            try:
                requests = max(200, int(duration * 500))
                result, command, diagnostics = h2load_load(
                    url,
                    requests=requests,
                    concurrency=max(concurrency, 16),
                    host=host,
                )
                payload = http_result(
                    server=server,
                    url=url,
                    host=host,
                    concurrency=max(concurrency, 16),
                    duration=duration,
                    result=result,
                    command=command,
                )
                payload["system"] = sampler.summary()
                payload["synvoid_metrics"] = {
                    "before": metrics_before,
                    "after": scrape_prometheus(server.ports["metrics"]),
                }
                payload["admin_stats"] = scrape_admin(server.ports["admin"], server.admin_token)
                payload["client"] = {"tool": "h2load", "diagnostics": diagnostics}
                writer.write(
                    workload="tls-h2",
                    process_profile=process_profile,
                    process_meta=process_meta,
                    supported=True,
                    result=payload,
                )
                return
            except Exception as exc:  # noqa: BLE001 - try oha next
                h2load_error = str(exc)
        if oha:
            try:
                result, command, stderr = oha_load(
                    url,
                    duration=duration,
                    concurrency=max(concurrency, 32),
                    host=host,
                    http_version="2",
                    insecure=True,
                )
                if stderr.strip():
                    result["diagnostics"] = stderr.strip()[-1000:]
                payload = http_result(
                    server=server,
                    url=url,
                    host=host,
                    concurrency=max(concurrency, 32),
                    duration=duration,
                    result=result,
                    command=command,
                )
                payload["system"] = sampler.summary()
                payload["synvoid_metrics"] = {
                    "before": metrics_before,
                    "after": scrape_prometheus(server.ports["metrics"]),
                }
                payload["admin_stats"] = scrape_admin(server.ports["admin"], server.admin_token)
                payload["client"] = {"tool": "oha", "http_version": "2"}
                writer.write(
                    workload="tls-h2",
                    process_profile=process_profile,
                    process_meta=process_meta,
                    supported=True,
                    result=payload,
                )
                return
            except Exception as exc:  # noqa: BLE001 - fall through to h2load / unsupported
                oha_error = str(exc)
        else:
            oha_error = "oha not found"
        writer.write(
            workload="tls-h2",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason=f"no working HTTP/2 client (h2load: {h2load_error}; oha: {oha_error})",
        )
    finally:
        sampler.stop()


def run_h3(
    *,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
    duration: float,
    concurrency: int,
) -> None:
    if not server.config.get("tls_enabled"):
        writer.write(
            workload="h3",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason="TLS disabled: openssl unavailable or certificate generation failed",
        )
        return
    oha = shutil.which("oha")
    if not oha:
        writer.write(
            workload="h3",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason="oha not found; no HTTP/3 load client is available",
        )
        return
    url = f"https://127.0.0.1:{server.ports['h3']}/"
    host = server.domains[0]
    sampler = ProcessSampler(server.pgid)
    sampler.start()
    try:
        try:
            result, command, stderr = oha_load(
                url,
                duration=duration,
                concurrency=max(4, min(concurrency, 32)),
                host=host,
                http_version="3",
                insecure=True,
            )
            if stderr.strip():
                result["diagnostics"] = stderr.strip()[-1000:]
            payload = http_result(
                server=server,
                url=url,
                host=host,
                concurrency=max(4, min(concurrency, 32)),
                duration=duration,
                result=result,
                command=command,
            )
            payload["system"] = sampler.summary()
            payload["synvoid_metrics"] = {
                "before": scrape_prometheus(server.ports["metrics"]),
                "after": scrape_prometheus(server.ports["metrics"]),
            }
            payload["admin_stats"] = scrape_admin(server.ports["admin"], server.admin_token)
            payload["client"] = {"tool": "oha", "http_version": "3"}
            writer.write(
                workload="h3",
                process_profile=process_profile,
                process_meta=process_meta,
                supported=True,
                result=payload,
            )
        except Exception as exc:  # noqa: BLE001 - unsupported is a valid outcome
            writer.write(
                workload="h3",
                process_profile=process_profile,
                process_meta=process_meta,
                supported=False,
                result={"command": [], "http": None, "metrics": None},
                unsupported_reason=f"HTTP/3 client or listener unavailable: {exc}",
            )
    finally:
        sampler.stop()


def chunked_probe(port: int, host: str, body: bytes) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.putrequest("POST", "/upload", skip_host=True)
        conn.putheader("Host", host)
        conn.putheader("User-Agent", BENCH_UA)
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Content-Type", "application/octet-stream")
        conn.endheaders()
        for offset in range(0, len(body), CHUNKED_CHUNK):
            chunk = body[offset : offset + CHUNKED_CHUNK]
            conn.send(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
        conn.send(b"0\r\n\r\n")
        response = conn.getresponse()
        response.read()
        return int(response.status)
    finally:
        conn.close()


def run_chunked_upload(
    *,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
    duration: float,
    concurrency: int,
) -> None:
    payload = secrets.token_bytes(CHUNKED_CHUNK * 2)
    try:
        probe_status = chunked_probe(server.ports["http"], server.domains[0], payload[:4096])
    except Exception as exc:  # noqa: BLE001 - probe failure becomes an unsupported record
        writer.write(
            workload="chunked-upload",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason=f"chunked probe failed: {type(exc).__name__}: {exc}",
        )
        return
    if probe_status not in (200, 201, 202, 204):
        writer.write(
            workload="chunked-upload",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "http": None, "metrics": None},
            unsupported_reason=(
                f"chunked request body returned HTTP {probe_status}; "
                "the current request path does not accept this workload"
            ),
        )
        return
    sampler = ProcessSampler(server.pgid)
    metrics_before = scrape_prometheus(server.ports["metrics"])
    sampler.start()
    try:
        load = PythonHttpLoad(
            port=server.ports["http"],
            scheme="http",
            host=server.domains[0],
            path="/upload",
            concurrency=max(4, concurrency // 2),
            duration=duration,
            method="POST",
            body=payload,
            chunked=True,
        )
        result = load.run()
        sampler.stop()
        payload_result = http_result(
            server=server,
            url=f"http://127.0.0.1:{server.ports['http']}/upload",
            host=server.domains[0],
            concurrency=max(4, concurrency // 2),
            duration=duration,
            result=result,
            command=[sys.executable, "benchmarks/multi_service/driver.py", "python-chunked-client"],
            method="POST",
        )
        payload_result["system"] = sampler.summary()
        payload_result["synvoid_metrics"] = {
            "before": metrics_before,
            "after": scrape_prometheus(server.ports["metrics"]),
        }
        payload_result["admin_stats"] = scrape_admin(server.ports["admin"], server.admin_token)
        payload_result["client"] = {
            "tool": "python",
            "transfer_encoding": "chunked",
            "body_bytes": len(payload),
        }
        writer.write(
            workload="chunked-upload",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=True,
            result=payload_result,
        )
    finally:
        sampler.stop()


def run_tcp_udp(
    *,
    name: str,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
    duration: float,
    concurrency: int,
) -> None:
    is_tcp = name.startswith("tcp-")
    is_multi = name.endswith("multi-port")
    ports_to_probe = (
        list(server.ports["tcp_multi"]) if is_multi else [server.ports["tcp_single"]]
    )
    kind = "tcp"
    if not is_tcp:
        ports_to_probe = (
            list(server.ports["udp_multi"]) if is_multi else [server.ports["udp_single"]]
        )
        kind = "udp"
    probe_results = {}
    for candidate in ports_to_probe:
        if is_tcp:
            probe_results[candidate] = port_open(candidate)
        else:
            probe_ok = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                sock.sendto(b"probe", ("127.0.0.1", candidate))
                sock.recvfrom(64)
                probe_ok = True
                sock.close()
            except OSError:
                probe_ok = False
            probe_results[candidate] = probe_ok
    missing = [candidate for candidate, ok in probe_results.items() if not ok]
    if missing:
        writer.write(
            workload=name,
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "tcp_udp": None},
            unsupported_reason=(
                f"{kind.upper()} listeners did not accept traffic on ports {missing}; "
                "every configured protocol port must be bound by the listener pool"
            ),
        )
        return
    sampler = ProcessSampler(server.pgid)
    sampler.start()
    try:
        per_port = {}
        for candidate in ports_to_probe:
            if is_tcp:
                per_port[str(candidate)] = tcp_load(
                    candidate, duration, max(1, concurrency // 2), b"x" * 64
                )
            else:
                per_port[str(candidate)] = udp_load(
                    candidate, duration, max(1, concurrency // 2), b"x" * 64
                )
        sampler.stop()
        writer.write(
            workload=name,
            process_profile=process_profile,
            process_meta=process_meta,
            supported=True,
            result={
                "command": [
                    sys.executable,
                    "benchmarks/multi_service/driver.py",
                    f"python-{kind}-client",
                ],
                "tcp_udp": per_port[str(ports_to_probe[0])],
                "tcp_udp_per_port": per_port,
                "tcp_udp_ports": {
                    str(candidate): True for candidate in ports_to_probe
                },
                "system": sampler.summary(),
            },
        )
    finally:
        sampler.stop()


def run_multi_listener(
    *,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
) -> None:
    ports_to_probe = [server.ports["http"], *server.ports["extra"]]
    missing = [port for port in ports_to_probe if not port_open(port)]
    if missing:
        writer.write(
            workload="multi-listener",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=False,
            result={"command": [], "listeners": []},
            unsupported_reason=(
                f"planned HTTP listener ports were not bound: {missing}; "
                "the canonical [[http.listeners]] plan must bind every entry"
            ),
        )
        return
    sampler = ProcessSampler(server.pgid)
    metrics_before = scrape_prometheus(server.ports["metrics"])
    sampler.start()
    try:
        listeners = []
        for port in ports_to_probe:
            load = PythonHttpLoad(
                port=port,
                scheme="http",
                host=server.domains[0],
                path="/",
                concurrency=1,
                duration=5.0,
            )
            result = load.run()
            payload = http_result(
                server=server,
                url=f"http://127.0.0.1:{port}/",
                host=server.domains[0],
                concurrency=1,
                duration=5.0,
                result=result,
                command=[
                    sys.executable,
                    "benchmarks/multi_service/driver.py",
                    "python-http-client",
                ],
            )
            listeners.append(
                {
                    "port": port,
                    "url": payload["http"]["url"],
                    "host_header": payload["http"]["host_header"],
                    **payload["metrics"],
                }
            )
        sampler.stop()
        writer.write(
            workload="multi-listener",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=True,
            result={
                "command": [
                    sys.executable,
                    "benchmarks/multi_service/driver.py",
                    "python-http-client",
                ],
                "listeners": listeners,
                "system": sampler.summary(),
                "synvoid_metrics": {
                    "before": metrics_before,
                    "after": scrape_prometheus(server.ports["metrics"]),
                },
                "admin_stats": scrape_admin(server.ports["admin"], server.admin_token),
                "client": {"tool": "python"},
            },
        )
    finally:
        sampler.stop()


def run_soak(
    *,
    server: ServerHandle,
    writer: ResultWriter,
    process_profile: str,
    process_meta: Dict[str, Any],
    soak_seconds: float,
    concurrency: int,
    tool: str,
) -> None:
    sampler = ProcessSampler(server.pgid, interval=5.0)
    metrics_before = scrape_prometheus(server.ports["metrics"])
    sampler.start()
    try:
        result: Dict[str, Any] = {}
        command: List[str] = []
        tool = choose_client("soak", tool)
        if tool == "oha" and shutil.which("oha"):
            try:
                result, command, stderr = oha_load(
                    f"http://127.0.0.1:{server.ports['http']}/",
                    duration=soak_seconds,
                    concurrency=max(32, concurrency),
                    host=server.domains[0],
                )
                if stderr.strip():
                    result["diagnostics"] = stderr.strip()[-1000:]
            except Exception as exc:  # noqa: BLE001 - fall back
                result = {
                    "requests": 0,
                    "requests_per_sec": 0.0,
                    "latency_ms": {"p50": None, "p95": None, "p99": None},
                    "errors": 0,
                    "error_rate": 0.0,
                    "status_codes": {},
                    "diagnostics": f"oha failed, fell back to python: {exc}",
                }
        if not result.get("requests"):
            load = PythonHttpLoad(
                port=server.ports["http"],
                scheme="http",
                host=server.domains[0],
                path="/",
                concurrency=max(32, concurrency),
                duration=soak_seconds,
            )
            result = load.run()
            command = [sys.executable, "benchmarks/multi_service/driver.py", "python-http-client"]
        sampler.stop()
        ok, reason = result_is_usable({"metrics": result})
        writer.write(
            workload="soak",
            process_profile=process_profile,
            process_meta=process_meta,
            supported=ok,
            unsupported_reason=None if ok else reason,
            result={
                "command": command,
                "http": {
                    "url": f"http://127.0.0.1:{server.ports['http']}/",
                    "method": "GET",
                    "host_header": server.domains[0],
                    "concurrency": max(32, concurrency),
                    "duration_secs": soak_seconds,
                },
                "metrics": result,
                "system": sampler.summary(),
                "synvoid_metrics": {
                    "before": metrics_before,
                    "after": scrape_prometheus(server.ports["metrics"]),
                },
                "admin_stats": scrape_admin(server.ports["admin"], server.admin_token),
                "client": {"tool": "oha" if command and command[0].endswith("oha") else "python"},
            },
        )
    finally:
        sampler.stop()


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


PROCESS_PROFILE_RE = re.compile(r"^threads-(\d+)$")


def process_profile_settings(name: str, threads: int) -> Tuple[int, int, bool]:
    cpu = max(1, os.cpu_count() or 1)
    if name == "default":
        return 1, cpu, False
    if name == "threads-1":
        return 1, 1, False
    match = PROCESS_PROFILE_RE.match(name)
    if match:
        return 1, max(1, int(match.group(1))), False
    if name == "workers-2":
        return 2, cpu, True
    raise SystemExit(f"unknown process profile {name!r}")


def workload_groups(workloads: Sequence[str]) -> Dict[Tuple[int, bool, str], List[str]]:
    groups: Dict[Tuple[int, bool, str], List[str]] = {}
    for workload in workloads:
        if workload == "vhost-1":
            key = (1, False, "main")
        elif workload == "vhost-100":
            key = (100, False, "main")
        elif workload == "multi-listener":
            key = (1, True, "main")
        elif workload in {"tcp-echo", "tcp-multi-port", "udp-echo", "udp-multi-port"}:
            key = (1, False, "main")
        elif workload == "soak":
            # Give the soak its own freshly started server. Earlier workloads
            # intentionally exercise failure paths; a steady-state drift
            # measurement must not inherit their connection/backlog state.
            key = (1000, False, "soak")
        else:
            key = (1000, False, "main")
        groups.setdefault(key, []).append(workload)
    return groups


def build_metadata(args: argparse.Namespace, binary: Optional[pathlib.Path]) -> Dict[str, Any]:
    revision = "unknown"
    code, out = run_capture(["git", "-C", str(REPO), "rev-parse", "HEAD"], timeout=5)
    if code == 0 and out:
        revision = out
    tools: Dict[str, Any] = {}
    for name in ("oha", "h2load", "wrk", "curl", "openssl"):
        path = shutil.which(name)
        tools[name] = {
            "path": path,
            "version": tool_version([path]) if path else None,
        }
    rustc = tool_version(["rustc"])
    cargo = tool_version(["cargo"])
    return {
        "run_id": f"{utc_stamp()}-{secrets.token_hex(3)}",
        "started_at": iso_now(),
        "subject": {
            "revision_sha": revision,
            "harness_sha": harness_sha(),
            "binary": str(binary) if binary else None,
            "binary_sha256": sha256_file(binary) if binary else None,
            "build_profile": args.build_profile,
        },
        "toolchain": {
            "rustc": rustc,
            "cargo": cargo,
            "python": platform.python_version(),
            "load_tool": "auto",
            "tools": tools,
        },
        "host": {
            "os": platform.system(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "cpu_model": cpu_model(),
            "cpu_count": os.cpu_count(),
            "memory_bytes": memory_bytes(),
        },
        "topology": {
            "kind": "loopback-same-host",
            "client_host": "127.0.0.1",
            "server_host": "127.0.0.1",
            "notes": "loopback hides the NIC and network RTT; never compare across hosts",
        },
    }


def resolve_binary(args: argparse.Namespace) -> pathlib.Path:
    if args.binary:
        path = pathlib.Path(args.binary).expanduser().resolve()
    else:
        path = (REPO / "target" / args.build_profile / "synvoid").resolve()
    if not path.exists():
        raise SystemExit(
            f"subject binary not found: {path}\n"
            f"build it first: cargo build --profile {args.build_profile} --bin synvoid"
        )
    if not os.access(path, os.X_OK):
        raise SystemExit(f"subject binary is not executable: {path}")
    return path


def write_run_files(
    *,
    out_dir: pathlib.Path,
    metadata: Dict[str, Any],
    results: List[Dict[str, Any]],
    commands: List[List[str]],
    args: argparse.Namespace,
    ports: Dict[str, Any],
) -> None:
    stem = metadata["run_id"]
    (out_dir / f"{stem}-RUN.md").write_text(render_run_markdown(metadata, args, ports, results))
    (out_dir / f"{stem}-commands.log").write_text(
        "\n".join(" ".join(str(part) for part in cmd) for cmd in (commands + CLIENT_COMMANDS))
        + "\n"
    )
    (out_dir / f"{stem}-summary.md").write_text(render_summary(metadata, results))
    (out_dir / f"{stem}-run.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "metadata": metadata,
                "args": vars(args),
                "ports": ports,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )


def render_run_markdown(
    metadata: Dict[str, Any],
    args: argparse.Namespace,
    ports: Dict[str, Any],
    results: List[Dict[str, Any]],
) -> str:
    subject = metadata["subject"]
    host = metadata["host"]
    toolchain = metadata["toolchain"]
    lines = [
        "# Multi-service benchmark run",
        "",
        f"- run id: `{metadata['run_id']}`",
        f"- started (UTC): {metadata['started_at']}",
        f"- revision SHA: `{subject['revision_sha']}`",
        f"- harness SHA: `{subject['harness_sha']}`",
        f"- binary: `{subject['binary']}`",
        f"- binary SHA-256: `{subject['binary_sha256']}`",
        f"- build profile: `{subject['build_profile']}`",
        f"- rustc: `{toolchain.get('rustc')}`",
        f"- cargo: `{toolchain.get('cargo')}`",
        f"- host: {host['os']} {host['kernel']} {host['arch']}, {host['cpu_model']}, {host['cpu_count']} CPUs",
        f"- topology: {metadata['topology']['kind']} (loopback, same host)",
        f"- process profiles: `{args.process_profiles}`",
        f"- waf profile: `{args.waf_profile}`",
        f"- workloads: `{','.join(args.workloads)}`",
        f"- duration per workload: {args.duration}s",
        f"- soak: {args.soak_seconds}s",
        f"- smoke: {args.smoke}",
        f"- results: {len(results)} workload result files",
        "",
        "## Loopback warning",
        "",
        "These numbers were measured over loopback on one host. They are not a",
        "production capacity claim and must not be compared with a different host,",
        "kernel, CPU, build profile or container runtime.",
        "",
        "## Ports",
        "",
        "```json",
        json.dumps(ports, indent=2, sort_keys=True),
        "```",
    ]
    return "\n".join(lines) + "\n"


def render_summary(metadata: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
    supported = [r for r in results if r.get("supported")]
    unsupported = [r for r in results if not r.get("supported")]
    lines = [
        "# Multi-service benchmark summary (generated)",
        "",
        f"- run: `{metadata['run_id']}`",
        f"- revision: `{metadata['subject']['revision_sha']}`",
        f"- harness: `{metadata['subject']['harness_sha']}`",
        f"- host: {metadata['host']['cpu_model']} ({metadata['host']['cpu_count']} CPUs)",
        f"- topology: {metadata['topology']['kind']}",
        "",
        "## Supported workloads",
        "",
        "| profile | workload | rps | p50 ms | p95 ms | p99 ms | errors | error rate | cpu % | RSS peak MiB | FD peak |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for result in supported:
        metrics = result.get("metrics") or {}
        latency = metrics.get("latency_ms") or {}
        tcp_udp = result.get("tcp_udp") or {}
        system = result.get("system") or {}
        if result.get("listeners"):
            for listener in result["listeners"]:
                listener_latency = listener.get("latency_ms") or {}
                lines.append(
                    "| {profile} | {workload}:{port} | {rps} | {p50} | {p95} | {p99} | {errors} | {rate} | {cpu} | {rss} | {fds} |".format(
                        profile=result.get("process_profile", {}).get("name", "?"),
                        workload=result.get("workload"),
                        port=listener.get("port", "?"),
                        rps=_fmt(listener.get("requests_per_sec"), 0),
                        p50=_fmt(listener_latency.get("p50")),
                        p95=_fmt(listener_latency.get("p95")),
                        p99=_fmt(listener_latency.get("p99")),
                        errors=_fmt(listener.get("errors"), 0),
                        rate=_fmt(listener.get("error_rate"), 4),
                        cpu=_fmt(system.get("cpu_percent"), 1),
                        rss=_fmt((system.get("rss_bytes_peak") or 0) / (1024 * 1024), 1),
                        fds=_fmt(system.get("fd_peak"), 0),
                    )
                )
            continue
        rps = metrics.get("requests_per_sec", tcp_udp.get("packets_per_sec"))
        errors = metrics.get("errors", tcp_udp.get("errors"))
        rate = metrics.get("error_rate")
        lines.append(
            "| {profile} | {workload} | {rps} | {p50} | {p95} | {p99} | {errors} | {rate} | {cpu} | {rss} | {fds} |".format(
                profile=result.get("process_profile", {}).get("name", "?"),
                workload=result.get("workload"),
                rps=_fmt(rps, 0),
                p50=_fmt(latency.get("p50")),
                p95=_fmt(latency.get("p95")),
                p99=_fmt(latency.get("p99")),
                errors=_fmt(errors, 0),
                rate=_fmt(rate, 4),
                cpu=_fmt(system.get("cpu_percent"), 1),
                rss=_fmt((system.get("rss_bytes_peak") or 0) / (1024 * 1024), 1),
                fds=_fmt(system.get("fd_peak"), 0),
            )
        )
    lines += [
        "",
        "## Unsupported workloads",
        "",
        "| profile | workload | reason |",
        "|---|---|---|",
    ]
    if not unsupported:
        lines.append("| — | — | none |")
    for result in unsupported:
        lines.append(
            "| {profile} | {workload} | {reason} |".format(
                profile=result.get("process_profile", {}).get("name", "?"),
                workload=result.get("workload"),
                reason=(result.get("unsupported_reason") or "unspecified").replace("|", "\\|"),
            )
        )
    lines += [
        "",
        "## Notes",
        "",
        "- `rps` is requests/sec for HTTP or packets/sec for TCP/UDP.",
        "- `errors` counts transport failures (including expected WAF block statuses only",
        "  when the status was not 2xx; inspect `status_codes` in the JSON).",
        "- A workload is marked unsupported only after the driver probed the path and",
        "  failed; it is never silently omitted.",
    ]
    return "\n".join(lines) + "\n"


def _fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "—"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if math.isnan(number) or math.isinf(number):
        return "—"
    return f"{number:.{digits}f}"


def run(args: argparse.Namespace) -> int:
    binary = resolve_binary(args)
    metadata = build_metadata(args, binary)
    metadata["toolchain"]["load_tool"] = args.tool
    out_dir = pathlib.Path(args.out).expanduser().resolve() / utc_now().strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    work_root = pathlib.Path(args.work_root).expanduser().resolve()
    work = work_root / f"synvoid-ms-{metadata['run_id']}"
    work.mkdir(parents=True, exist_ok=True)
    commands: List[List[str]] = []
    ports = allocate_ports()
    writer = ResultWriter(out_dir, metadata)
    upstreams: List[subprocess.Popen] = []
    servers: List[ServerHandle] = []
    try:
        upstreams = start_upstreams(work, ports, commands)
        tls_enabled = generate_cert(work)
        if args.skip_server:
            print(
                json.dumps(
                    {"metadata": metadata, "ports": ports, "tls_enabled": tls_enabled}, indent=2
                )
            )
            return 0

        for profile_name in args.process_profiles:
            workers, worker_threads, allow_multi = process_profile_settings(
                profile_name, args.threads
            )
            process_meta = common_process_meta(
                profile_name, workers, worker_threads, args.waf_profile
            )
            groups = workload_groups(args.workloads)
            server_seq = 0
            for group_key, group_workloads in groups.items():
                if not group_workloads:
                    continue
                site_count, extra_listen, group_label = group_key
                # Each group gets its own HTTP/TLS/H3/admin/metrics ports.
                # Stop the previous group's server before binding the next one;
                # leaving it running made the second group fail to bind and the
                # readiness probe see a refused connection.
                if servers:
                    previous = servers.pop()
                    stop_process(previous.popen)
                    previous.cleanup()
                server_seq += 1
                server_work = (
                    work
                    / f"server-{profile_name}-{site_count}-{int(extra_listen)}-{group_label}-{server_seq}"
                )
                server_work.mkdir(parents=True, exist_ok=True)
                config = write_config(
                    server_work,
                    ports=ports,
                    worker_threads=worker_threads,
                    workers=workers,
                    allow_multi_worker=allow_multi,
                    site_count=site_count,
                    waf_profile=args.waf_profile,
                    tls_enabled=tls_enabled,
                    extra_listen=extra_listen,
                )
                server = start_synvoid(
                    binary=binary,
                    work=server_work,
                    config=config,
                    ports=ports,
                    commands=commands,
                )
                servers.append(server)
                try:
                    for workload in group_workloads:
                        before = len(writer.results)
                        try:
                            if workload in {
                                "vhost-1",
                                "vhost-100",
                                "vhost-1000",
                                "h1-keepalive",
                                "h1-concurrent",
                                "mixed-static-proxy",
                                "waf-small",
                                "waf-body",
                            }:
                                run_http_workload(
                                    name=workload,
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                    duration=args.duration,
                                    concurrency=args.concurrency,
                                    tool=args.tool,
                                    waf_profile=args.waf_profile,
                                    commands=commands,
                                )
                            elif workload == "tls-h2":
                                run_tls_h2(
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                    duration=args.duration,
                                    concurrency=args.concurrency,
                                    commands=commands,
                                )
                            elif workload == "h3":
                                run_h3(
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                    duration=args.duration,
                                    concurrency=args.concurrency,
                                )
                            elif workload == "chunked-upload":
                                run_chunked_upload(
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                    duration=args.duration,
                                    concurrency=args.concurrency,
                                )
                            elif workload in {
                                "tcp-echo",
                                "tcp-multi-port",
                                "udp-echo",
                                "udp-multi-port",
                            }:
                                run_tcp_udp(
                                    name=workload,
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                    duration=args.duration,
                                    concurrency=args.concurrency,
                                )
                            elif workload == "multi-listener":
                                run_multi_listener(
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                )
                            elif workload == "soak":
                                run_soak(
                                    server=server,
                                    writer=writer,
                                    process_profile=profile_name,
                                    process_meta=process_meta,
                                    soak_seconds=args.soak_seconds,
                                    concurrency=args.concurrency,
                                    tool=args.tool,
                                )
                            else:
                                raise SystemExit(f"unknown workload {workload!r}")
                        except Exception as exc:  # noqa: BLE001 - record, keep the run alive
                            writer.write(
                                workload=workload,
                                process_profile=profile_name,
                                process_meta=process_meta,
                                supported=False,
                                result={
                                    "command": [],
                                    "diagnostics": f"{type(exc).__name__}: {exc}",
                                    "server_log_tail": server.log_tail(30),
                                },
                                unsupported_reason=f"workload failed: {type(exc).__name__}: {exc}",
                            )
                        if len(writer.results) == before:
                            writer.write(
                                workload=workload,
                                process_profile=profile_name,
                                process_meta=process_meta,
                                supported=False,
                                result={},
                                unsupported_reason="workload produced no result",
                            )
                finally:
                    time.sleep(0.5)
                    stop_process(server.popen)
                    server.cleanup()
    finally:
        for server in servers:
            stop_process(server.popen)
            server.cleanup()
        for proc in upstreams:
            stop_process(proc)
        write_run_files(
            out_dir=out_dir,
            metadata=metadata,
            results=writer.results,
            commands=commands,
            args=args,
            ports=ports,
        )
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"work directory kept: {work}", file=sys.stderr)

    supported = sum(1 for result in writer.results if result.get("supported"))
    print(f"results: {out_dir}")
    print(
        f"workloads: {len(writer.results)} ({supported} supported, {len(writer.results) - supported} unsupported)"
    )
    print(f"summary: {out_dir / (metadata['run_id'] + '-summary.md')}")
    return 0


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manual-only multi-service SynVoid benchmark harness",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--binary", default=None, help="subject binary (default: target/<build-profile>/synvoid)"
    )
    parser.add_argument("--build-profile", default="release", choices=("release", "ci", "debug"))
    parser.add_argument(
        "--process-profiles",
        default="default",
        help="comma list: default, threads-1, threads-N, workers-2",
    )
    parser.add_argument("--waf-profile", default="on", choices=("off", "on", "block"))
    parser.add_argument("--workloads", default="all", help="comma/space list; 'all' includes soak")
    parser.add_argument(
        "--duration", type=float, default=10.0, help="seconds per measured workload"
    )
    parser.add_argument("--soak-seconds", type=float, default=1800.0)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--threads", type=int, default=4, help="N for the threads-N profile")
    parser.add_argument("--tool", default="auto", choices=("auto", "oha", "python"))
    parser.add_argument("--out", default=str(HERE / "results"), help="results root")
    parser.add_argument("--work-root", default=os.environ.get("TMPDIR", "/tmp"))
    parser.add_argument("--keep-work", action="store_true")
    parser.add_argument(
        "--skip-server",
        action="store_true",
        help="resolve metadata and exit without starting SynVoid",
    )
    parser.add_argument("--list-workloads", action="store_true")
    parser.add_argument(
        "--smoke", action="store_true", help="tiny pipeline check; never adjudication evidence"
    )
    args = parser.parse_args(argv)

    if args.list_workloads:
        print("\n".join(ALL_WORKLOADS))
        raise SystemExit(0)

    if args.smoke:
        args.duration = min(args.duration, 1.0)
        args.soak_seconds = min(args.soak_seconds, 3.0)
        args.concurrency = min(args.concurrency, 8)
        if args.workloads == "all":
            args.workloads = ",".join(ALL_WORKLOADS)
    args.process_profiles = [
        part for part in args.process_profiles.replace(" ", ",").split(",") if part
    ]
    if not args.process_profiles:
        raise SystemExit("--process-profiles must not be empty")
    if args.workloads.strip().lower() == "all":
        args.workloads = list(ALL_WORKLOADS)
    else:
        normalized = args.workloads.replace(",", " ").split()
        unknown = [name for name in normalized if name not in ALL_WORKLOADS]
        if unknown:
            raise SystemExit(f"unknown workloads: {', '.join(unknown)}")
        args.workloads = normalized
    if args.tool == "auto" and not shutil.which("oha"):
        args.tool = "python"
    if args.tool == "oha" and not shutil.which("oha"):
        raise SystemExit("--tool oha requested but oha is not installed")
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level report
        print(f"benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
