#!/usr/bin/env python3
"""Small, task-scoped dumpcap service for an isolated CAPEsolo network.

The service deliberately exposes no shell or arbitrary command endpoint.  A
request may only start/stop/download a capture whose file name is a validated
CAPEsolo run id.  Bind it to the Ubuntu Internal Network address, never to a
NAT/bridged interface.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
MAX_BODY = 64 * 1024
SCHEMA = "capesolo-pcap-agent/1.3"


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_dumpcap_stats(text):
    captured = None
    dropped = None
    for line in str(text or "").splitlines():
        match = re.search(r"Packets captured:\s*(\d+)", line, re.I)
        if match:
            captured = int(match.group(1))
        match = re.search(r"Packets dropped:\s*(\d+)", line, re.I)
        if match:
            dropped = int(match.group(1))
    return captured, dropped


def packet_loss_metadata(captured, dropped):
    """Describe loss without turning an omitted dumpcap counter into zero."""
    if dropped is None:
        return "unknown", "dumpcap_did_not_report_drop_count"
    if dropped > 0:
        return "drops_observed", "dumpcap_reported_drops"
    if captured is None:
        return "none_reported", "dumpcap_reported_zero_drops_without_capture_count"
    return "none_observed", "dumpcap_reported_zero_drops"


class CaptureState:
    def __init__(self, config):
        self.config = config
        self.lock = threading.RLock()
        self.active = None
        self.records = {}

    def _path(self, run_id):
        return self.config.output_dir / (run_id + ".pcapng")

    def start(self, run_id, guest_ip, duration):
        if not RUN_ID_RE.fullmatch(str(run_id or "")):
            raise ValueError("invalid run_id")
        guest = ipaddress.ip_address(str(guest_ip or ""))
        if guest.is_loopback or guest.is_unspecified or guest.is_multicast:
            raise ValueError("invalid guest_ip")
        if guest not in self.config.guest_network or str(guest) == self.config.bind:
            raise ValueError("guest_ip is outside the configured Internal Network")
        duration = max(10, min(self.config.max_duration, int(duration)))
        with self.lock:
            self._refresh_locked()
            if self.active is not None:
                if self.active["run_id"] == run_id:
                    return dict(self.active)
                raise RuntimeError("another capture is already active")

            path = self._path(run_id)
            if path.exists():
                raise RuntimeError("capture for this run_id already exists")
            capture_filter = (
                "host %s and not (host %s and tcp port %d)"
                % (guest, self.config.bind, self.config.port)
            )
            command = [
                self.config.dumpcap,
                "-q",
                "-i",
                self.config.interface,
                "-f",
                capture_filter,
                "-B",
                str(self.config.buffer_mib),
                "-a",
                "duration:%d" % duration,
                "-w",
                str(path),
            ]
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                start_new_session=True,
            )
            time.sleep(0.12)
            if process.poll() is not None:
                detail = (process.stderr.read(4096) if process.stderr else "").strip()
                raise RuntimeError("dumpcap exited during startup: %s" % detail)
            record = {
                "schema": SCHEMA,
                "run_id": run_id,
                "guest_ip": str(guest),
                "interface": self.config.interface,
                "capture_filter": capture_filter,
                "path": str(path),
                "duration": duration,
                "capture_pid": process.pid,
                "process": process,
                "started": True,
                "stopped": False,
                "status": "capturing",
                "started_utc": utc_now(),
            }
            self.active = record
            self.records[run_id] = record
            return self.public(record)

    def _refresh_locked(self):
        record = self.active
        if record is None:
            return
        process = record["process"]
        if process.poll() is None:
            return
        self._finalize_locked(record)

    def _finalize_locked(self, record):
        process = record["process"]
        try:
            stderr = process.stderr.read(65536) if process.stderr else ""
        except Exception:
            stderr = ""
        captured, dropped = parse_dumpcap_stats(stderr)
        loss_status, loss_reason = packet_loss_metadata(captured, dropped)
        path = Path(record["path"])
        record.update(
            stopped=True,
            status="complete" if path.is_file() and path.stat().st_size >= 24 else "empty",
            stopped_utc=utc_now(),
            exit_code=process.returncode,
            packets_captured=captured,
            packets_dropped=dropped,
            packet_loss_status=loss_status,
            packet_loss_reason=loss_reason,
            bytes=path.stat().st_size if path.is_file() else 0,
            sha256=sha256_file(path) if path.is_file() and path.stat().st_size else None,
        )
        if self.active is record:
            self.active = None

    def stop(self, run_id):
        if not RUN_ID_RE.fullmatch(str(run_id or "")):
            raise ValueError("invalid run_id")
        with self.lock:
            self._refresh_locked()
            record = self.records.get(run_id)
            if record is None:
                raise KeyError("unknown run_id")
            process = record["process"]
            if not record.get("stopped") and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=self.config.stop_timeout)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2.0)
                self._finalize_locked(record)
            return self.public(record)

    def get(self, run_id):
        if not RUN_ID_RE.fullmatch(str(run_id or "")):
            raise ValueError("invalid run_id")
        with self.lock:
            self._refresh_locked()
            record = self.records.get(run_id)
            return self.public(record) if record is not None else None

    @staticmethod
    def public(record):
        if record is None:
            return None
        return {key: value for key, value in record.items() if key not in ("process", "path")}

    def capture_path(self, run_id):
        with self.lock:
            self._refresh_locked()
            record = self.records.get(run_id)
            if record is None or not record.get("stopped"):
                return None
            path = Path(record["path"])
            return path if path.is_file() else None


class Handler(BaseHTTPRequestHandler):
    server_version = "CAPEsoloPcap/1.3"

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def _authorized(self):
        expected = self.server.config.token
        if not expected:
            return True
        supplied = self.headers.get("X-CAPEsolo-Token", "")
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def _json(self, status, payload):
        # Include the Ubuntu wall clock in each control response. The Windows
        # client brackets the request with local timestamps and estimates the
        # agent-minus-guest offset without rewriting either raw timeline.
        if isinstance(payload, dict):
            payload = dict(payload)
            payload.setdefault("server_time_ns", time.time_ns())
            payload.setdefault("server_monotonic_ns", time.monotonic_ns())
            payload.setdefault("server_utc", utc_now())
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid Content-Length")
        if length <= 0 or length > MAX_BODY:
            raise ValueError("invalid request body size")
        data = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            active = self.server.state.get(self.server.state.active["run_id"]) if self.server.state.active else None
            return self._json(200, {"schema": SCHEMA, "status": "ok", "active": active})
        if not self._authorized():
            return self._json(401, {"error": "unauthorized"})
        if parsed.path == "/v1/status":
            run_id = (parse_qs(parsed.query).get("run_id") or [""])[0]
            try:
                record = self.server.state.get(run_id)
                return self._json(200 if record else 404, record or {"error": "unknown run_id"})
            except Exception as exc:
                return self._json(400, {"error": str(exc)})
        prefix = "/v1/capture/"
        if parsed.path.startswith(prefix):
            run_id = parsed.path[len(prefix):]
            try:
                path = self.server.state.capture_path(run_id)
            except Exception as exc:
                return self._json(400, {"error": str(exc)})
            if path is None:
                return self._json(409, {"error": "capture is unknown or still active"})
            size = path.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pcapng")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", 'attachment; filename="%s.pcapng"' % run_id)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    self.wfile.write(chunk)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return self._json(401, {"error": "unauthorized"})
        try:
            body = self._body()
            if self.path == "/v1/start":
                result = self.server.state.start(
                    str(body.get("run_id") or ""),
                    str(body.get("guest_ip") or ""),
                    int(body.get("duration") or self.server.config.default_duration),
                )
                return self._json(200, result)
            if self.path == "/v1/stop":
                result = self.server.state.stop(str(body.get("run_id") or ""))
                return self._json(200, result)
            return self._json(404, {"error": "not found"})
        except KeyError as exc:
            self._json(404, {"error": str(exc)})
        except (ValueError, RuntimeError) as exc:
            self._json(409 if isinstance(exc, RuntimeError) else 400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": "internal error: %s" % exc})


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default=os.environ.get("CAPESOLO_PCAP_BIND", "192.168.56.2"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CAPESOLO_PCAP_PORT", "54321")))
    parser.add_argument("--interface", default=os.environ.get("CAPESOLO_PCAP_INTERFACE", "enp0s3"))
    parser.add_argument("--guest-network", default=os.environ.get("CAPESOLO_PCAP_GUEST_NETWORK", "192.168.56.0/24"))
    parser.add_argument("--output-dir", type=Path, default=Path(os.environ.get("CAPESOLO_PCAP_OUTPUT", "/var/lib/capesolo-pcap")))
    parser.add_argument("--dumpcap", default=os.environ.get("CAPESOLO_DUMPCAP", "/usr/bin/dumpcap"))
    parser.add_argument("--token", default=os.environ.get("CAPESOLO_PCAP_TOKEN", ""))
    parser.add_argument("--default-duration", type=int, default=240)
    parser.add_argument("--max-duration", type=int, default=900)
    parser.add_argument("--buffer-mib", type=int, default=64)
    parser.add_argument("--stop-timeout", type=float, default=8.0)
    return parser.parse_args()


def main():
    config = parse_args()
    bind = ipaddress.ip_address(config.bind)
    if bind.is_unspecified or bind.is_loopback or bind.is_multicast:
        raise SystemExit("--bind must be the Ubuntu Internal Network address")
    if not INTERFACE_RE.fullmatch(config.interface):
        raise SystemExit("invalid --interface")
    config.guest_network = ipaddress.ip_network(config.guest_network, strict=False)
    if bind not in config.guest_network:
        raise SystemExit("--bind must belong to --guest-network")
    if not Path(config.dumpcap).is_file():
        raise SystemExit("dumpcap not found: %s" % config.dumpcap)
    config.output_dir.mkdir(parents=True, exist_ok=True)
    config.output_dir = config.output_dir.resolve()
    config.max_duration = max(10, min(3600, config.max_duration))
    config.default_duration = max(10, min(config.max_duration, config.default_duration))
    config.buffer_mib = max(1, min(512, config.buffer_mib))
    server = ThreadingHTTPServer((str(bind), config.port), Handler)
    server.config = config
    server.state = CaptureState(config)
    print(
        "CAPEsolo PCAP agent listening on http://%s:%d interface=%s auth=%s"
        % (bind, config.port, config.interface, "token" if config.token else "internal-network-only"),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        active = server.state.active
        if active is not None:
            try:
                server.state.stop(active["run_id"])
            except Exception:
                pass
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
