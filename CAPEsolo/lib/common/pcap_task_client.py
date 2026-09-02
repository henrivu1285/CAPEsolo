"""Task-scoped client for the external CAPEsolo PCAP capture agent.

The malware guest must not capture its own traffic: a sample can tamper with a
guest-side capture process and the capture would disappear when the snapshot is
restored.  This client therefore asks the isolated Ubuntu/INetSim VM to run
``dumpcap`` for exactly one CAPEsolo ``run_id`` and downloads the resulting
pcapng into the current analysis directory.

Only Python's standard library is used because this module runs inside the
Windows analyzer guest.  Capture failure is reported as coverage metadata and
never aborts the malware analysis.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

try:
    from .clock_model import analyze_clock_samples
except ImportError:  # standalone self-tests load this file by path
    from CAPEsolo.lib.common.clock_model import analyze_clock_samples


SCHEMA = "capesolo-pcap-runtime/1.4"
MAX_CONTROL_RESPONSE = 1024 * 1024
MAX_CAPTURE_BYTES = 2 * 1024 * 1024 * 1024
MAX_CLOCK_UNCERTAINTY_NS = 250 * 1000 * 1000
SYNCHRONIZED_CLOCK_NS = 2 * 1000 * 1000 * 1000
CLOCK_DRIFT_WARNING_NS = 500 * 1000 * 1000
CLOCK_DISCONTINUITY_NS = 2 * 1000 * 1000 * 1000
DEFAULT_CLOCK_SAMPLE_INTERVAL = 10.0
MAX_CLOCK_SAMPLES = 128
MAX_CLOCK_SAMPLE_ERRORS = 8


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_agent_url(value):
    url = str(value or "").strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("pcap_agent_url must be a plain HTTP URL without credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("pcap_agent_url must not contain a path, query, or fragment")
    return url


def detect_source_ip(agent_url):
    """Return the Windows address selected for the route to the capture VM."""
    parsed = urlparse(_safe_agent_url(agent_url))
    port = int(parsed.port or 80)
    family = socket.AF_INET6 if ":" in parsed.hostname else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.connect((parsed.hostname, port))
        value = sock.getsockname()[0]
        ipaddress.ip_address(value)
        return value
    finally:
        sock.close()


class PcapTaskClient:
    def __init__(
        self,
        agent_url,
        token="",
        guest_ip="auto",
        timeout=5.0,
        max_capture_bytes=MAX_CAPTURE_BYTES,
        clock_sample_interval=DEFAULT_CLOCK_SAMPLE_INTERVAL,
    ):
        self.agent_url = _safe_agent_url(agent_url)
        self.token = str(token or "")
        self.guest_ip = str(guest_ip or "auto").strip()
        self.timeout = max(0.5, float(timeout))
        self.max_capture_bytes = max(1024 * 1024, int(max_capture_bytes))
        self.clock_sample_interval = min(60.0, max(5.0, float(clock_sample_interval)))
        self._clock_lock = threading.RLock()
        self._clock_sampler_stop = threading.Event()
        self._clock_sampler_thread = None
        self.runtime = {
            "schema": SCHEMA,
            "configured": True,
            "agent_url": self.agent_url,
            "guest_ip": None,
            "run_id": None,
            "status": "configured",
            "started": False,
            "stopped": False,
            "fetched": False,
            "clock_sync": {
                "schema": "capesolo-clock-correlation/1.3",
                "status": "unavailable",
                "source": "agent_response_midpoint",
                "usable": False,
                "samples": 0,
                "sample_points": [],
                "model": "unavailable",
                "drift_detected": False,
                "discontinuity_detected": False,
            },
            "clock_sampler": {
                "status": "configured",
                "interval_seconds": self.clock_sample_interval,
                "periodic_requests": 0,
                "failures": 0,
                "errors": [],
            },
            "clock_domains": {
                "start_requested_utc": "windows_guest",
                "start_requested_guest_utc": "windows_guest",
                "stop_requested_utc": "windows_guest",
                "stop_requested_guest_utc": "windows_guest",
                "updated_utc": "windows_guest",
                "capture_started_utc": "ubuntu_agent",
                "capture_started_agent_utc": "ubuntu_agent",
                "capture_stopped_utc": "ubuntu_agent",
                "capture_stopped_agent_utc": "ubuntu_agent",
            },
            "errors": [],
        }

    def _headers(self, content_type=False):
        headers = {"Accept": "application/json", "User-Agent": "CAPEsolo-P32314/pcap"}
        if content_type:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["X-CAPEsolo-Token"] = self.token
        return headers

    def _json_request(self, method, path, payload=None):
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.agent_url + path,
            data=body,
            headers=self._headers(content_type=payload is not None),
            method=method,
        )
        client_send_ns = time.time_ns()
        client_send_monotonic_ns = time.monotonic_ns()
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_CONTROL_RESPONSE + 1)
        except HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", "replace")
            raise RuntimeError("capture agent HTTP %s: %s" % (exc.code, detail))
        except (URLError, OSError) as exc:
            raise RuntimeError("capture agent unavailable: %s" % exc)
        client_receive_monotonic_ns = time.monotonic_ns()
        client_receive_ns = time.time_ns()
        if len(raw) > MAX_CONTROL_RESPONSE:
            raise RuntimeError("capture agent response exceeded the safety limit")
        try:
            result = json.loads(raw.decode("utf-8", "replace"))
        except Exception as exc:
            raise RuntimeError("capture agent returned invalid JSON: %s" % exc)
        if not isinstance(result, dict):
            raise RuntimeError("capture agent returned a non-object response")
        self._record_clock_sample(
            result,
            client_send_ns,
            client_receive_ns,
            sample_kind=path.split("?", 1)[0],
            client_send_monotonic_ns=client_send_monotonic_ns,
            client_receive_monotonic_ns=client_receive_monotonic_ns,
        )
        return result

    def _record_clock_sample(
        self, response, client_send_ns, client_receive_ns, sample_kind="manual",
        client_send_monotonic_ns=None, client_receive_monotonic_ns=None,
    ):
        """Keep bounded samples and classify stable, slew and step intervals.

        Windows sandbox time can move while an analysis starts. Keeping only
        the best RTT sample made a later offset apply to early packets. The
        correlation layer interpolates continuous points on the Ubuntu clock,
        but a step larger than ``CLOCK_DISCONTINUITY_NS`` makes correlation
        unusable instead of pretending the jump was gradual.
        """
        try:
            server_ns = int(response.get("server_time_ns"))
        except (TypeError, ValueError):
            return
        wall_span_ns = int(client_receive_ns) - int(client_send_ns)
        monotonic_span_ns = None
        if client_send_monotonic_ns is not None and client_receive_monotonic_ns is not None:
            monotonic_span_ns = (
                int(client_receive_monotonic_ns) - int(client_send_monotonic_ns)
            )
        rtt_ns = max(0, monotonic_span_ns if monotonic_span_ns is not None else wall_span_ns)
        request_wall_adjustment_ns = (
            wall_span_ns - monotonic_span_ns
            if monotonic_span_ns is not None else None
        )
        midpoint_ns = (int(client_send_ns) + int(client_receive_ns)) // 2
        midpoint_monotonic_ns = None
        if client_send_monotonic_ns is not None and client_receive_monotonic_ns is not None:
            midpoint_monotonic_ns = (
                int(client_send_monotonic_ns) + int(client_receive_monotonic_ns)
            ) // 2
        offset_ns = server_ns - midpoint_ns
        uncertainty_ns = rtt_ns // 2
        if uncertainty_ns > MAX_CLOCK_UNCERTAINTY_NS or (
            request_wall_adjustment_ns is not None
            and abs(request_wall_adjustment_ns) > MAX_CLOCK_UNCERTAINTY_NS
        ):
            status = "unreliable"
        elif abs(offset_ns) <= SYNCHRONIZED_CLOCK_NS:
            status = "synchronized"
        else:
            status = "offset_compensated"
        sample = {
            "status": status,
            "offset_ns": offset_ns,
            "rtt_ns": rtt_ns,
            "uncertainty_ns": uncertainty_ns,
            "client_request_wall_span_ns": wall_span_ns,
            "client_request_monotonic_span_ns": monotonic_span_ns,
            "client_request_wall_adjustment_ns": request_wall_adjustment_ns,
            "client_send_time_ns": int(client_send_ns),
            "client_receive_time_ns": int(client_receive_ns),
            "client_midpoint_time_ns": int(midpoint_ns),
            "client_send_monotonic_ns": (
                int(client_send_monotonic_ns)
                if client_send_monotonic_ns is not None else None
            ),
            "client_receive_monotonic_ns": (
                int(client_receive_monotonic_ns)
                if client_receive_monotonic_ns is not None else None
            ),
            "client_midpoint_monotonic_ns": midpoint_monotonic_ns,
            "server_time_ns": server_ns,
            "server_monotonic_ns": response.get("server_monotonic_ns"),
            "server_utc": response.get("server_utc"),
            "sample_kind": str(sample_kind or "manual"),
        }
        with self._clock_lock:
            previous = self.runtime.get("clock_sync")
            previous = previous if isinstance(previous, dict) else {}
            points = [
                item for item in (previous.get("sample_points") or [])
                if isinstance(item, dict) and item.get("server_time_ns") is not None
            ]
            points.append(sample)
            points = sorted(
                points, key=lambda item: int(item.get("server_time_ns") or 0)
            )[-MAX_CLOCK_SAMPLES:]
            analysis = analyze_clock_samples(
                points,
                max_uncertainty_ns=MAX_CLOCK_UNCERTAINTY_NS,
                slew_threshold_ns=CLOCK_DRIFT_WARNING_NS,
                discontinuity_ns=CLOCK_DISCONTINUITY_NS,
            )
            reliable = analysis["reliable_points"]
            best_pool = reliable or points
            best = min(
                best_pool, key=lambda item: int(item.get("rtt_ns") or (1 << 62))
            )
            offset_span_ns = int(analysis["offset_span_ns"])
            max_step_ns = int(analysis["max_step_ns"])
            server_span_ns = (
                int(reliable[-1].get("server_time_ns") or 0)
                - int(reliable[0].get("server_time_ns") or 0)
                if len(reliable) > 1 else 0
            )
            self.runtime["clock_sync"] = {
                "schema": "capesolo-clock-correlation/1.3",
                "status": analysis["status"],
                "source": "agent_response_midpoint_periodic",
                "offset_semantics": "agent_time_minus_windows_guest_time",
                "offset_ns": int(best.get("offset_ns") or 0),
                "offset_ms": round(int(best.get("offset_ns") or 0) / 1_000_000.0, 3),
                "rtt_ns": int(best.get("rtt_ns") or 0),
                "rtt_ms": round(int(best.get("rtt_ns") or 0) / 1_000_000.0, 3),
                "uncertainty_ns": int(best.get("uncertainty_ns") or 0),
                "uncertainty_ms": round(int(best.get("uncertainty_ns") or 0) / 1_000_000.0, 3),
                "client_send_time_ns": int(best.get("client_send_time_ns") or 0),
                "client_receive_time_ns": int(best.get("client_receive_time_ns") or 0),
                "server_time_ns": int(best.get("server_time_ns") or 0),
                "samples": len(points),
                "reliable_samples": len(reliable),
                "sample_points": points,
                "sample_interval_seconds": self.clock_sample_interval,
                "sampling_span_seconds": round(server_span_ns / 1_000_000_000.0, 6),
                "model": analysis["model"],
                "usable": analysis["usable"],
                "full_capture_usable": analysis["full_capture_usable"],
                "fallback_allowed": analysis["fallback_allowed"],
                "offset_span_ns": offset_span_ns,
                "offset_span_ms": round(offset_span_ns / 1_000_000.0, 3),
                "max_step_ns": max_step_ns,
                "max_step_ms": round(max_step_ns / 1_000_000.0, 3),
                "drift_detected": analysis["drift_detected"],
                "drift_warning_threshold_ms": CLOCK_DRIFT_WARNING_NS // 1_000_000,
                "slew_detected": analysis["slew_detected"],
                "slew_intervals": analysis["slew_intervals"],
                "discontinuity_detected": analysis["discontinuity_detected"],
                "discontinuity_threshold_ms": CLOCK_DISCONTINUITY_NS // 1_000_000,
                "discontinuity_intervals": analysis["discontinuity_intervals"],
                "unusable_intervals": analysis["unusable_intervals"],
                "segments": analysis["segments"],
                "raw_timestamps_modified": False,
            }

    def _clock_sample_once(self):
        run_id = str(self.runtime.get("run_id") or "")
        if not run_id:
            return False
        sampler = self.runtime.setdefault("clock_sampler", {})
        try:
            self._json_request(
                "GET", "/v1/status?run_id=" + quote(run_id, safe="")
            )
            sampler["periodic_requests"] = int(sampler.get("periodic_requests") or 0) + 1
            return True
        except Exception as exc:
            sampler["failures"] = int(sampler.get("failures") or 0) + 1
            errors = sampler.setdefault("errors", [])
            errors.append(str(exc))
            del errors[:-MAX_CLOCK_SAMPLE_ERRORS]
            return False

    def _clock_sample_loop(self):
        while not self._clock_sampler_stop.wait(self.clock_sample_interval):
            self._clock_sample_once()

    def _start_clock_sampler(self):
        if self._clock_sampler_thread is not None:
            return
        self._clock_sampler_stop.clear()
        sampler = self.runtime.setdefault("clock_sampler", {})
        sampler["status"] = "running"
        thread = threading.Thread(
            target=self._clock_sample_loop,
            name="CAPEsoloClockSampler",
            daemon=True,
        )
        self._clock_sampler_thread = thread
        thread.start()

    def _stop_clock_sampler(self):
        self._clock_sampler_stop.set()
        thread = self._clock_sampler_thread
        if thread is not None:
            thread.join(timeout=min(2.0, self.clock_sample_interval + 0.5))
        self._clock_sampler_thread = None
        self.runtime.setdefault("clock_sampler", {})["status"] = "stopped"

    def _resolved_guest_ip(self):
        value = self.guest_ip
        if value.lower() in ("", "auto"):
            value = detect_source_ip(self.agent_url)
        ip = ipaddress.ip_address(value)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError("pcap_guest_ip is not a capturable guest address")
        return str(ip)

    def start(self, run_id, duration=240):
        self.runtime["run_id"] = str(run_id or "")
        self.runtime["start_requested_utc"] = _utc_now()
        self.runtime["start_requested_guest_utc"] = self.runtime["start_requested_utc"]
        try:
            guest_ip = self._resolved_guest_ip()
            self.runtime["guest_ip"] = guest_ip
            response = self._json_request(
                "POST",
                "/v1/start",
                {
                    "run_id": self.runtime["run_id"],
                    "guest_ip": guest_ip,
                    "duration": max(10, int(duration)),
                },
            )
            self.runtime.update(
                started=bool(response.get("started")),
                status=str(response.get("status") or "started"),
                capture_started_utc=response.get("started_utc"),
                capture_started_agent_utc=response.get("started_utc"),
                interface=response.get("interface"),
                capture_filter=response.get("capture_filter"),
                agent_pid=response.get("capture_pid"),
            )
            if not self.runtime["started"]:
                raise RuntimeError(str(response.get("error") or "capture was not started"))
            self._start_clock_sampler()
        except Exception as exc:
            self.runtime["status"] = "start_failed"
            self.runtime["errors"].append(str(exc))
        return dict(self.runtime)

    def _download(self, run_id, destination):
        path = "/v1/capture/" + str(run_id)
        request = Request(
            self.agent_url + path,
            headers={**self._headers(), "Accept": "application/octet-stream"},
            method="GET",
        )
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(destination.name + ".partial")
        digest = hashlib.sha256()
        total = 0
        try:
            with urlopen(request, timeout=max(self.timeout, 30.0)) as response, partial.open("wb") as out:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_capture_bytes:
                        raise RuntimeError("capture exceeded configured maximum size")
                    digest.update(chunk)
                    out.write(chunk)
            if total < 24:
                raise RuntimeError("capture is empty or has no complete file header")
            os.replace(str(partial), str(destination))
            return {
                "path": str(destination),
                "bytes": total,
                "sha256": digest.hexdigest(),
            }
        finally:
            try:
                if partial.exists():
                    partial.unlink()
            except OSError:
                pass

    def stop_and_fetch(self, run_id, analysis_dir, fetch=True):
        self.runtime["stop_requested_utc"] = _utc_now()
        self.runtime["stop_requested_guest_utc"] = self.runtime["stop_requested_utc"]
        self._stop_clock_sampler()
        if not self.runtime.get("started"):
            self.runtime["stopped"] = False
            self.runtime["fetched"] = False
            return self._write_runtime(analysis_dir)
        try:
            response = self._json_request("POST", "/v1/stop", {"run_id": str(run_id)})
            self.runtime.update(
                stopped=bool(response.get("stopped")),
                status=str(response.get("status") or "stopped"),
                capture_stopped_utc=response.get("stopped_utc"),
                capture_stopped_agent_utc=response.get("stopped_utc"),
                capture_exit_code=response.get("exit_code"),
                packets_captured=response.get("packets_captured"),
                packets_dropped=response.get("packets_dropped"),
                packet_loss_status=response.get("packet_loss_status") or "unknown",
                packet_loss_reason=response.get("packet_loss_reason") or "agent_did_not_report",
                agent_capture_bytes=response.get("bytes"),
                agent_capture_sha256=response.get("sha256"),
            )
            if not self.runtime["stopped"]:
                raise RuntimeError(str(response.get("error") or "capture did not stop cleanly"))
        except Exception as exc:
            self.runtime["status"] = "stop_failed"
            self.runtime["errors"].append(str(exc))
            return self._write_runtime(analysis_dir)

        if fetch:
            try:
                downloaded = self._download(run_id, Path(analysis_dir) / "dump.pcapng")
                self.runtime.update(downloaded)
                self.runtime["fetched"] = True
                self.runtime["status"] = "complete"
                remote_hash = str(self.runtime.get("agent_capture_sha256") or "").lower()
                if remote_hash and remote_hash != downloaded["sha256"].lower():
                    raise RuntimeError("downloaded capture SHA-256 differs from the agent")
            except Exception as exc:
                self.runtime["status"] = "fetch_failed"
                self.runtime["errors"].append(str(exc))
        else:
            self.runtime["status"] = "stopped_not_fetched"
        return self._write_runtime(analysis_dir)

    def _write_runtime(self, analysis_dir):
        self.runtime["updated_utc"] = _utc_now()
        path = Path(analysis_dir) / "pcap_runtime.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(json.dumps(self.runtime, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(temporary), str(path))
            self.runtime["runtime_path"] = str(path)
        except Exception as exc:
            self.runtime["errors"].append("runtime_write_failed: %s" % exc)
        return dict(self.runtime)
