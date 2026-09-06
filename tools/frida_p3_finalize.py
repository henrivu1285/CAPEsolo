#!/usr/bin/env python3
"""Build the P3.2.3.16 summary for the current CAPEsolo attempt.

P3.2.3.16 retains the active-time child observation window, gates cold
cross-bitness child attach on usable injector prewarm, and preserves the exact
terminal attach outcome. Raw evidence and the lossless clean view are unchanged.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for search_path in (HERE, PROJECT_ROOT):
    if str(search_path) not in sys.path:
        sys.path.insert(0, str(search_path))

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION, product_version_for_runtime
from CAPEsolo.capelib.network_summary import InterpretNetworkAbsence
from frida_artifact_filter import classify_analysis
from frida_behavior_provenance import classify_behavior
try:
    from frida_behavior_pid_repair import repair_behavior_pid_ownership
except ImportError:
    repair_behavior_pid_ownership = None
from frida_behavior_compact import build_compact_view
from frida_behavior_chains import build_behavior_chains
from p3_run_scope import load_runtime_for_analysis, select_run_log

P3_EVIDENCE_RE = re.compile(r"\[P3Evidence\]\s+(\{.*\})\s*$")
RESULTSERVER_RE = re.compile(r"ResultServer transfers complete=(\d+) incomplete=(\d+)")
RESULTSERVER_SHUTDOWN_WARNING_RE = re.compile(
    r"ResultServer (?:did not stop via its own hub|thread still alive|did not stop cleanly)",
    re.I,
)
SIGNATURE_RE = re.compile(r'Analysis matched signature \"([^\"]+)\"')
PROFILE_RE = re.compile(r'FridaMuncher.*(?:P3(?:\.\d+)?|v11 P2\.1 Hybrid Optimized) config:.*?profile=([^ ]+)')
ATTACH_FAIL_RE = re.compile(r"Frida attach attempt \d+ failed|Could not attach Frida", re.I)
API_RATE_CAP_RE = re.compile(r"api-rate-cap:\s+([A-Za-z0-9_]+)\s+hook disabled due to rate", re.I)
SCRIPT_SETUP_FAIL_RE = re.compile(
    r"\[pid=(\d+)\]\s+Script/setup failed for role=([A-Za-z_]+)", re.I
)

READY_FRIDA_STATES = {"hooks_ready", "fast_hooks_ready"}
INTENTIONAL_CHILD_STATES = {
    "capemon_only_policy",
    "capemon_observed_short_lived",
    "fast_hooks_configured_unconfirmed_target_exited",
}


def detect_default_analysis_dir() -> Path:
    candidates = [Path.cwd() / "cfg.ini"]
    if sys.platform.startswith("win"):
        import os
        candidates.append(Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "CAPEsolo" / "cfg.ini")
    for cfg in candidates:
        try:
            if not cfg.is_file():
                continue
            parser = configparser.ConfigParser()
            parser.read(cfg, encoding="utf-8")
            value = parser.get("analysis_directory", "analysis", fallback="").strip()
            if value:
                return Path(value)
        except Exception:
            continue
    if sys.platform.startswith("win"):
        import os
        return Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "CAPEsolo" / "analysis"
    return Path.cwd()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _recover_p3_events(log_text: str, run_id: str | None = None) -> list[dict]:
    events = []
    for line in log_text.splitlines():
        m = P3_EVIDENCE_RE.search(line)
        if not m:
            continue
        try:
            event = json.loads(m.group(1))
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        if run_id and event.get("run_id") not in (None, run_id):
            continue
        events.append(event)
    return events


def _sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _artifact_details(classification: dict) -> dict:
    path = classification.get("resolved_path")
    p = Path(path) if path else None
    size = None
    digest = None
    actual_mz = None
    if p and p.is_file():
        try:
            size = p.stat().st_size
            with p.open("rb") as fh:
                actual_mz = fh.read(2) == b"MZ"
        except OSError:
            pass
        digest = _sha256(p)
    out = dict(classification)
    if size is not None:
        out["size"] = size
    if digest is not None:
        out["sha256"] = digest
    if actual_mz is not None:
        out["is_pe"] = actual_mz or bool(out.get("is_pe"))
    return out


def _event_count(events: list[dict], kind: str) -> int:
    return sum(1 for event in events if event.get("kind") == kind)


def _first_event(events: list[dict], kind: str) -> dict | None:
    return next((event for event in events if event.get("kind") == kind), None)


def _attach_outcome_summary(events: list[dict], log_text: str) -> dict:
    """Count one terminal outcome per (pid, attempt).

    P3.2.3 logged two human-readable failure lines for one attach and the old
    regex therefore inflated failure counts. P3.2.3.4 uses structured
    `frida_attach` events as the source of truth, while retaining a legacy log
    fallback for older runs.
    """
    terminal = {}
    late_cleanup = 0
    for event in events:
        kind = str(event.get("kind") or "")
        if kind == "frida_attach_late_cleanup":
            late_cleanup += 1
            continue
        if kind != "frida_attach":
            continue
        status = str(event.get("status") or "").strip().lower()
        if not status:
            continue
        try:
            pid = int(event.get("pid") or 0)
        except Exception:
            pid = 0
        try:
            attempt = int(event.get("attempt") or 0)
        except Exception:
            attempt = 0
        try:
            create_time = round(float(event.get("create_time")), 3) if event.get("create_time") is not None else None
        except Exception:
            create_time = None
        # Last structured event wins for the same PID+create_time+attempt.
        terminal[(pid, create_time, attempt)] = event

    if not terminal:
        legacy = len(ATTACH_FAIL_RE.findall(log_text))
        # Historical P3.2.3 may emit both "attempt failed" and "Could not
        # attach" for the same failure.  We cannot recover perfect identity
        # without events, so expose it explicitly as a legacy estimate.
        return {
            "attempts": 0,
            "success": 0,
            "failed_exception": legacy,
            "target_died": 0,
            "timeout": 0,
            "device_unavailable": 0,
            "stop_requested": 0,
            "other": 0,
            "late_sessions_detached": 0,
            "hard_failures": legacy,
            "legacy_log_estimate": True,
            "events": [],
        }

    counts = {
        "success": 0,
        "failed_exception": 0,
        "target_died": 0,
        "timeout": 0,
        "device_unavailable": 0,
        "stop_requested": 0,
        "other": 0,
    }
    ordered = sorted(terminal.values(), key=lambda e: (float(e.get("monotonic") or 0.0), int(e.get("seq") or 0)))
    for event in ordered:
        status = str(event.get("status") or "").strip().lower()
        # P3.2.3 structured legacy status.
        if status == "failed":
            status = "failed_exception"
        if status in counts:
            counts[status] += 1
        else:
            counts["other"] += 1
    hard = counts["failed_exception"] + counts["timeout"] + counts["device_unavailable"] + counts["other"]
    return {
        "attempts": len(ordered),
        **counts,
        "late_sessions_detached": late_cleanup,
        "hard_failures": hard,
        "legacy_log_estimate": False,
        "events": ordered,
    }


def _process_instrumentation_summary(
    events: list[dict], lineage: dict, log_text: str = ""
) -> dict:
    """Resolve the latest usable instrumentation state for every tracked PID."""
    by_pid: dict[str, dict] = {}

    def ensure(pid, role=None):
        key = str(pid)
        item = by_pid.setdefault(key, {
            "pid": int(pid) if str(pid).isdigit() else pid,
            "role": str(role or "unknown"),
            "status": "not_attempted",
            "source": "lineage",
        })
        if role and item.get("role") in {None, "", "unknown"}:
            item["role"] = str(role)
        return item

    for raw_pid, meta in (lineage or {}).items():
        role = meta.get("role") if isinstance(meta, dict) else None
        item = ensure(raw_pid, role)
        stored = meta.get("frida_process_outcome") if isinstance(meta, dict) else None
        if isinstance(stored, dict) and stored.get("status"):
            item.update(stored)
            item["source"] = "runtime_lineage"

    ordered = sorted(
        [event for event in events if isinstance(event, dict)],
        key=lambda e: (float(e.get("monotonic") or 0.0), int(e.get("seq") or 0)),
    )
    for event in ordered:
        kind = str(event.get("kind") or "")
        if kind not in {
            "frida_attach",
            "frida_script_setup_failed",
            "frida_hooks_partial_ready",
            "frida_hooks_ready",
            "frida_process_outcome",
        } or event.get("pid") is None:
            continue
        item = ensure(event.get("pid"), event.get("role"))
        if kind == "frida_attach":
            status = str(event.get("status") or "")
            if status == "success" and item.get("status") == "not_attempted":
                item.update({
                    "status": "agent_attached_only",
                    "source": "frida_attach",
                    "attach_status": status,
                })
            elif status and item.get("status") == "not_attempted":
                item.update({
                    "status": status,
                    "source": "frida_attach",
                    "attach_status": status,
                })
        elif kind == "frida_script_setup_failed":
            item.update({
                "status": str(event.get("status") or "script_setup_failed"),
                "source": kind,
                "error_type": event.get("error_type"),
                "error": event.get("error"),
                "scripts_loaded": event.get("scripts_loaded", []),
            })
        elif kind == "frida_hooks_partial_ready":
            item.update({
                "status": "fast_hooks_ready",
                "source": kind,
                "scripts_loaded": event.get("scripts_loaded", []),
            })
        elif kind == "frida_hooks_ready":
            item.update({
                "status": "hooks_ready",
                "source": kind,
            })
        elif kind == "frida_process_outcome" and event.get("status"):
            item.update({
                key: value for key, value in event.items()
                if key not in {"schema", "kind", "severity", "wall_time", "monotonic", "run_id", "seq"}
            })
            item["source"] = kind

    # Backward-compatible recovery for P3.2.3.4 logs, which logged setup
    # tracebacks but did not emit a structured terminal setup event.
    for match in SCRIPT_SETUP_FAIL_RE.finditer(log_text or ""):
        item = ensure(match.group(1), match.group(2).lower())
        if item.get("status") in {"hooks_ready", "fast_hooks_ready"}:
            continue
        tail = (log_text or "")[match.start(): match.start() + 3000].lower()
        status = (
            "transport_closed_before_scripts"
            if "connection is closed" in tail
            else "script_setup_failed"
        )
        item.update({
            "status": status,
            "source": "analysis_log_legacy_setup_failure",
        })

    counts = {}
    for item in by_pid.values():
        status = str(item.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    incomplete = []
    for item in by_pid.values():
        role = str(item.get("role") or "")
        status = str(item.get("status") or "")
        if role == "child" and status in READY_FRIDA_STATES | INTENTIONAL_CHILD_STATES:
            continue
        if role == "injected" and status in READY_FRIDA_STATES:
            continue
        if role in {"child", "injected"}:
            incomplete.append(item)
    return {
        "by_pid": by_pid,
        "counts": dict(sorted(counts.items())),
        "incomplete": incomplete,
        "setup_failures": sum(
            1 for item in by_pid.values()
            if item.get("status") in {
                "script_setup_failed",
                "transport_closed_before_scripts",
                "target_exited_during_script_setup",
                "hooks_ready_timeout",
            }
        ),
    }


def _role_axis(process_summary: dict, role: str, pids: list) -> str:
    if not pids:
        return "not_applicable"
    by_pid = process_summary.get("by_pid") or {}
    states = [
        str((by_pid.get(str(pid)) or {}).get("status") or "not_attempted")
        for pid in pids
    ]
    if states and all(state == "hooks_ready" for state in states):
        return "ready"
    if role == "child" and states and all(state in INTENTIONAL_CHILD_STATES for state in states):
        return "capemon_observed"
    if len(states) == 1:
        return states[0]
    if states and all(state in READY_FRIDA_STATES for state in states):
        return "fast_hooks_ready"
    if role == "child" and states and all(
        state in READY_FRIDA_STATES | INTENTIONAL_CHILD_STATES for state in states
    ):
        return "hybrid_observed"
    return "partial"


def build_werfault_diagnostics(
    events: list[dict],
    lineage: dict,
    process_summary: dict,
) -> dict:
    """Assess direct child-Frida involvement without claiming crash causality."""
    observations = [
        event for event in events
        if isinstance(event, dict)
        and event.get("kind") == "descendant_excluded"
        and str(
            event.get("name")
            or re.split(r"[\\/]", str(event.get("exe") or ""))[-1]
        ).lower()
        == "werfault.exe"
    ]
    attach_pids = {
        str(event.get("pid")) for event in events
        if isinstance(event, dict)
        and event.get("kind") in {"frida_attach_start", "frida_attach"}
        and event.get("pid") is not None
    }
    by_pid = process_summary.get("by_pid") if isinstance(process_summary, dict) else {}
    by_pid = by_pid if isinstance(by_pid, dict) else {}
    rows = []
    for event in observations:
        parent_pid = event.get("ppid")
        parent_meta = lineage.get(str(parent_pid)) if isinstance(lineage, dict) else None
        parent_meta = parent_meta if isinstance(parent_meta, dict) else {}
        parent_outcome = by_pid.get(str(parent_pid)) if isinstance(by_pid, dict) else None
        parent_outcome = parent_outcome if isinstance(parent_outcome, dict) else {}
        direct_attach = str(parent_pid) in attach_pids
        rows.append({
            "werfault_pid": event.get("pid"),
            "parent_pid": parent_pid,
            "parent_role": parent_meta.get("role"),
            "parent_process": parent_meta.get("exe"),
            "parent_frida_attach_observed": direct_attach,
            "parent_instrumentation_status": parent_outcome.get("status"),
            "assessment": (
                "child_frida_temporal_association_possible_not_causal"
                if direct_attach else
                "direct_child_frida_cause_not_supported"
            ),
        })

    direct_attach_seen = any(row["parent_frida_attach_observed"] for row in rows)
    if not rows:
        status = "werfault_not_observed"
    elif direct_attach_seen:
        status = "werfault_with_parent_frida_attach_causality_undetermined"
    else:
        status = "werfault_without_parent_frida_attach"
    return {
        "status": status,
        "werfault_observations": len(rows),
        "direct_parent_frida_attach_observed": direct_attach_seen,
        "direct_child_frida_cause_supported": False,
        "root_frida_indirect_effect_excluded": False,
        "sample_or_environment_cause_excluded": False,
        "observations": rows,
        "notes": [
            "WerFault launch is a crash/error-reporting observation, not proof of root cause.",
            "A parent with no Frida attach rules out only a direct attach explanation; root instrumentation, sample behavior, and VM state remain separate hypotheses.",
        ],
    }


def build_analysis_hygiene(chains_result: dict) -> dict:
    chains = chains_result.get("chains") if isinstance(chains_result, dict) else []
    chains = chains if isinstance(chains, list) else []
    gaps = [
        {
            "registry": item.get("registry"),
            "target": item.get("target"),
            "confidence": item.get("confidence"),
            "missing_steps": item.get("missing_steps", []),
        }
        for item in chains
        if isinstance(item, dict)
        and item.get("chain_type") == "persistence_run_key"
        and item.get("materialization_observed") is False
    ]
    return {
        "status": "review_required" if gaps else "no_materialization_gap_observed",
        "clean_snapshot_verified": False,
        "persistence_materialization_gaps": len(gaps),
        "gaps": gaps,
        "recommendation": (
            "Restore a clean VM snapshot and verify each target path and persistence value are absent before rerunning."
            if gaps else
            "Snapshot cleanliness is not proven by behavior telemetry; retain the normal clean-restore procedure."
        ),
        "raw_call_synthesized": False,
    }


def _report_signature_names(report_path: str | None) -> list[str]:
    if not report_path:
        return []
    data = _load_json(Path(report_path))
    sigs = data.get("signatures") if isinstance(data.get("signatures"), list) else []
    out = []
    for sig in sigs:
        if isinstance(sig, dict) and sig.get("name"):
            out.append(str(sig.get("name")))
    return out


def _unique_in_order(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _read_jsonl(path: str | Path | None) -> list[dict]:
    if not path:
        return []
    records = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _record_argument(record: dict, name: str):
    call = record.get("call") if isinstance(record.get("call"), dict) else {}
    wanted = str(name or "").lower()
    for arg in call.get("arguments") or []:
        if isinstance(arg, dict) and str(arg.get("name") or "").lower() == wanted:
            return arg.get("value")
    return None


def detect_behavior_telemetry_gaps(records: list[dict]) -> dict:
    """Find high-value API-chain discontinuities without inventing raw calls.

    P3.2.3.16 checks registry handle continuity. A RegSetValue call
    using a decoded handle that has no observed open/create origin is reported
    as a suspected telemetry gap, especially when the process resolved a
    registry-opening API and immediately closes the same handle. The missing
    call is never synthesized into the raw or clean behavior streams.
    """
    by_pid: dict[int, list[dict]] = {}
    for record in records:
        try:
            pid = int(record.get("pid"))
        except Exception:
            continue
        by_pid.setdefault(pid, []).append(record)

    gaps = []
    open_apis = {"regcreatekeyexa", "regcreatekeyexw", "regopenkeyexa", "regopenkeyexw"}
    native_open_apis = {"ntopenkey", "ntopenkeyex", "ntcreatekey"}
    for pid, items in by_pid.items():
        items.sort(key=lambda r: (
            str(r.get("timestamp") or ""),
            int(r.get("call_id") or 0),
        ))
        active_handles: dict[str, dict] = {}
        resolved = set()
        for index, record in enumerate(items):
            api = str(record.get("api") or "").strip()
            api_lower = api.lower()
            if api_lower == "ldrgetprocedureaddressforcaller":
                value = _record_argument(record, "FunctionName")
                if value:
                    resolved.add(str(value).strip().lower())
                continue

            if api_lower in open_apis:
                handle = _record_argument(record, "Handle")
                if handle is not None:
                    active_handles[str(handle).lower()] = {
                        "api": api,
                        "call_id": record.get("call_id"),
                    }
                continue
            if api_lower in native_open_apis:
                handle = _record_argument(record, "KeyHandle")
                if handle is not None:
                    active_handles[str(handle).lower()] = {
                        "api": api,
                        "call_id": record.get("call_id"),
                    }
                continue
            if api_lower == "regclosekey":
                handle = _record_argument(record, "Handle")
                if handle is not None:
                    active_handles.pop(str(handle).lower(), None)
                continue
            if api_lower not in {"regsetvalueexa", "regsetvalueexw"}:
                continue

            handle = _record_argument(record, "Handle")
            handle_key = str(handle).lower() if handle is not None else ""
            if not handle_key or handle_key in active_handles:
                continue
            full_name = _record_argument(record, "FullName")
            next_record = items[index + 1] if index + 1 < len(items) else {}
            next_same_close = (
                str(next_record.get("api") or "").lower() == "regclosekey"
                and str(_record_argument(next_record, "Handle") or "").lower() == handle_key
            )
            opener_resolved = any(name in resolved for name in open_apis)
            confidence = "high" if full_name and opener_resolved and next_same_close else "medium"
            gaps.append({
                "kind": "registry_handle_origin_missing",
                "pid": pid,
                "process_name": record.get("process_name"),
                "timestamp": record.get("timestamp"),
                "observed_api": api,
                "call_id": record.get("call_id"),
                "handle": handle,
                "full_name": full_name,
                "missing_precursor": "RegCreateKeyEx/RegOpenKeyEx/NtOpenKey",
                "confidence": confidence,
                "evidence": {
                    "opening_api_resolved": opener_resolved,
                    "same_handle_immediately_closed": next_same_close,
                    "decoded_registry_path": bool(full_name),
                },
                "raw_call_synthesized": False,
            })

    return {
        "schema": "capesolo-frida-telemetry-continuity/1.0",
        "status": "suspected_gap" if gaps else "complete_observed",
        "suspected_gaps": len(gaps),
        "high_confidence_gaps": sum(1 for gap in gaps if gap.get("confidence") == "high"),
        "gaps": gaps,
        "notes": [
            "This is a continuity warning, not a synthesized API event.",
            "Raw report.json and behavior.filtered.jsonl remain unchanged.",
        ],
    }


def build_network_observation(analysis_dir: Path, runtime: dict) -> dict:
    """Describe capture/decoding/PID coverage without treating silence as no C2."""
    pcap_runtime = runtime.get("pcap") if isinstance(runtime.get("pcap"), dict) else {}
    current_run = str(runtime.get("run_id") or "")
    runtime_file = _load_json(analysis_dir / "pcap_runtime.json")
    runtime_file_run = str(runtime_file.get("run_id") or "")
    if runtime_file and (not current_run or runtime_file_run == current_run):
        pcap_runtime = {**pcap_runtime, **runtime_file}

    report = _load_json(analysis_dir / "report.json")
    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    capture = network.get("capture") if isinstance(network.get("capture"), dict) else {}
    attribution = network.get("attribution") if isinstance(network.get("attribution"), dict) else {}
    flow_attr = attribution.get("flows") if isinstance(attribution.get("flows"), dict) else {}
    dns_attr = attribution.get("dns") if isinstance(attribution.get("dns"), dict) else {}
    clock_correlation = (
        attribution.get("clock_correlation")
        if isinstance(attribution.get("clock_correlation"), dict)
        else {}
    )

    runtime_status = str(pcap_runtime.get("status") or "").lower()
    pcap_run = str(pcap_runtime.get("run_id") or "")
    capture_bound = (
        not pcap_runtime
        or (
            runtime_status == "complete"
            and bool(pcap_runtime.get("fetched"))
            and (not current_run or pcap_run == current_run)
        )
    )
    capture_path = None
    if capture_bound:
        for candidate in (
            analysis_dir / "dump.pcapng",
            analysis_dir / "dump.pcap",
        ):
            if candidate.is_file() and candidate.stat().st_size >= 24:
                capture_path = candidate
                break

    # Capture-derived rows are usable only when the file is bound and present.
    # Behavior/JS network entries in report.json remain visible separately.
    if capture_path is None:
        capture = {}
        attribution = {}
        flow_attr = {}
        dns_attr = {}

    errors = [str(item) for item in (pcap_runtime.get("errors") or []) if str(item)]
    counts = capture.get("counts") if isinstance(capture.get("counts"), dict) else {}
    protocol_occurrences = (
        capture.get("protocol_occurrences")
        if isinstance(capture.get("protocol_occurrences"), dict)
        else {}
    )
    frames = int(counts.get("frames") or 0)
    packets = int(counts.get("packets") or 0)
    if capture_path is not None:
        capture_status = "empty" if counts and frames == 0 else "complete"
    elif runtime_status in {"start_failed", "stop_failed", "fetch_failed", "client_unavailable"}:
        capture_status = "failed"
    elif runtime_status == "disabled" or pcap_runtime.get("configured") is False:
        capture_status = "disabled"
    else:
        capture_status = "missing"

    total_flows = int(flow_attr.get("total") or 0)
    mapped_flows = int(flow_attr.get("mapped") or 0)
    tracked_flows = int(flow_attr.get("tracked") or 0)
    clock_status = str(clock_correlation.get("status") or "unavailable")
    if capture_status not in {"complete", "empty"}:
        attribution_status = "unavailable"
    elif total_flows == 0:
        attribution_status = "not_applicable"
    elif clock_status == "clock_segmented" and mapped_flows < total_flows:
        attribution_status = "partial_clock_segments"
    elif mapped_flows == total_flows:
        attribution_status = "complete"
    elif mapped_flows > 0:
        attribution_status = "partial"
    elif clock_correlation and not clock_correlation.get("usable"):
        if (
            clock_correlation.get("discontinuity_detected")
            or clock_correlation.get("status") == "clock_discontinuity"
        ):
            attribution_status = "clock_discontinuity"
        else:
            attribution_status = "clock_unsynchronized"
    else:
        attribution_status = "unavailable"

    absence_interpretation = InterpretNetworkAbsence(
        capture_status, frames, packets, total_flows, mapped_flows,
        tracked_flows, clock_correlation,
    )

    decrypted_counts = (
        ((network.get("decrypted") or {}).get("counts") or {})
        if capture_path is not None and isinstance(network.get("decrypted"), dict)
        else {}
    )
    decrypted = network.get("decrypted") if isinstance(network.get("decrypted"), dict) else {}
    decrypt_engine = decrypted.get("engine") if isinstance(decrypted.get("engine"), dict) else {}
    key_material = (
        decrypted.get("key_material")
        if isinstance(decrypted.get("key_material"), dict)
        else {}
    )
    tls_events = int(counts.get("TLS") or 0)
    tls_sessions = int(((capture.get("sessions") or {}).get("total") or 0))
    if int(decrypted_counts.get("https_ex") or 0) > 0:
        tls_visibility = "decrypted"
    elif tls_events or tls_sessions:
        tls_visibility = "metadata_only"
    else:
        tls_visibility = "not_observed"

    return {
        "schema": "capesolo-network-observation/1.3",
        "capture_status": capture_status,
        "pid_attribution_status": attribution_status,
        "tls_visibility": tls_visibility,
        "required": bool(pcap_runtime.get("required")),
        "path": str(capture_path) if capture_path else None,
        "bytes": capture_path.stat().st_size if capture_path else int(pcap_runtime.get("bytes") or 0),
        "sha256": pcap_runtime.get("sha256") or pcap_runtime.get("agent_capture_sha256"),
        "packets": packets,
        "frames": frames,
        "packet_loss": {
            "status": pcap_runtime.get("packet_loss_status") or "unknown",
            "reason": pcap_runtime.get("packet_loss_reason") or "not_reported",
            "captured": pcap_runtime.get("packets_captured"),
            "dropped": pcap_runtime.get("packets_dropped"),
        },
        "event_accounting": {
            "raw_occurrences": int(capture.get("raw_event_occurrences") or 0),
            "display_rows": int(capture.get("display_event_rows") or 0),
        },
        "flows": {
            "total": total_flows,
            "mapped": mapped_flows,
            "high": int(flow_attr.get("high") or 0),
            "medium": int(flow_attr.get("medium") or 0),
            "ambiguous": int(flow_attr.get("ambiguous") or 0),
            "unmapped": int(flow_attr.get("unmapped") or 0),
            "tracked": tracked_flows,
        },
        "dns": {
            "unique_names": len(network.get("dns") or []),
            "request_occurrences": sum(
                int(item.get("count") or 0)
                for item in (network.get("dns") or []) if isinstance(item, dict)
            ),
            "capture_request_occurrences": int(
                dns_attr.get("requests_total", dns_attr.get("total") or 0)
            ),
            "capture_response_occurrences": int(dns_attr.get("responses_total") or 0),
            "requester_mapped": int(dns_attr.get("mapped") or 0),
            "ambiguous": int(dns_attr.get("ambiguous") or 0),
            "unmapped": int(dns_attr.get("unmapped") or 0),
        },
        "http": {
            "unique_requests": len(network.get("http") or []),
            "request_occurrences_all_sources": sum(
                int(item.get("count") or 1)
                for item in (network.get("http") or []) if isinstance(item, dict)
            ),
            "capture_request_occurrences": int(protocol_occurrences.get("http_requests") or 0),
            "capture_response_occurrences": int(protocol_occurrences.get("http_responses") or 0),
            "response_rows_all_sources": len(network.get("http_responses") or []),
            "decrypted_https": int(decrypted_counts.get("https_ex") or 0),
        },
        "tls": {
            "events": tls_events,
            "sessions": tls_sessions,
            "with_keys": int(((capture.get("sessions") or {}).get("with_keys") or 0)),
            "engine": decrypt_engine,
            "key_material": key_material,
            "secret_entries": int(decrypted.get("secrets") or 0),
        },
        "sources": [
            source for source in (network.get("sources") or [])
            if capture_path is not None or source not in {"pcap", "decrypted"}
        ],
        "sysmon": {
            "connect_events": int(attribution.get("sysmon_connect_events") or 0),
            "dns_events": int(attribution.get("sysmon_dns_events") or 0),
        },
        "runtime_status": runtime_status or None,
        "clock_correlation": clock_correlation,
        "errors": errors,
        "absence_interpretation": absence_interpretation,
        "raw_network_events_synthesized": False,
    }


def build_report(analysis_dir: Path, output_dir: Path | None = None) -> dict:
    analysis_dir = analysis_dir.resolve()
    output_dir = (output_dir or analysis_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    runtime_path, runtime = load_runtime_for_analysis(analysis_dir)
    run_version = product_version_for_runtime(runtime)
    run_id = str(runtime.get("run_id") or "").strip() or None

    log_path = analysis_dir / "analysis.log"
    full_log_text = _read_text(log_path)
    log_text, run_scope = select_run_log(full_log_text, runtime)

    events = runtime.get("evidence") if isinstance(runtime.get("evidence"), list) else []
    event_source = "runtime_json"
    if not events:
        events = _recover_p3_events(log_text, run_id=run_id)
        event_source = "analysis_log_run_scope"

    try:
        artifact_result = classify_analysis(
            analysis_dir=analysis_dir,
            output_dir=output_dir,
            runtime=runtime,
        )
    except FileNotFoundError:
        artifact_result = {
            "summary": {"artifacts": 0, "instrumentation": 0, "possible": 0, "retained": 0, "retained_pe": 0},
            "artifacts": [], "instrumentation_ranges": [], "error": "files_manifest_not_found",
        }
    except Exception as exc:
        artifact_result = {
            "summary": {"artifacts": 0, "instrumentation": 0, "possible": 0, "retained": 0, "retained_pe": 0},
            "artifacts": [], "instrumentation_ranges": [], "error": str(exc),
        }

    artifacts = [_artifact_details(item) for item in artifact_result.get("artifacts", [])]
    retained = [item for item in artifacts if not item.get("instrumentation")]
    instrumentation = [item for item in artifacts if item.get("instrumentation")]
    instrumentation_possible = [
        item for item in artifacts
        if item.get("instrumentation_possible") and not item.get("instrumentation")
    ]
    instrumentation_timing_only = [
        item for item in artifacts
        if item.get("instrumentation_possible_timing_only")
        and not item.get("instrumentation")
        and not item.get("instrumentation_possible")
    ]

    try:
        if repair_behavior_pid_ownership is None:
            raise RuntimeError("frida_behavior_pid_repair_not_installed")
        pid_repair_result = repair_behavior_pid_ownership(
            analysis_dir=analysis_dir,
            output_dir=output_dir,
            runtime=runtime,
        )
    except Exception as exc:
        pid_repair_result = {
            "schema": "capesolo-frida-behavior-pid-repair/1.0",
            "version": run_version,
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": str(exc),
            "raw_report_unchanged": True,
        }

    fixed_report = pid_repair_result.get("output_report")
    behavior_report_path = Path(fixed_report) if fixed_report else None

    try:
        behavior_result = classify_behavior(
            analysis_dir=analysis_dir,
            report_json=behavior_report_path,
            output_dir=output_dir,
            runtime=runtime,
            artifact_result=artifact_result,
        )
    except Exception as exc:
        behavior_result = {
            "schema": "capesolo-frida-behavior/3.2.3.14",
            "version": run_version,
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": str(exc),
            "summary": {},
        }

    try:
        compact_result = build_compact_view(
            analysis_dir=analysis_dir,
            output_dir=output_dir,
            runtime=runtime,
        )
    except Exception as exc:
        compact_result = {
            "schema": "capesolo-frida-behavior-compact/3.2.3.14",
            "version": run_version,
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": str(exc),
            "summary": {},
            "api_coverage": {},
        }

    try:
        chains_result = build_behavior_chains(
            analysis_dir=analysis_dir,
            output_dir=output_dir,
        )
    except Exception as exc:
        chains_result = {
            "schema": "capesolo-frida-behavior-chains/3.2.3.14",
            "version": run_version,
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": str(exc),
            "summary": {},
            "chains": [],
        }

    analysis_hygiene = build_analysis_hygiene(chains_result)

    telemetry_continuity = detect_behavior_telemetry_gaps(
        _read_jsonl(behavior_result.get("filtered_jsonl"))
    )
    network_observation = build_network_observation(analysis_dir, runtime)

    resultserver_matches = RESULTSERVER_RE.findall(log_text)
    resultserver_shutdown_warnings = RESULTSERVER_SHUTDOWN_WARNING_RE.findall(log_text)
    if resultserver_matches:
        complete, incomplete = map(int, resultserver_matches[-1])
        if incomplete:
            resultserver_status = "degraded"
        elif resultserver_shutdown_warnings:
            resultserver_status = "complete_with_shutdown_warning"
        else:
            resultserver_status = "complete"
    else:
        complete, incomplete = None, None
        resultserver_status = "unknown"

    duplicate_upload_lines = [
        line for line in log_text.splitlines()
        if (
            "already exists, discarding" in line
            or "Analyzer tried to overwrite an existing file" in line
            or ("Cannot store upload" in line and "already exists" in line)
        )
    ]

    signatures = _unique_in_order(
        list(SIGNATURE_RE.findall(log_text))
        + _report_signature_names(behavior_result.get("source_report"))
    )
    raw_unpacker = "Unpacker" in signatures
    retained_pe_payloads = sum(1 for item in retained if item.get("is_pe"))
    def _artifact_identity(item):
        return str(item.get("sha256") or item.get("resolved_path") or item.get("path") or "")
    retained_unique = {x for x in (_artifact_identity(item) for item in retained) if x}
    retained_pe_unique = {
        _artifact_identity(item) for item in retained
        if item.get("is_pe") and _artifact_identity(item)
    }
    if not raw_unpacker:
        unpacker_confidence = "none"
    elif retained_pe_payloads > 0:
        unpacker_confidence = "high"
    elif instrumentation or instrumentation_possible:
        unpacker_confidence = "low"
    else:
        unpacker_confidence = "medium"

    root_ready = bool(_first_event(events, "root_instrumentation_ready")) or "Root instrumentation ready" in log_text
    gate_events = [
        e for e in events
        if e.get("kind") == "frida_hook_event" and e.get("hook") == "EP_Gate"
    ]
    gate_released = any(
        (e.get("action") == "released")
        or ((e.get("payload") or {}).get("action") == "released")
        for e in gate_events
    ) or "'hook': 'EP_Gate', 'action': 'released'" in log_text

    gate_mode = str(runtime.get("gate_mode") or "none").lower()
    gate_status = "not_applicable" if gate_mode == "none" else ("released" if gate_released else "not_released")
    hooks_ready_events = [e for e in events if e.get("kind") == "frida_hooks_ready"]
    child_promotions = [e for e in events if e.get("kind") == "child_promoted"]
    root_failed = bool(_first_event(events, "root_instrumentation_failed"))
    frida_any_ready = bool(root_ready or hooks_ready_events)
    roles_ready = sorted({str(e.get("role") or "unknown") for e in hooks_ready_events})

    attach_outcomes = _attach_outcome_summary(events, log_text)
    attach_failures = int(attach_outcomes.get("hard_failures") or 0)
    lineage = runtime.get("lineage") if isinstance(runtime.get("lineage"), dict) else {}
    process_instrumentation = _process_instrumentation_summary(events, lineage, log_text)
    crash_diagnostics = build_werfault_diagnostics(
        events, lineage, process_instrumentation
    )
    root_pids = [
        int(pid) if str(pid).isdigit() else pid
        for pid, meta in lineage.items()
        if isinstance(meta, dict) and str(meta.get("role") or "").lower() == "root"
    ]
    child_pids = [
        int(pid) if str(pid).isdigit() else pid
        for pid, meta in lineage.items()
        if isinstance(meta, dict) and str(meta.get("role") or "").lower() == "child"
    ]
    injected_pids = [
        int(pid) if str(pid).isdigit() else pid
        for pid, meta in lineage.items()
        if isinstance(meta, dict) and str(meta.get("role") or "").lower() == "injected"
    ]
    coverage_reasons = [
        "frida_pid_incomplete:{pid}:{status}".format(
            pid=item.get("pid"), status=item.get("status")
        )
        for item in process_instrumentation.get("incomplete", [])
    ]
    if telemetry_continuity.get("high_confidence_gaps"):
        coverage_reasons.append(
            "behavior_telemetry_gap:{count}".format(
                count=telemetry_continuity.get("high_confidence_gaps")
            )
        )
    injection_enrollments = _event_count(events, "injection_enrolled")
    injection_hints = _event_count(events, "injection_hint")
    sysmon_remote_threads = _event_count(events, "sysmon_remote_thread")
    tampering_events = _event_count(events, "sysmon_process_tampering")
    capemon_fallbacks = sum(
        1 for e in events
        if e.get("kind") == "capemon_mapping" and e.get("status") == "fallback"
    )

    rate_cap_lines = [line for line in log_text.splitlines() if API_RATE_CAP_RE.search(line)]
    rate_cap_apis = _unique_in_order([
        m.group(1) for line in rate_cap_lines for m in [API_RATE_CAP_RE.search(line)] if m
    ])

    profile_info = runtime.get("profile") if isinstance(runtime.get("profile"), dict) else {}
    if not profile_info:
        start = _first_event(events, "controller_start") or {}
        profile_info = {
            "request": start.get("profile_request"),
            "selected": start.get("profile_selected"),
            "selection": start.get("profile_selection"),
        }
        if not profile_info.get("selected"):
            m = PROFILE_RE.search(log_text)
            if m:
                profile_info["selected"] = m.group(1)
                profile_info["selection"] = {"source": "analysis_log_run_scope"}

    run_completed = "Run completed" in log_text
    frida_detached = "Detached " in log_text and "Frida session" in log_text

    integrity_reasons = []
    if incomplete not in (None, 0):
        integrity_reasons.append(f"resultserver_incomplete:{incomplete}")
    if duplicate_upload_lines:
        integrity_reasons.append(f"duplicate_uploads:{len(duplicate_upload_lines)}")
    if attach_failures:
        integrity_reasons.append(f"frida_attach_failures:{attach_failures}")
    if not pid_repair_result.get("available", False):
        integrity_reasons.append("behavior_pid_repair_unavailable")
    if (
        network_observation.get("required")
        and network_observation.get("capture_status") not in {"complete", "empty"}
    ):
        integrity_reasons.append(
            "required_network_capture:%s" % network_observation.get("capture_status")
        )

    if not run_completed:
        overall = "partial"
    elif integrity_reasons or coverage_reasons:
        overall = "degraded"
    elif not frida_any_ready:
        # CAPEMON/Sysmon may still have captured a useful run, but the hybrid
        # instrumentation coverage is incomplete. Treat this as degraded rather
        # than partial when the analyzer itself completed.
        overall = "degraded"
    else:
        overall = "complete"

    api_coverage_status = str(
        ((compact_result.get("api_coverage") or {}).get("status"))
        or ("lower_bound" if rate_cap_apis else "full_observed")
    )
    status_axes = {
        "analyzer": "complete" if run_completed else "partial",
        "resultserver": resultserver_status,
        "capemon": "ready" if _event_count(events, "capemon_ready") else ("fallback" if capemon_fallbacks else "unknown"),
        "frida_root": "ready" if (root_ready or "root" in roles_ready) else (
            "failed" if root_failed else _role_axis(process_instrumentation, "root", root_pids)
        ),
        "frida_child": _role_axis(process_instrumentation, "child", child_pids),
        "frida_injected": _role_axis(process_instrumentation, "injected", injected_pids),
        "behavior_integrity": "complete" if (
            pid_repair_result.get("available", False)
            and pid_repair_result.get("ownership_invariant_ok") is True
        ) else "degraded",
        "telemetry_continuity": telemetry_continuity.get("status"),
        "api_coverage": api_coverage_status,
        "network_capture": network_observation.get("capture_status"),
        "network_pid_attribution": network_observation.get("pid_attribution_status"),
        "tls_visibility": network_observation.get("tls_visibility"),
    }

    report = {
        "schema": "capesolo-frida-p3-report/1.2.3.15",
        "version": run_version,
        "processor_version": PRODUCT_VERSION,
        "analysis_dir": str(analysis_dir),
        "status": overall,
        "status_axes": status_axes,
        "run": {
            "run_id": run_id,
            "runtime_path": str(runtime_path) if runtime_path else None,
            "started_wall": runtime.get("run_started_wall"),
            "stopped_wall": runtime.get("run_stopped_wall"),
            "scope": run_scope,
        },
        "profile": profile_info,
        "runtime_evidence": {
            "source": event_source,
            "events": len(events),
            "dropped": runtime.get("evidence_dropped", 0),
            "hook_counts": runtime.get("hook_counts", {}),
        },
        "instrumentation": {
            "root_ready": root_ready,
            "root_failed": root_failed,
            "frida_any_ready": frida_any_ready,
            "roles_ready": roles_ready,
            "gate_mode": gate_mode,
            "gate_status": gate_status,
            "gate_released": gate_released,
            "child_promotions": child_promotions,
            "lifecycle": runtime.get("lifecycle", {}),
            "frida_attach_failures": attach_failures,
            "frida_script_setup_failures": process_instrumentation.get("setup_failures", 0),
            "frida_attach": attach_outcomes,
            "process_outcomes": process_instrumentation,
            "attach_interference_possible": [
                item for item in (process_instrumentation.get("by_pid") or {}).values()
                if item.get("instrumentation_interference_possible") is True
            ],
            "coverage_reasons": coverage_reasons,
            "frida_detached_cleanly": frida_detached,
            "capemon_sync_fallbacks": capemon_fallbacks,
            "sysmon": runtime.get("sysmon", {}),
            "lineage": runtime.get("lineage", {}),
            "excluded_descendants": runtime.get("excluded_descendants", {}),
        },
        "process_enrollment": {
            "injection_hints": injection_hints,
            "sysmon_remote_thread_candidates": sysmon_remote_threads,
            "injection_enrollments": injection_enrollments,
            "validated_in_this_run": injection_enrollments > 0,
        },
        "crash_diagnostics": crash_diagnostics,
        "analysis_hygiene": analysis_hygiene,
        "telemetry": {
            "sysmon_tampering_events": tampering_events,
            "signatures_generated": signatures,
            "unpacker_signature": raw_unpacker,
            "unpacker_evidence": {
                "raw_signature": raw_unpacker,
                "retained_pe_payloads": retained_pe_payloads,
                "confirmed_instrumentation_artifacts": len(instrumentation),
                "possible_instrumentation_artifacts": len(instrumentation_possible),
                "confidence": unpacker_confidence,
            },
            "coverage": {
                "api_rate_cap_detected": bool(rate_cap_apis),
                "disabled_hooks": rate_cap_apis,
                "rate_cap_event_count": len(rate_cap_lines),
                "examples": rate_cap_lines[:10],
                "status": api_coverage_status,
                "framework_only_rate_caps": (
                    (compact_result.get("api_coverage") or {}).get(
                        "framework_only_rate_caps", []
                    )
                ),
            },
        },
        "artifacts": {
            "summary": {
                **(artifact_result.get("summary", {}) or {}),
                "retained_unique": len(retained_unique),
                "retained_pe_unique": len(retained_pe_unique),
                "retained_occurrences": len(retained),
                "retained_pe_occurrences": retained_pe_payloads,
            },
            "instrumentation": instrumentation,
            "instrumentation_possible": instrumentation_possible,
            "instrumentation_timing_only": instrumentation_timing_only,
            "retained": retained,
            "instrumentation_ranges": artifact_result.get("instrumentation_ranges", []),
            "run_scope": artifact_result.get("run_scope"),
            "manifest_scope": artifact_result.get("manifest_scope"),
            "classification_error": artifact_result.get("error"),
        },
        "behavior_pid_repair": {
            "available": pid_repair_result.get("available", False),
            "changed": pid_repair_result.get("changed", False),
            "raw_report_unchanged": pid_repair_result.get("raw_report_unchanged", True),
            "source_report": pid_repair_result.get("source_report"),
            "fixed_report": pid_repair_result.get("output_report"),
            "fixed_report_created": pid_repair_result.get("fixed_report_created", False),
            "summary_path": pid_repair_result.get("summary_path"),
            "raw_call_occurrences": pid_repair_result.get("raw_call_occurrences", 0),
            "repaired_call_occurrences": pid_repair_result.get("repaired_call_occurrences", 0),
            "thread_mismatch_removed": pid_repair_result.get("thread_mismatch_removed", 0),
            "duplicate_call_containers_detected": pid_repair_result.get("duplicate_call_containers_detected", False),
            "ownership_invariant_ok": pid_repair_result.get("ownership_invariant_ok"),
            "per_process": pid_repair_result.get("per_process", []),
            "error": None if pid_repair_result.get("available", False) else pid_repair_result.get("reason"),
        },
        "behavior_provenance": {
            "available": behavior_result.get("available", False),
            "source_report": behavior_result.get("source_report"),
            "summary": behavior_result.get("summary", {}),
            "frida_ranges": behavior_result.get("frida_ranges", []),
            "confirmed_private_ranges": behavior_result.get("confirmed_private_ranges", []),
            "possible_private_ranges": behavior_result.get("possible_private_ranges", []),
            "sample_protected_ranges": behavior_result.get("sample_protected_ranges", []),
            "capemon_ranges": behavior_result.get("capemon_ranges", []),
            "error": None if behavior_result.get("available", False) else behavior_result.get("reason"),
        },
        "behavior_compaction": {
            "available": compact_result.get("available", False),
            "summary": compact_result.get("summary", {}),
            "api_coverage": compact_result.get("api_coverage", {}),
            "compact_jsonl": compact_result.get("compact_jsonl"),
            "error": None if compact_result.get("available", False) else compact_result.get("reason"),
        },
        "behavior_chains": {
            "available": chains_result.get("available", False),
            "summary": chains_result.get("summary", {}),
            "chains": chains_result.get("chains", []),
            "json_path": chains_result.get("json_path"),
            "jsonl_path": chains_result.get("jsonl_path"),
            "error": None if chains_result.get("available", False) else chains_result.get("reason"),
        },
        "telemetry_continuity": telemetry_continuity,
        "network_observation": network_observation,
        "integrity": {
            "resultserver": {
                "status": resultserver_status,
                "complete_transfers": complete,
                "incomplete_transfers": incomplete,
                "shutdown_warning_count": len(resultserver_shutdown_warnings),
            },
            "duplicate_upload_count": len(duplicate_upload_lines),
            "duplicate_upload_examples": duplicate_upload_lines[:10],
            "reasons": integrity_reasons,
            "instrumentation_coverage_reasons": coverage_reasons,
        },
        "notes": [
            "P3.2.3.16 retains P3.2/P3.2.1 run scoping and provenance invariants.",
            "Use a clean analysis output directory between attempts so derived evidence cannot mix across runs.",
            "Retained artifacts are not automatically labeled malicious.",
            "No artifact is downgraded solely because it was dumped near Frida bootstrap time.",
            "Upstream CAPEsolo per-process call ownership is validated; report.behavior_fixed.json is created only as a fallback for an older/accreting report.",
            "Behavior provenance consumes the fixed report plus confirmed private instrumentation ranges and bounded same-thread Frida context.",
            "CAPEMON api-rate-cap events are reported as telemetry coverage warnings; they do not alter raw evidence or automatically change the overall run status.",
            "P3.2.3.16 keeps behavior.compact.jsonl as a presentation-only semantic view; behavior.filtered.jsonl remains lossless and unchanged.",
            "P3.2.3.16 reports missing file materialization without synthesizing CopyFile/CreateFile evidence.",
            "P3.2.3.16 retains generic behavior-chain summaries for persistence, stage hand-off, and conservative injection precursors.",
            "P3.2.3.16 separates Frida agent attach, fast child hooks, CAPEMON-observed short-lived children, and full hooks-ready outcomes per PID.",
            "Adaptive child policy uses active observation time; scheduler/VM stalls are reported separately and do not consume the CAPEMON-exclusive window.",
            "A requested target architecture with failed injector prewarm remains CAPEMON/Sysmon-only instead of receiving a slow cold attach.",
            "P3.2.3.16 preserves target_died_during_optional_attach and reports possible instrumentation interference without claiming causation.",
            "WerFault attribution uses the parent PID's actual attach evidence and never treats temporal proximity as proof of causation.",
            "Registry handle continuity warnings never synthesize missing raw API calls.",
            "Per-API rate-cap coverage marks observed counts as lower bounds instead of treating missing post-cap calls as absence of activity.",
            "Process-injection coverage is only marked validated when an injected target was actually enrolled in this run.",
            "Network absence is only meaningful when network_capture is complete; missing/failed capture is a coverage gap, not proof of no C2.",
            "Flow PID ownership is assigned only from matching Sysmon EID3 evidence; DNS EID22 identifies the requester, not necessarily the UDP wire owner.",
        ],
    }
    return report


def _mirror_derived_files(output_dir: Path, run_id: str | None, paths: list[Path]) -> Path | None:
    if not run_id:
        return None
    run_dir = output_dir / "p3_runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    for path in paths:
        if path.is_file():
            shutil.copy2(path, run_dir / path.name)
    return run_dir


def write_report(report: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "frida_p3_report.json"
    txt_path = output_dir / "frida_p3_report.txt"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    a = report.get("artifacts", {}).get("summary", {})
    rs = report.get("integrity", {}).get("resultserver", {})
    p = report.get("profile", {})
    e = report.get("process_enrollment", {})
    b = report.get("behavior_provenance", {}).get("summary", {})
    bc = report.get("behavior_compaction", {}).get("summary", {})
    api_cov = report.get("behavior_compaction", {}).get("api_coverage", {})
    pr = report.get("behavior_pid_repair", {})
    run = report.get("run", {})
    process_outcomes = report.get("instrumentation", {}).get("process_outcomes", {})
    continuity = report.get("telemetry_continuity", {})
    crashes = report.get("crash_diagnostics", {})
    hygiene = report.get("analysis_hygiene", {})
    network = report.get("network_observation", {})
    lines = [
        f"CAPEsolo + Frida {report.get('version') or PRODUCT_VERSION} summary",
        "===========================",
        f"status: {report.get('status')}",
        "status axes: " + ", ".join(
            f"{name}={value}" for name, value in (report.get("status_axes") or {}).items()
        ),
        f"run_id: {run.get('run_id')}",
        f"mixed analysis.log detected: {(run.get('scope') or {}).get('mixed_log_detected')}",
        f"profile: {p.get('selected') or ((p.get('selection') or {}).get('selected'))}",
        f"root instrumentation ready: {report.get('instrumentation', {}).get('root_ready')}",
        f"gate: mode={report.get('instrumentation', {}).get('gate_mode')} status={report.get('instrumentation', {}).get('gate_status')} released={report.get('instrumentation', {}).get('gate_released')}",
        f"Frida attach: attempts={((report.get('instrumentation', {}).get('frida_attach') or {}).get('attempts', 0))} success={((report.get('instrumentation', {}).get('frida_attach') or {}).get('success', 0))} failed_exception={((report.get('instrumentation', {}).get('frida_attach') or {}).get('failed_exception', 0))} target_died={((report.get('instrumentation', {}).get('frida_attach') or {}).get('target_died', 0))} timeout={((report.get('instrumentation', {}).get('frida_attach') or {}).get('timeout', 0))} device_unavailable={((report.get('instrumentation', {}).get('frida_attach') or {}).get('device_unavailable', 0))}",
        f"Frida process outcomes: counts={process_outcomes.get('counts', {})} setup_failures={report.get('instrumentation', {}).get('frida_script_setup_failures', 0)}",
        f"Telemetry continuity: status={continuity.get('status')} suspected={continuity.get('suspected_gaps', 0)} high_confidence={continuity.get('high_confidence_gaps', 0)}",
        f"Early agent: enabled={((report.get('instrumentation', {}).get('lifecycle') or {}).get('early_agent') or {}).get('enabled', False)} roles={((report.get('instrumentation', {}).get('lifecycle') or {}).get('early_agent') or {}).get('roles', [])}",
        f"Injector prewarm: {((report.get('instrumentation', {}).get('lifecycle') or {}).get('injector_prewarm') or {})}",
        f"artifacts: total={a.get('artifacts', 0)} confirmed_instrumentation={a.get('instrumentation', 0)} timing_only={a.get('timing_only', 0)} malware_candidates={a.get('malware_candidates', 0)} retained_occurrences={a.get('retained_occurrences', a.get('retained', 0))} retained_unique={a.get('retained_unique', 0)} retained_pe_occurrences={a.get('retained_pe_occurrences', a.get('retained_pe', 0))} retained_pe_unique={a.get('retained_pe_unique', 0)}",
        f"PID ownership: available={pr.get('available')} changed={pr.get('changed')} fallback_created={pr.get('fixed_report_created')} raw_occurrences={pr.get('raw_call_occurrences', 0)} repaired_occurrences={pr.get('repaired_call_occurrences', 0)} mismatch_removed={pr.get('thread_mismatch_removed', 0)} invariant_ok={pr.get('ownership_invariant_ok')}",
        f"behavior: total={b.get('calls_total', 0)} framework_removed={b.get('framework_removed_from_clean_view', 0)} clean={b.get('calls_filtered_clean_view', 0)} network_candidates={b.get('network_candidate_calls', 0)} thread_propagated={((b.get('thread_context') or {}).get('propagated_calls', 0))}",
        f"unhook restore bursts: classified_possible={((b.get('unhook_restore_bursts') or {}).get('classified_calls', 0))} bursts={((b.get('unhook_restore_bursts') or {}).get('bursts', 0))}",
        f"behavior run-scope: thread_mismatch_removed={((b.get('run_scoping') or {}).get('thread_mismatch_removed', 0))} outside_time_removed={((b.get('run_scoping') or {}).get('outside_time_scope_removed', 0))}",
        f"semantic behavior: raw_clean={bc.get('raw_clean_calls', 0)} semantic_records={bc.get('semantic_records', 0)} bursts={bc.get('burst_records', 0)} display_saved={bc.get('display_records_saved', 0)} expansion_ok={bc.get('expansion_invariant_ok')}",
        f"behavior chains: persistence={((report.get('behavior_chains', {}).get('summary') or {}).get('persistence_run_key', 0))} injection_precursors={((report.get('behavior_chains', {}).get('summary') or {}).get('injection_precursors', 0))} confirmed_injection={((report.get('behavior_chains', {}).get('summary') or {}).get('confirmed_injection_sequences', 0))} stage_handoffs={((report.get('behavior_chains', {}).get('summary') or {}).get('stage_handoffs', 0))}",
        f"analysis hygiene: status={hygiene.get('status')} persistence_without_materialization={hygiene.get('persistence_materialization_gaps', 0)} clean_snapshot_verified={hygiene.get('clean_snapshot_verified')}",
        f"WerFault diagnostics: status={crashes.get('status')} observations={crashes.get('werfault_observations', 0)} direct_parent_attach={crashes.get('direct_parent_frida_attach_observed')} direct_child_frida_cause_supported={crashes.get('direct_child_frida_cause_supported')}",
        f"injection: hints={e.get('injection_hints', 0)} enrolled={e.get('injection_enrollments', 0)} validated_this_run={e.get('validated_in_this_run')}",
        f"ResultServer: status={rs.get('status')} complete={rs.get('complete_transfers')} incomplete={rs.get('incomplete_transfers')}",
        f"Network capture: status={network.get('capture_status')} packets={network.get('packets', 0)} bytes={network.get('bytes', 0)} path={network.get('path')}",
        f"Network decode: dns_unique={((network.get('dns') or {}).get('unique_names', 0))} dns_queries={((network.get('dns') or {}).get('capture_request_occurrences', 0))} http_unique={((network.get('http') or {}).get('unique_requests', 0))} http_capture_requests={((network.get('http') or {}).get('capture_request_occurrences', 0))} tls_events={((network.get('tls') or {}).get('events', 0))} tls_visibility={network.get('tls_visibility')}",
        f"PCAP loss: status={((network.get('packet_loss') or {}).get('status'))} captured={((network.get('packet_loss') or {}).get('captured'))} dropped={((network.get('packet_loss') or {}).get('dropped'))}",
        f"Network PID map: status={network.get('pid_attribution_status')} flows={((network.get('flows') or {}).get('total', 0))} mapped={((network.get('flows') or {}).get('mapped', 0))} high={((network.get('flows') or {}).get('high', 0))} medium={((network.get('flows') or {}).get('medium', 0))} ambiguous={((network.get('flows') or {}).get('ambiguous', 0))} unmapped={((network.get('flows') or {}).get('unmapped', 0))}",
        f"signatures: {', '.join(report.get('telemetry', {}).get('signatures_generated', [])) or '<not generated / none matched>'}",
        f"unpacker confidence: {report.get('telemetry', {}).get('unpacker_evidence', {}).get('confidence')}",
        f"CAPEMON sync fallbacks: {report.get('instrumentation', {}).get('capemon_sync_fallbacks', 0)}",
    ]
    coverage = report.get("telemetry", {}).get("coverage", {})
    if coverage.get("api_rate_cap_detected"):
        label = (
            "API hook coverage note"
            if coverage.get("status") == "expected_framework_rate_cap"
            else "API hook coverage warning"
        )
        lines.append(label + ": rate-cap disabled " + ", ".join(coverage.get("disabled_hooks", [])))
    capped_by_api = [
        name for name, meta in ((api_cov.get("by_api") or {}).items())
        if isinstance(meta, dict) and meta.get("state") == "rate_capped"
    ]
    if capped_by_api:
        details = []
        for name in capped_by_api:
            meta = (api_cov.get("by_api") or {}).get(name) or {}
            details.append(f"{name}(observed_total={meta.get('observed_total', 0)},clean={meta.get('clean_view_calls', 0)},lower_bound=True)")
        lines.append("per-API coverage: " + "; ".join(details))
    reasons = report.get("integrity", {}).get("reasons", [])
    if reasons:
        lines.append("integrity warnings: " + ", ".join(reasons))
    coverage_reasons = report.get("instrumentation", {}).get("coverage_reasons", [])
    if coverage_reasons:
        lines.append("instrumentation coverage: " + ", ".join(coverage_reasons))
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    derived = [
        json_path, txt_path,
        output_dir / "frida_artifact_classification.json",
        output_dir / "files.filtered.jsonl",
        output_dir / "frida_behavior_pid_repair.json",
        output_dir / "report.behavior_fixed.json",
        output_dir / "frida_behavior_provenance.json",
        output_dir / "behavior.provenance.jsonl",
        output_dir / "behavior.filtered.jsonl",
        output_dir / "frida_behavior_compact.json",
        output_dir / "behavior.compact.jsonl",
        output_dir / "frida_behavior_chains.json",
        output_dir / "behavior.chains.jsonl",
    ]
    _mirror_derived_files(output_dir, (report.get("run") or {}).get("run_id"), derived)
    return json_path, txt_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=detect_default_analysis_dir())
    ap.add_argument("--output-dir", type=Path)
    args = ap.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    output_dir = (args.output_dir or analysis_dir).resolve()
    report = build_report(analysis_dir, output_dir=output_dir)
    json_path, txt_path = write_report(report, output_dir)
    print(f"status={report['status']}")
    print(f"run_id={(report.get('run') or {}).get('run_id')}")
    print(json_path)
    print(txt_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
