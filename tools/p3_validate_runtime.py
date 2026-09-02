#!/usr/bin/env python3
"""Validate P3.2.3.14 runtime coverage after a sandbox run.

Read-only validator. It does not create processes, inject code, or modify
CAPEsolo evidence. Use it after a normal malware run or a separately controlled
lab injection test to verify lifecycle/enrollment behavior.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION
from CAPEsolo.capelib.network_pid import load_clock_sync
from CAPEsolo.capelib.network_decrypt import Unavailable as tls_decryption_unavailable


def load_runtime(analysis_dir: Path) -> dict:
    direct = analysis_dir / "frida_p3_runtime.json"
    if direct.is_file():
        return json.loads(direct.read_text(encoding="utf-8", errors="replace"))
    marker = analysis_dir / "p3_current_run.json"
    if marker.is_file():
        m = json.loads(marker.read_text(encoding="utf-8", errors="replace"))
        rid = str(m.get("run_id") or "")
        candidate = analysis_dir / "p3_runs" / rid / "frida_p3_runtime.json"
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
    raise FileNotFoundError("frida_p3_runtime.json not found")


def summarize(runtime: dict) -> dict:
    events = runtime.get("evidence") if isinstance(runtime.get("evidence"), list) else []
    lineage = runtime.get("lineage") if isinstance(runtime.get("lineage"), dict) else {}
    by_kind = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        k = str(event.get("kind") or "<none>")
        by_kind[k] = by_kind.get(k, 0) + 1
    roles = {}
    for pid, meta in lineage.items():
        if not isinstance(meta, dict):
            continue
        role = str(meta.get("role") or "unknown")
        roles.setdefault(role, []).append(int(pid) if str(pid).isdigit() else pid)
    hooks_ready = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "frida_hooks_ready"
    ]
    promoted = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "child_promoted"
    ]
    enrolled = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "injection_enrolled"
    ]
    attach_events = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "frida_attach"
    ]
    attach_counts = {}
    for e in attach_events:
        status = str(e.get("status") or "unknown")
        attach_counts[status] = attach_counts.get(status, 0) + 1
    helper_seen = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "frida_helper_seen"
    ]
    helper_extensions = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "frida_attach_helper_extension"
    ]
    child_policy_events = [
        e for e in events
        if isinstance(e, dict) and e.get("kind") == "child_attach_policy"
    ]
    process_outcomes = {}
    for pid, meta in lineage.items():
        if not isinstance(meta, dict):
            continue
        outcome = meta.get("frida_process_outcome")
        if isinstance(outcome, dict):
            process_outcomes[str(pid)] = outcome
    for event in events:
        if not isinstance(event, dict) or event.get("kind") != "frida_process_outcome":
            continue
        process_outcomes[str(event.get("pid"))] = {
            key: value for key, value in event.items()
            if key not in {"schema", "kind", "severity", "wall_time", "monotonic", "run_id", "seq"}
        }
    outcome_counts = {}
    for outcome in process_outcomes.values():
        status = str(outcome.get("status") or "unknown")
        outcome_counts[status] = outcome_counts.get(status, 0) + 1
    interference_possible = [
        outcome for outcome in process_outcomes.values()
        if outcome.get("instrumentation_interference_possible") is True
    ]
    return {
        "validator_version": PRODUCT_VERSION,
        "version": runtime.get("version"),
        "run_id": runtime.get("run_id"),
        "profile": (runtime.get("profile") or {}).get("selected") if isinstance(runtime.get("profile"), dict) else None,
        "roles": roles,
        "frida_hooks_ready": len(hooks_ready),
        "ready_roles": sorted({str(e.get("role") or "unknown") for e in hooks_ready}),
        "child_promotions": len(promoted),
        "injection_hints": by_kind.get("injection_hint", 0),
        "sysmon_remote_threads": by_kind.get("sysmon_remote_thread", 0),
        "injection_enrollments": len(enrolled),
        "injected_role_pids": roles.get("injected", []),
        "root_failed": by_kind.get("root_instrumentation_failed", 0) > 0,
        "capemon_ready_events": by_kind.get("capemon_ready", 0),
        "frida_device": ((runtime.get("lifecycle") or {}).get("frida_device", {})),
        "early_agent": ((runtime.get("lifecycle") or {}).get("early_agent", {})),
        "child_attach": ((runtime.get("lifecycle") or {}).get("child_attach", {})),
        "injector_prewarm": ((runtime.get("lifecycle") or {}).get("injector_prewarm", {})),
        "frida_attach_outcomes": attach_counts,
        "frida_process_outcomes": process_outcomes,
        "frida_process_outcome_counts": outcome_counts,
        "attach_interference_possible": interference_possible,
        "frida_script_setup_failures": by_kind.get("frida_script_setup_failed", 0),
        "frida_helper_seen": len(helper_seen),
        "frida_helper_extensions": len(helper_extensions),
        "child_attach_policy_events": child_policy_events,
        "capemon_observed_children": sum(
            count for status, count in outcome_counts.items()
            if status in {
                "capemon_only_policy",
                "capemon_observed_short_lived",
                "capemon_observed_prewarm_unavailable",
            }
        ),
        "result_storage_preflight": runtime.get("result_storage_preflight", {}),
    }


def summarize_network(analysis_dir: Path) -> dict:
    def load(name):
        path = analysis_dir / name
        if not path.is_file():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return {}
        return value if isinstance(value, dict) else {}

    pcap = load("pcap_runtime.json")
    report = load("report.json")
    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    attribution = network.get("attribution") if isinstance(network.get("attribution"), dict) else {}
    capture = network.get("capture") if isinstance(network.get("capture"), dict) else {}
    decrypted = network.get("decrypted") if isinstance(network.get("decrypted"), dict) else {}
    tls_reason = tls_decryption_unavailable()
    return {
        "capture_status": pcap.get("status") or "missing",
        "capture_fetched": bool(pcap.get("fetched")),
        "capture_bytes": int(pcap.get("bytes") or 0),
        "packet_loss": {
            "status": pcap.get("packet_loss_status") or "unknown",
            "reason": pcap.get("packet_loss_reason") or "not_reported",
            "captured": pcap.get("packets_captured"),
            "dropped": pcap.get("packets_dropped"),
        },
        "clock_sync": load_clock_sync(analysis_dir),
        "flows": attribution.get("flows") or {},
        "dns_requesters": attribution.get("dns") or {},
        "traffic_classification": network.get("traffic_classification") or {},
        "event_accounting": {
            "raw_occurrences": int(capture.get("raw_event_occurrences") or 0),
            "display_rows": int(capture.get("display_event_rows") or 0),
        },
        "http_requests_unique": len(network.get("http") or []),
        "http_requests": len(network.get("http") or []),
        "http_request_occurrences": sum(
            int(item.get("count") or 1)
            for item in (network.get("http") or []) if isinstance(item, dict)
        ),
        "capture_protocol_occurrences": capture.get("protocol_occurrences") or {},
        "http_responses": len(network.get("http_responses") or []),
        "tls_events": len(network.get("tls") or []),
        "tls_decryption": {
            "engine_ready": not bool(tls_reason),
            "preflight_reason": tls_reason or "ready",
            "runtime": decrypted,
        },
        "raw_network_events_synthesized": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=Path(r"C:\Users\Public\CAPEsolo\analysis"))
    ap.add_argument("--expect-enrollment", action="store_true", help="fail unless at least one role=injected enrollment is present")
    ap.add_argument("--expect-frida-role", choices=["root", "child", "injected"], action="append", default=[])
    args = ap.parse_args()

    runtime = load_runtime(args.analysis_dir.resolve())
    result = summarize(runtime)
    result["network"] = summarize_network(args.analysis_dir.resolve())
    print(json.dumps(result, indent=2, ensure_ascii=False))

    failures = []
    if args.expect_enrollment and not result["injection_enrollments"]:
        failures.append("expected injection enrollment but none was recorded")
    if args.expect_enrollment and not result["injected_role_pids"]:
        failures.append("injection enrollment expected but lineage has no role=injected PID")
    for role in args.expect_frida_role:
        if role not in result["ready_roles"]:
            failures.append(f"expected Frida hooks ready for role={role}")
    if failures:
        for failure in failures:
            print("FAIL:", failure)
        return 2
    print("PASS runtime validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
