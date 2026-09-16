"""Acquisition completeness is separate from positive detection evidence."""
from __future__ import annotations
import json
import re
from pathlib import Path
from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION, PROCESSOR_REVISION as REVISION
from CAPEsolo.capelib.evidence_snapshot import validate_snapshot


def read_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def collect_quality(results, analysis_dir, finalizer=None):
    base = Path(analysis_dir)
    runtime = read_json(base / "frida_p3_runtime.json")
    final = finalizer if finalizer is not None else read_json(base / "frida_p3_report.json")
    # A stale finalizer must not describe another run's acquisition.
    runtime_id = runtime.get("run_id") or (runtime.get("run") or {}).get("run_id")
    final_id = (final.get("run") or {}).get("run_id")
    stale = bool(runtime_id and final_id and runtime_id != final_id)
    if stale:
        final = {}
    axes = dict(final.get("status_axes") or {})
    api = (final.get("telemetry") or {}).get("coverage") or {}
    hooks = set(api.get("disabled_hooks") or [])
    background = api.get("background_rate_caps") or []
    pid_caps = api.get("by_pid_api") or {}
    try:
        from tools.p3_run_scope import select_run_log
        log_path = base / "analysis.log"
        if runtime_id and log_path.is_file():
            scoped, scope = select_run_log(log_path.read_text(encoding="utf-8", errors="replace"), runtime)
            if scope.get("selected"):
                from CAPEsolo.capelib.telemetry_coverage import rate_cap_events
                from tools.p3_run_scope import current_run_pids
                events = rate_cap_events(scoped, current_run_pids(runtime))
                # Recompute old finalizers' globally aggregated hook lists.
                hooks = {e["api"] for e in events if e["scope"] != "background"}
                background = [e for e in events if e["scope"] == "background"]
    except (ImportError, OSError, ValueError):
        pass
    if not final:
        # Only use this log when it is scoped by a run-specific directory.
        axes.setdefault("api_coverage", "unknown")
    network = final.get("network_observation") or {}
    clean = base / "behavior.filtered.jsonl"
    clean_count = 0
    if clean.is_file():
        with clean.open(encoding="utf-8") as f:
            clean_count = sum(bool(line.strip()) for line in f)
    limitations = []
    from CAPEsolo.capelib.service_processes import attach_service_processes
    try:
        service = attach_service_processes(results, base)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        service = {"status": "failed", "links": [], "limitations": ["service_correlation_failed:"+type(exc).__name__]}
        results["service_processes"] = service
    if service.get("links") or service.get("unresolved_services") or service.get("status") in {"partial", "failed"}:
        limitations.extend(service.get("limitations", []))
        axes["service_process_coverage"] = "partial" if service.get("status") in {"partial", "failed"} else "complete"
    if service.get("evtx_status") in {"partial", "invalid"} or (service.get("evtx_status") == "unavailable" and service.get("evtx_expected")):
        axes["evtx_export"] = "degraded"
        limitations.append("evtx_export_"+service["evtx_status"])

    tracking = runtime.get("service_tracking") or {}
    if tracking.get("enabled"):
        axes["service_realtime"] = "active" if tracking.get("security_ever_active") else "degraded"
        if not tracking.get("security_ever_active"):
            limitations.append("service_realtime_security_unavailable")
        if tracking.get("events_dropped"):
            axes["service_realtime"] = "partial"
            limitations.append("service_realtime_events_dropped")
        if any(v.get("error") for v in (tracking.get("subscriptions") or {}).values() if isinstance(v, dict)):
            axes["service_realtime"] = "partial"
            limitations.append("service_realtime_subscription_error")
        if any(m.get("capemon_request") in {"failed", "unknown", "identity_mismatch"} for m in (runtime.get("lineage") or {}).values() if isinstance(m, dict)):
            limitations.append("related_process_monitor_not_confirmed")
    harmful_hooks = hooks - set(api.get("framework_only_rate_caps") or [])
    if harmful_hooks or (not hooks and api.get("api_rate_cap_detected") and not background):
        limitations.append("api_rate_capped_counts_are_lower_bounds")
        axes["api_coverage"] = "degraded"
    if stale:
        limitations.append("finalizer_run_id_mismatch")
    if not final:
        limitations.append("finalizer_quality_unavailable")
    if not clean_count:
        limitations.append("clean_behavior_missing_or_empty")
    if "target_pid" in runtime and not runtime.get("target_pid") and not runtime.get("lineage"):
        limitations.append("target_lineage_unresolved")
        axes["target_attribution"] = "degraded"
    if axes.get("frida_child") in {"partial", "capemon_only", "capemon_observed_prewarm_unavailable"}:
        limitations.append("frida_child_partial_capemon_may_still_be_present")
    pcap = read_json(base / "pcap_runtime.json")
    if axes.get("network_capture") == "failed" or pcap.get("status") == "start_failed":
        limitations.append("pcap_capture_failed")
    if axes.get("resultserver") in {"degraded", "failed", "incomplete"}:
        limitations.append("resultserver_incomplete_transfers")
    if (network.get("packet_loss") or {}).get("status") == "unknown" and axes.get("network_capture") != "failed":
        limitations.append("pcap_drop_count_unknown")
    if (network.get("flows") or {}).get("tracked") == 0 and axes.get("network_capture") != "failed":
        limitations.append("no_pcap_flow_attributed_to_tracked_processes")
    clock = network.get("clock_correlation") or {}
    if clock.get("status") == "clock_slew_compensated":
        limitations.append("clock_slew_compensated")
    if axes.get("network_pid_attribution") in {"partial", "unavailable", "failed"}:
        limitations.append("network_pid_attribution_incomplete")
    snapshot_status, snapshot_origin = "unavailable", "unknown"
    try:
        snapshot = validate_snapshot(base, results, runtime)
        if snapshot:
            snapshot_status, snapshot_origin = "consistent", snapshot["origin"]
            if snapshot_origin == "historical_redacted":
                limitations.append("historical_redacted_source_original_bytes_unavailable")
        capa_clean = ((results.get("capa") or {}).get("dynamic") or {}).get("clean_sha256")
        if capa_clean and clean.is_file():
            from CAPEsolo.capelib.evidence_snapshot import digest_file
            if digest_file(clean) != capa_clean:
                snapshot_status = "capa_source_mismatch"
                limitations.append("capa_clean_hash_mismatch")
    except (OSError, ValueError, KeyError) as exc:
        snapshot_status = "mismatch"
        limitations.append(str(exc))
    if snapshot_status in {"mismatch", "capa_source_mismatch"}:
        axes["evidence_consistency"] = "degraded"
    degraded = any(v in {"partial", "degraded", "failed", "incomplete", "capemon_only", "capemon_observed_prewarm_unavailable", "partial_clock_segments"} for v in axes.values())
    required = ("analyzer", "resultserver", "behavior_integrity", "api_coverage")
    complete = all(axes.get(k) in {"complete", "ready", "full_observed", "expected_framework_rate_cap"} for k in required) and bool(clean_count)
    status = "degraded" if degraded else "complete" if complete else "unknown"
    return {
        "schema": "capesolo-analysis-quality/1.1", "processor_version": PRODUCT_VERSION, "processor_revision": REVISION,
        "acquisition_version": runtime.get("version") or final.get("version") or "unknown",
        "run_id": runtime_id or final_id, "status": status,
        "coverage_confidence": "high" if status == "complete" and not limitations else "limited" if status in {"complete", "degraded"} else "unknown",
        "status_axes": axes, "clean_api_records": clean_count,
        "disabled_hooks": sorted(hooks), "limitations": limitations,
        "background_rate_caps": background, "by_pid_api": pid_caps,
        "evidence_consistency": {"status": snapshot_status, "origin": snapshot_origin},
        "network": {"flows": network.get("flows", {}), "packet_loss": network.get("packet_loss", {}), "clock_status": clock.get("status", "unknown"),
                    "capture_status": pcap.get("status", axes.get("network_capture")), "capture_errors": pcap.get("errors", []),
                    "clock_offset_span_seconds": clock.get("offset_span_seconds"),
                    "clock_compensation_is_not_stability": True},
        "service_processes": service,
        "unpacking_evidence": results.get("unpacking_evidence") or {},
        "clean_snapshot_verified": False,
        "interpretation": "Collection completion does not imply complete API coverage. Missing capability matches cannot establish absence of behavior. Sigma EventID projections do not establish Sysmon configuration.",
    }
