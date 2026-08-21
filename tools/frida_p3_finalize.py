#!/usr/bin/env python3
"""Build the P3.2.2 summary for the current CAPEsolo attempt.

P3.2.2 keeps the validated P3.2.1 provenance layer and adds a separate semantic
compact view plus per-API coverage accounting. Raw CAPEsolo evidence and the
lossless behavior.filtered.jsonl clean view remain unchanged.
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
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from frida_artifact_filter import classify_analysis
except ImportError:
    from frida_artifact_filter_p32 import classify_analysis
try:
    from frida_behavior_provenance import classify_behavior
except ImportError:
    from frida_behavior_provenance_p321 import classify_behavior
try:
    from frida_behavior_compact import build_compact_view
except ImportError:
    from frida_behavior_compact_p322 import build_compact_view
try:
    from p3_run_scope import load_runtime_for_analysis, select_run_log
except ImportError:
    from p3_run_scope_p32 import load_runtime_for_analysis, select_run_log

P3_EVIDENCE_RE = re.compile(r"\[P3Evidence\]\s+(\{.*\})\s*$")
RESULTSERVER_RE = re.compile(r"ResultServer transfers complete=(\d+) incomplete=(\d+)")
SIGNATURE_RE = re.compile(r'Analysis matched signature \"([^\"]+)\"')
PROFILE_RE = re.compile(r'FridaMuncher.*(?:P3(?:\.\d+)?|v11 P2\.1 Hybrid Optimized) config:.*?profile=([^ ]+)')
ATTACH_FAIL_RE = re.compile(r"Frida attach attempt \d+ failed|Could not attach Frida", re.I)
API_RATE_CAP_RE = re.compile(r"api-rate-cap:\s+([A-Za-z0-9_]+)\s+hook disabled due to rate", re.I)


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


def build_report(analysis_dir: Path, output_dir: Path | None = None) -> dict:
    analysis_dir = analysis_dir.resolve()
    output_dir = (output_dir or analysis_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    runtime_path, runtime = load_runtime_for_analysis(analysis_dir)
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

    try:
        behavior_result = classify_behavior(
            analysis_dir=analysis_dir,
            output_dir=output_dir,
            runtime=runtime,
            artifact_result=artifact_result,
        )
    except Exception as exc:
        behavior_result = {
            "schema": "capesolo-frida-behavior/3.2.1",
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
            "schema": "capesolo-frida-behavior-compact/3.2.2",
            "available": False,
            "reason": str(exc),
            "summary": {},
            "api_coverage": {},
        }

    resultserver_matches = RESULTSERVER_RE.findall(log_text)
    if resultserver_matches:
        complete, incomplete = map(int, resultserver_matches[-1])
        resultserver_status = "complete" if incomplete == 0 else "degraded"
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

    attach_failures = len(ATTACH_FAIL_RE.findall(log_text))
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

    if not run_completed:
        overall = "partial"
    elif not root_ready:
        overall = "partial"
    elif integrity_reasons:
        overall = "degraded"
    else:
        overall = "complete"

    report = {
        "schema": "capesolo-frida-p3-report/1.2.2",
        "version": "P3.2.2",
        "analysis_dir": str(analysis_dir),
        "status": overall,
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
            "gate_released": gate_released,
            "frida_attach_failures": attach_failures,
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
                "status": "degraded" if rate_cap_apis else "full_observed",
            },
        },
        "artifacts": {
            "summary": artifact_result.get("summary", {}),
            "instrumentation": instrumentation,
            "instrumentation_possible": instrumentation_possible,
            "retained": retained,
            "instrumentation_ranges": artifact_result.get("instrumentation_ranges", []),
            "run_scope": artifact_result.get("run_scope"),
            "manifest_scope": artifact_result.get("manifest_scope"),
            "classification_error": artifact_result.get("error"),
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
        "integrity": {
            "resultserver": {
                "status": resultserver_status,
                "complete_transfers": complete,
                "incomplete_transfers": incomplete,
            },
            "duplicate_upload_count": len(duplicate_upload_lines),
            "duplicate_upload_examples": duplicate_upload_lines[:10],
            "reasons": integrity_reasons,
        },
        "notes": [
            "P3.2.2 retains P3.2/P3.2.1 run scoping and provenance invariants.",
            "Raw CAPEsolo files remain shared unless the analysis directory is archived/cleaned between attempts.",
            "Retained artifacts are not automatically labeled malicious.",
            "PE payloads are not downgraded solely because they were dumped near Frida bootstrap time.",
            "Behavior provenance also consumes confirmed private instrumentation artifact ranges and bounded same-thread Frida context; raw CAPE report.json is untouched.",
            "CAPEMON api-rate-cap events are reported as telemetry coverage warnings; they do not alter raw evidence or automatically change the overall run status.",
            "P3.2.2 adds behavior.compact.jsonl as a presentation-only semantic view; behavior.filtered.jsonl remains lossless and unchanged.",
            "Per-API rate-cap coverage marks observed counts as lower bounds instead of treating missing post-cap calls as absence of activity.",
            "Process-injection coverage is only marked validated when an injected target was actually enrolled in this run.",
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
    run = report.get("run", {})
    lines = [
        "CAPEsolo + Frida P3.2.2 summary",
        "===========================",
        f"status: {report.get('status')}",
        f"run_id: {run.get('run_id')}",
        f"mixed analysis.log detected: {(run.get('scope') or {}).get('mixed_log_detected')}",
        f"profile: {p.get('selected') or ((p.get('selection') or {}).get('selected'))}",
        f"root instrumentation ready: {report.get('instrumentation', {}).get('root_ready')}",
        f"gate released: {report.get('instrumentation', {}).get('gate_released')}",
        f"artifacts: total={a.get('artifacts', 0)} instrumentation={a.get('instrumentation', 0)} possible={a.get('possible', 0)} retained={a.get('retained', 0)} retained_pe={a.get('retained_pe', 0)}",
        f"behavior: total={b.get('calls_total', 0)} framework_removed={b.get('framework_removed_from_clean_view', 0)} clean={b.get('calls_filtered_clean_view', 0)} network_candidates={b.get('network_candidate_calls', 0)} thread_propagated={((b.get('thread_context') or {}).get('propagated_calls', 0))}",
        f"semantic behavior: raw_clean={bc.get('raw_clean_calls', 0)} semantic_records={bc.get('semantic_records', 0)} bursts={bc.get('burst_records', 0)} display_saved={bc.get('display_records_saved', 0)} expansion_ok={bc.get('expansion_invariant_ok')}",
        f"injection: hints={e.get('injection_hints', 0)} enrolled={e.get('injection_enrollments', 0)} validated_this_run={e.get('validated_in_this_run')}",
        f"ResultServer: status={rs.get('status')} complete={rs.get('complete_transfers')} incomplete={rs.get('incomplete_transfers')}",
        f"signatures: {', '.join(report.get('telemetry', {}).get('signatures_generated', [])) or '<not generated / none matched>'}",
        f"unpacker confidence: {report.get('telemetry', {}).get('unpacker_evidence', {}).get('confidence')}",
        f"CAPEMON sync fallbacks: {report.get('instrumentation', {}).get('capemon_sync_fallbacks', 0)}",
    ]
    coverage = report.get("telemetry", {}).get("coverage", {})
    if coverage.get("api_rate_cap_detected"):
        lines.append("API hook coverage warning: rate-cap disabled " + ", ".join(coverage.get("disabled_hooks", [])))
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
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    derived = [
        json_path, txt_path,
        output_dir / "frida_artifact_classification.json",
        output_dir / "files.filtered.jsonl",
        output_dir / "frida_behavior_provenance.json",
        output_dir / "behavior.provenance.jsonl",
        output_dir / "behavior.filtered.jsonl",
        output_dir / "frida_behavior_compact.json",
        output_dir / "behavior.compact.jsonl",
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
