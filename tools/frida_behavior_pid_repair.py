#!/usr/bin/env python3
"""Repair CAPE behavior call ownership without modifying raw report.json.

Some CAPEsolo report builders expose one global API-call list under every
process container.  The process thread lists remain process-specific, so a call
whose thread is explicitly owned by another process can be removed from the
wrong container with high confidence.

The raw report is immutable evidence. This tool always writes diagnostics and
creates a derived fixed report only when a mismatch is actually found:

* report.behavior_fixed.json       corrected containers (legacy reports only)
* frida_behavior_pid_repair.json   repair diagnostics and invariants

Unknown thread IDs are retained.  Reused/ambiguous thread IDs are also retained
under every declared owner rather than guessed from incomplete evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for search_path in (HERE, PROJECT_ROOT):
    if str(search_path) not in sys.path:
        sys.path.insert(0, str(search_path))

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION, product_version_for_runtime
from p3_run_scope import current_run_pids, load_runtime_for_analysis


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _pid(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tid(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("thread_id", value.get("id"))
    if value is None:
        return ""
    text = str(value).strip()
    try:
        return str(int(text, 0))
    except (TypeError, ValueError):
        return text


def _call_container_digest(calls: list[dict]) -> str:
    payload = json.dumps(calls, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def repair_report(
    report: dict,
    *,
    tracked_pids: set[int] | None = None,
    source_report: str | None = None,
    source_sha256: str | None = None,
    product_version: str = PRODUCT_VERSION,
) -> tuple[dict, dict]:
    """Return a repaired deep copy and a machine-readable diagnostic summary."""
    fixed = copy.deepcopy(report)
    behavior = fixed.get("behavior") if isinstance(fixed.get("behavior"), dict) else {}
    processes = behavior.get("processes") if isinstance(behavior.get("processes"), list) else []
    tracked = set(tracked_pids or set())

    thread_owners: dict[str, set[int]] = defaultdict(set)
    process_threads: dict[int, set[str]] = {}
    digest_groups: dict[str, list[int]] = defaultdict(list)

    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = _pid(proc.get("process_id"))
        if pid is None:
            continue
        tids = {_tid(item) for item in (proc.get("threads") or [])}
        tids.discard("")
        process_threads[pid] = tids
        for tid in tids:
            thread_owners[tid].add(pid)
        calls = proc.get("calls") if isinstance(proc.get("calls"), list) else []
        if calls:
            digest_groups[_call_container_digest(calls)].append(pid)

    duplicate_groups = [
        {"pids": sorted(pids), "call_count": len(next(
            proc.get("calls") for proc in processes
            if isinstance(proc, dict) and _pid(proc.get("process_id")) == pids[0]
        ))}
        for pids in digest_groups.values()
        if len(pids) > 1
    ]

    raw_occurrences = 0
    repaired_occurrences = 0
    mismatch_removed = 0
    unknown_thread_calls = 0
    ambiguous_thread_calls = 0
    per_process = []

    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = _pid(proc.get("process_id"))
        if pid is None:
            continue
        calls = proc.get("calls") if isinstance(proc.get("calls"), list) else []
        raw_count = len(calls)
        raw_occurrences += raw_count
        kept = []
        removed = 0
        unknown = 0
        ambiguous = 0

        for call in calls:
            if not isinstance(call, dict):
                kept.append(call)
                continue
            tid = _tid(call.get("thread_id"))
            owners = thread_owners.get(tid, set()) if tid else set()
            if not owners:
                # No strong ownership evidence: preserve the call.
                unknown += 1
                kept.append(call)
                continue
            if len(owners) > 1:
                ambiguous += 1
            if pid not in owners:
                removed += 1
                continue
            kept.append(call)

        proc["calls"] = kept
        repaired_count = len(kept)
        repaired_occurrences += repaired_count
        mismatch_removed += removed
        unknown_thread_calls += unknown
        ambiguous_thread_calls += ambiguous
        per_process.append({
            "pid": pid,
            "process_name": proc.get("process_name"),
            "tracked_current_run": not tracked or pid in tracked,
            "declared_threads": len(process_threads.get(pid, set())),
            "raw_call_occurrences": raw_count,
            "repaired_call_occurrences": repaired_count,
            "thread_mismatch_removed": removed,
            "unknown_thread_calls_retained": unknown,
            "ambiguous_thread_calls_retained": ambiguous,
        })

    invariant_violations = 0
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = _pid(proc.get("process_id"))
        if pid is None:
            continue
        for call in proc.get("calls") or []:
            if not isinstance(call, dict):
                continue
            owners = thread_owners.get(_tid(call.get("thread_id")), set())
            if owners and pid not in owners:
                invariant_violations += 1

    summary = {
        "schema": "capesolo-frida-behavior-pid-repair/1.0",
        "version": str(product_version or PRODUCT_VERSION),
        "processor_version": PRODUCT_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "available": True,
        "source_report": source_report,
        "source_sha256": source_sha256,
        "raw_report_unchanged": True,
        "changed": mismatch_removed > 0,
        "raw_call_occurrences": raw_occurrences,
        "repaired_call_occurrences": repaired_occurrences,
        "thread_mismatch_removed": mismatch_removed,
        "unknown_thread_calls_retained": unknown_thread_calls,
        "ambiguous_thread_calls_retained": ambiguous_thread_calls,
        "thread_owner_entries": len(thread_owners),
        "duplicate_call_container_groups": duplicate_groups,
        "duplicate_call_containers_detected": bool(duplicate_groups),
        "ownership_invariant_ok": invariant_violations == 0,
        "ownership_invariant_violations": invariant_violations,
        "tracked_pids": sorted(tracked),
        "per_process": per_process,
        "notes": [
            "Calls are removed only when their thread ID is explicitly owned by another process.",
            "Unknown and ambiguous/reused thread IDs are retained conservatively.",
            "The upstream CAPEsolo report is used directly when ownership is already correct.",
            "A derived fixed report is created only for an older/accreting report; raw report.json remains evidence.",
        ],
    }
    fixed["frida_p3_behavior_pid_repair"] = {
        key: value for key, value in summary.items()
        if key not in {"per_process", "notes"}
    }
    return fixed, summary


def repair_behavior_pid_ownership(
    analysis_dir: Path,
    report_json: Path | None = None,
    output_dir: Path | None = None,
    runtime: dict | None = None,
) -> dict:
    analysis_dir = Path(analysis_dir).resolve()
    output_dir = Path(output_dir or analysis_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(report_json).resolve() if report_json else analysis_dir / "report.json"
    summary_path = output_dir / "frida_behavior_pid_repair.json"
    fixed_path = output_dir / "report.behavior_fixed.json"
    if runtime is None:
        _, runtime = load_runtime_for_analysis(analysis_dir)
    product_version = product_version_for_runtime(runtime)

    if not report_path.is_file():
        result = {
            "schema": "capesolo-frida-behavior-pid-repair/1.0",
            "version": product_version,
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": "cape_report_json_not_found",
            "source_report": str(report_path),
            "raw_report_unchanged": True,
        }
        summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        return result

    report = _load_json(report_path)
    if not report:
        result = {
            "schema": "capesolo-frida-behavior-pid-repair/1.0",
            "version": product_version,
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": "cape_report_json_invalid",
            "source_report": str(report_path),
            "raw_report_unchanged": True,
        }
        summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        return result

    fixed, result = repair_report(
        report,
        tracked_pids=current_run_pids(runtime or {}),
        source_report=str(report_path),
        source_sha256=_sha256(report_path),
        product_version=product_version,
    )
    if result.get("changed"):
        fixed_path.write_text(json.dumps(fixed, indent=2, ensure_ascii=False), encoding="utf-8")
        result["output_report"] = str(fixed_path)
        result["fixed_report_created"] = True
        result["output_sha256"] = _sha256(fixed_path)
    else:
        # CAPEsolo main already materializes each ParseProcessLog independently.
        # Do not create a second copy of a report whose ownership invariant is valid.
        result["output_report"] = str(report_path)
        result["fixed_report_created"] = False
        result["output_sha256"] = result.get("source_sha256")
    result["summary_path"] = str(summary_path)
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-dir", type=Path, default=Path("."))
    parser.add_argument("--report-json", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    result = repair_behavior_pid_ownership(
        args.analysis_dir,
        report_json=args.report_json,
        output_dir=args.output_dir,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("available") else 2


if __name__ == "__main__":
    raise SystemExit(main())
