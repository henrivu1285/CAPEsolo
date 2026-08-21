#!/usr/bin/env python3
"""Offline invariants for P3.2.2 semantic behavior compaction."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

try:
    from frida_artifact_filter import classify_analysis
except ImportError:
    from frida_artifact_filter_p32 import classify_analysis
try:
    from frida_behavior_provenance import classify_behavior, parse_address, _in_range, THREAD_PROPAGATABLE_APIS
except ImportError:
    from frida_behavior_provenance_p321 import classify_behavior, parse_address, _in_range, THREAD_PROPAGATABLE_APIS
try:
    from frida_behavior_compact import build_compact_view, COMPACTABLE_APIS, COMPACT_MIN_GROUP_COUNT
except ImportError:
    from frida_behavior_compact_p322 import build_compact_view, COMPACTABLE_APIS, COMPACT_MIN_GROUP_COUNT
try:
    from p3_run_scope import load_runtime_for_analysis
except ImportError:
    from p3_run_scope_p32 import load_runtime_for_analysis


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, required=True)
    args = ap.parse_args()
    analysis = args.analysis_dir.resolve()
    _, runtime = load_runtime_for_analysis(analysis)

    artifacts = classify_analysis(analysis, output_dir=analysis, runtime=runtime)
    bad_pe = [
        a for a in artifacts.get("artifacts", [])
        if a.get("is_pe") and a.get("instrumentation_possible")
        and not a.get("instrumentation") and not a.get("reasons")
    ]
    if bad_pe:
        raise SystemExit(f"FAIL: temporal-only PE marked possible instrumentation: {len(bad_pe)}")

    behavior = classify_behavior(analysis, output_dir=analysis, runtime=runtime, artifact_result=artifacts)
    if not behavior.get("available"):
        raise SystemExit(f"FAIL: behavior provenance unavailable: {behavior.get('reason')}")

    filtered_path = analysis / "behavior.filtered.jsonl"
    provenance_path = analysis / "behavior.provenance.jsonl"
    filtered = _load_jsonl(filtered_path)
    all_records = _load_jsonl(provenance_path)

    for n, rec in enumerate(filtered, 1):
        if rec.get("provenance") in {"framework_frida", "framework_capemon"}:
            raise SystemExit(f"FAIL: framework call leaked into filtered behavior at line {n}")

    confirmed = behavior.get("confirmed_private_ranges") or []
    for n, rec in enumerate(filtered, 1):
        call = rec.get("call") if isinstance(rec.get("call"), dict) else {}
        for field in ("caller", "parentcaller"):
            addr = parse_address(call.get(field))
            if _in_range(addr, confirmed) is not None:
                raise SystemExit(f"FAIL: confirmed private instrumentation range leaked at filtered line {n} ({field})")

    propagated = [
        rec for rec in all_records
        if any(r.get("kind") == "frida_thread_context" for r in rec.get("reasons", []))
    ]
    for rec in propagated:
        if str(rec.get("api") or "").lower() not in THREAD_PROPAGATABLE_APIS:
            raise SystemExit(f"FAIL: non-plumbing API propagated by thread context: {rec.get('api')}")
        if not rec.get("filter_from_clean_view") or rec.get("provenance") != "framework_frida":
            raise SystemExit("FAIL: propagated Frida call not filtered")

    before_hash = _sha256(filtered_path)
    compact_result = build_compact_view(analysis, output_dir=analysis, runtime=runtime)
    after_hash = _sha256(filtered_path)
    if before_hash != after_hash:
        raise SystemExit("FAIL: behavior.filtered.jsonl changed during semantic compaction")
    if not compact_result.get("available"):
        raise SystemExit(f"FAIL: compact behavior unavailable: {compact_result.get('reason')}")

    compact = _load_jsonl(analysis / "behavior.compact.jsonl")
    expanded = sum(int(r.get("count") or 0) for r in compact)
    if expanded != len(filtered):
        raise SystemExit(f"FAIL: compact expansion mismatch: expanded={expanded} filtered={len(filtered)}")

    for n, rec in enumerate(compact, 1):
        if rec.get("record_type") != "burst":
            continue
        if str(rec.get("api") or "").lower() not in COMPACTABLE_APIS:
            raise SystemExit(f"FAIL: non-compactable API burst at line {n}: {rec.get('api')}")
        if int(rec.get("count") or 0) < COMPACT_MIN_GROUP_COUNT:
            raise SystemExit(f"FAIL: undersized burst at line {n}: count={rec.get('count')}")
        if rec.get("provenance") in {"framework_frida", "framework_capemon"}:
            raise SystemExit(f"FAIL: framework call present in compact clean view at line {n}")

    coverage = compact_result.get("api_coverage") or {}
    for api in coverage.get("disabled_hooks", []):
        meta = (coverage.get("by_api") or {}).get(api) or {}
        if meta.get("state") != "rate_capped" or meta.get("count_semantics") != "lower_bound":
            raise SystemExit(f"FAIL: rate-capped API lacks lower-bound semantics: {api}")

    summary = compact_result.get("summary") or {}
    if not summary.get("expansion_invariant_ok"):
        raise SystemExit("FAIL: compact expansion invariant not marked true")

    print("PASS: P3.2.2 P3.2.1 provenance invariants")
    print("PASS: P3.2.2 clean-view immutability")
    print("PASS: P3.2.2 semantic expansion invariant")
    print("PASS: P3.2.2 conservative burst eligibility")
    print("PASS: P3.2.2 per-API rate-cap lower-bound semantics")
    print(json.dumps({
        "artifact_summary": artifacts.get("summary"),
        "behavior_summary": behavior.get("summary"),
        "compact_summary": compact_result.get("summary"),
        "api_coverage": compact_result.get("api_coverage"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
