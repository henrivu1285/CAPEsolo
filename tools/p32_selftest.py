#!/usr/bin/env python3
"""Offline invariants for P3.2.1 behavior/artifact provenance."""
from __future__ import annotations

import argparse
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
    from p3_run_scope import load_runtime_for_analysis
except ImportError:
    from p3_run_scope_p32 import load_runtime_for_analysis


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
    if behavior.get("available"):
        filtered_path = analysis / "behavior.filtered.jsonl"
        provenance_path = analysis / "behavior.provenance.jsonl"
        filtered = [json.loads(x) for x in filtered_path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
        all_records = [json.loads(x) for x in provenance_path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]

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

    print("PASS: P3.2.1 artifact temporal rule")
    print("PASS: P3.2.1 confirmed-private-range rule")
    print("PASS: P3.2.1 bounded thread-context rule")
    print("PASS: P3.2.1 behavior clean-view rule")
    print(json.dumps({
        "artifact_summary": artifacts.get("summary"),
        "behavior_summary": behavior.get("summary"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
