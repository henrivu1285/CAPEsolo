#!/usr/bin/env python3
"""Replay historical P3 reports through the P3.2.3.16 Sigma pipeline.

The command intentionally does not execute samples.  It consumes report.json
and, when present, behavior.filtered.jsonl plus P3 runtime artifacts.  A replay
fails if Sigma-only evidence is promoted to observed/attempted or changes the
threat score.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from CAPEsolo.capelib.mitre_attack_v12 import AttackMapper
from CAPEsolo.capelib.threat_assessment import assess_threat
from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION


def _load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _status_counts(mappings: list[dict]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("status") or "unknown") for row in mappings).items()))


def replay_case(report_path: Path) -> dict:
    started = time.monotonic()
    results = _load(report_path)
    original_attack = results.get("mitre_attack") or {}
    attack = AttackMapper(results, report_path.parent).build()
    mappings = [row for row in attack.get("mappings") or [] if isinstance(row, dict)]

    sigma_only = []
    corroborated = []
    invalid_promotions = []
    for row in mappings:
        sources = {str(value) for value in row.get("sources") or []}
        if sources and sources <= {"sigma_rule"}:
            sigma_only.append(str(row.get("id") or ""))
            if row.get("status") != "candidate":
                invalid_promotions.append(str(row.get("id") or ""))
        elif "sigma_rule" in sources:
            corroborated.append(str(row.get("id") or ""))

    scored_results = copy.deepcopy(results)
    scored_results["mitre_attack"] = attack
    score_with_sigma = assess_threat(scored_results)

    without_sigma_only = copy.deepcopy(attack)
    without_sigma_only["mappings"] = [
        row for row in without_sigma_only.get("mappings") or []
        if not ({str(value) for value in row.get("sources") or []} and
                {str(value) for value in row.get("sources") or []} <= {"sigma_rule"})
    ]
    baseline_results = copy.deepcopy(results)
    baseline_results["mitre_attack"] = without_sigma_only
    score_without_sigma_only = assess_threat(baseline_results)

    sigma = attack.get("sigma") or {}
    matches = sigma.get("matches") or []
    previous_mappings = [row for row in original_attack.get("mappings") or [] if isinstance(row, dict)]
    checks = {
        "sigma_pack_available": sigma.get("available") is True,
        "no_sigma_only_promotion": not invalid_promotions,
        "sigma_only_score_neutral": score_with_sigma.get("score") == score_without_sigma_only.get("score"),
        "processor_version": attack.get("processor_version") == PRODUCT_VERSION,
    }
    return {
        "sample": report_path.parent.name,
        "report": report_path.name,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "target": {
            "name": (results.get("target") or {}).get("name"),
            "sha256": (results.get("target") or {}).get("sha256"),
        },
        "previous_attack": {
            "processor_version": original_attack.get("processor_version"),
            "status_counts": _status_counts(previous_mappings),
        },
        "p32316_attack": {
            "status_counts": _status_counts(mappings),
            "sigma_only_candidates": sorted(set(sigma_only)),
            "native_corroborated_by_sigma": sorted(set(corroborated)),
        },
        "sigma": {
            "source": sigma.get("source") or {},
            "telemetry": sigma.get("telemetry") or {},
            "coverage": sigma.get("coverage") or {},
            "rule_matches": len(matches),
            "attack_candidates": len(sigma.get("attack_candidates") or []),
            "matched_rules": [
                {
                    "rule_id": row.get("rule_id"), "title": row.get("title"),
                    "authors": row.get("authors") or [],
                    "attack_ids": row.get("attack_ids") or [],
                    "logsource": (row.get("logsource") or {}).get("category"),
                }
                for row in matches
            ],
        },
        "threat_score": {
            "with_sigma": score_with_sigma.get("score"),
            "without_sigma_only": score_without_sigma_only.get("score"),
            "verdict": score_with_sigma.get("verdict"),
        },
        "checks": checks,
        "passed": all(checks.values()),
        "invalid_sigma_promotions": invalid_promotions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path, help="Directory containing one subdirectory per report corpus")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    reports = sorted(args.corpus.resolve().glob("*/report.json"))
    if not reports:
        parser.error("no */report.json files found")
    cases = []
    for report in reports:
        case = replay_case(report)
        cases.append(case)
        print(
            f"{'PASS' if case['passed'] else 'FAIL'} {case['sample']} "
            f"sigma={case['sigma']['rule_matches']} candidates={case['sigma']['attack_candidates']} "
            f"score={case['threat_score']['with_sigma']} elapsed={case['elapsed_seconds']}s"
        )
    payload = {
        "schema": "capesolo-p32316-sigma-replay/1.0",
        "processor_version": PRODUCT_VERSION,
        "reports": len(cases),
        "passed": sum(case["passed"] for case in cases),
        "failed": sum(not case["passed"] for case in cases),
        "cases": cases,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"RESULT passed={payload['passed']}/{payload['reports']}")
    return 0 if not payload["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
