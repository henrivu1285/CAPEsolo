"""Deterministic, evidence-weighted threat assessment for P3.2.3.16.

The score is a triage aid, not a probability and not an antivirus verdict.  It
uses unique ATT&CK technique families, completed state machines, signatures and
family/config detections.  Every category is capped so repeated API calls or
duplicate parent/sub-technique mappings cannot inflate the result.
"""
from __future__ import annotations

import re
from typing import Any

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION

SCHEMA = "capesolo-threat-assessment/1.0"
SCORE_VERSION = "p32316-evidence-v3"
THRESHOLDS = {
    "benign": {"minimum": 0, "maximum": 19},
    "suspicious": {"minimum": 20, "maximum": 59},
    "malicious": {"minimum": 60, "maximum": 100},
}

# Higher-risk behaviors receive more weight. Discovery and generic evasion
# checks intentionally contribute little on their own because legitimate
# software commonly performs them.
TECHNIQUE_WEIGHTS = {
    "T1003": 24, "T1055": 20, "T1056": 10, "T1071": 12, "T1095": 12,
    "T1105": 16, "T1547": 16, "T1543": 15, "T1053": 14, "T1573": 12,
    "T1685": 12, "T1070": 8, "T1140": 9, "T1027": 8, "T1112": 6,
    "T1036": 5, "T1518": 4, "T1057": 3, "T1012": 2, "T1622": 5,
    "T1497": 4, "T1082": 3, "T1016": 3, "T1083": 2, "T1113": 8,
    "T1614": 2,
}
TACTIC_DEFAULTS = {
    "impact": 16, "credential-access": 15, "exfiltration": 14,
    "command-and-control": 12, "lateral-movement": 12,
    "persistence": 10, "privilege-escalation": 10,
    "defense-impairment": 9, "defense-evasion": 8, "stealth": 8,
    "collection": 7, "execution": 6, "discovery": 3,
}
STATUS_FACTORS = {"observed": 1.0, "candidate": 0.25, "attempted": 0.15}
CONFIDENCE_FACTORS = {"high": 1.0, "medium": 0.85, "low": 0.6}


def _bounded_int(value: Any, minimum: int = 0, maximum: int = 100) -> int:
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return minimum


def _technique_base(mapping: dict) -> int:
    technique_id = str(mapping.get("id") or "")
    family = technique_id.split(".", 1)[0]
    if family in TECHNIQUE_WEIGHTS:
        return TECHNIQUE_WEIGHTS[family]
    return max((TACTIC_DEFAULTS.get(str(tactic), 4) for tactic in mapping.get("tactics") or []), default=4)


def _attack_component(attack: dict) -> dict:
    # Keep only the strongest member of a technique family (e.g. T1055 and
    # T1055.004) so parent/sub-technique duplication cannot double-score.
    strongest: dict[str, dict] = {}
    for mapping in attack.get("mappings") or []:
        if not isinstance(mapping, dict) or mapping.get("status") not in STATUS_FACTORS:
            continue
        # Sigma-only mappings deliberately remain review candidates and must
        # not inflate the maliciousness score.  When a native detector also
        # supports the same mapping, normal scoring still applies.
        sources = {str(value) for value in mapping.get("sources") or []}
        if mapping.get("status") == "candidate" and sources and sources <= {"sigma_rule"}:
            continue
        family = str(mapping.get("id") or "").split(".", 1)[0]
        raw = _technique_base(mapping)
        points = round(raw * STATUS_FACTORS[mapping["status"]] * CONFIDENCE_FACTORS.get(str(mapping.get("confidence") or "low"), 0.6))
        signal = {
            "id": mapping.get("id"), "name": mapping.get("name"),
            "status": mapping.get("status"), "confidence": mapping.get("confidence"),
            "points": max(1, points), "rule_ids": list(mapping.get("rule_ids") or []),
        }
        previous = strongest.get(family)
        if previous is None or (signal["points"], str(signal["id"])) > (previous["points"], str(previous["id"])):
            strongest[family] = signal
    signals = sorted(strongest.values(), key=lambda row: (-row["points"], str(row.get("id"))))
    return {"category": "mitre_attack", "points": min(65, sum(row["points"] for row in signals)), "cap": 65, "signals": signals}


def _state_component(attack: dict) -> dict:
    signals = []
    seen = set()
    for state in attack.get("state_machine_evaluations") or []:
        if not isinstance(state, dict) or state.get("complete") is not True or state.get("scoreable") is False:
            continue
        rule_id = str(state.get("rule_id") or "")
        if not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)
        points = 4 if any(token in rule_id for token in ("injection", "credential", "persistence")) else 2
        signals.append({"rule_id": rule_id, "points": points, "state_trace": list(state.get("state_trace") or [])})
    signals.sort(key=lambda row: (-row["points"], row["rule_id"]))
    return {"category": "validated_state_machines", "points": min(12, sum(row["points"] for row in signals)), "cap": 12, "signals": signals}


def _signature_component(results: dict) -> dict:
    signals = []
    seen = set()
    for signature in results.get("signatures") or []:
        if not isinstance(signature, dict):
            continue
        name = str(signature.get("name") or signature.get("description") or "unnamed")
        key = name.lower()
        # Multi-engine reputation is scored separately as an independent,
        # high-strength source rather than as an ordinary behavior signature.
        if key.startswith("antivirus_"):
            continue
        if key in seen:
            continue
        seen.add(key)
        severity = _bounded_int(signature.get("severity"), 0, 5)
        base = {0: 0, 1: 2, 2: 4, 3: 7, 4: 9, 5: 10}.get(severity, 0)
        try:
            confidence = float(signature.get("confidence") if signature.get("confidence") is not None else 100)
        except (TypeError, ValueError):
            confidence = 100.0
        points = round(base * max(0.25, min(1.0, confidence / 100.0)))
        if points:
            signals.append({"name": name, "severity": severity, "confidence": round(confidence, 1), "points": max(1, points)})
    signals.sort(key=lambda row: (-row["points"], row["name"].lower()))
    return {"category": "behavior_signatures", "points": min(13, sum(row["points"] for row in signals)), "cap": 13, "signals": signals}


def _reputation_component(results: dict) -> dict:
    providers = []
    for signature in results.get("signatures") or []:
        if not isinstance(signature, dict):
            continue
        name = str(signature.get("name") or "")
        description = str(signature.get("description") or "")
        if not name.lower().startswith("antivirus_"):
            continue
        counts = [int(value) for value in re.findall(r"\b\d+\b", description)]
        engines = max(counts, default=0)
        points = 60 if engines >= 10 else 40 if engines >= 3 else 20
        providers.append({"name": name, "engines": engines, "strength": points, "description": description[:240]})
    providers.sort(key=lambda row: (-row["strength"], -row["engines"], row["name"]))
    points = providers[0]["strength"] if providers else 0
    signals = []
    if providers:
        signals.append({
            "name": "multi-engine antivirus reputation", "points": points,
            "engines": max(row["engines"] for row in providers),
            "providers": [row["name"] for row in providers],
        })
    return {"category": "external_reputation", "points": points, "cap": 60, "signals": signals}


def _detection_component(results: dict) -> dict:
    names = sorted({str(value).strip() for value in results.get("detections") or [] if str(value).strip()})
    signals = [{"name": name, "points": 8 if index == 0 else 2} for index, name in enumerate(names)]
    return {"category": "family_or_config_detections", "points": min(10, sum(row["points"] for row in signals)), "cap": 10, "signals": signals}


def _quality(attack: dict) -> dict:
    coverage = attack.get("coverage") or {}
    behavior = coverage.get("behavior") or {}
    network = coverage.get("network") or {}
    checks = {
        "behavior_available": behavior.get("available") is True,
        "clean_behavior_available": bool(behavior.get("clean_calls")) and behavior.get("source") != "raw_behavior_fallback",
        "attack_evidence_available": bool(attack.get("mappings")),
        "signature_pipeline_ran": isinstance(coverage.get("signatures"), dict),
        "network_capture_complete": network.get("capture_status") == "complete",
        "network_pid_attribution_usable": network.get("clock_usable") is True,
    }
    quality_points = sum((2, 2, 1, 1, 1, 1)[index] for index, value in enumerate(checks.values()) if value)
    confidence = "high" if quality_points >= 6 else "medium" if quality_points >= 3 else "low"
    limitations = [str(row.get("code")) for row in attack.get("coverage_warnings") or [] if isinstance(row, dict) and row.get("code")]
    return {"confidence": confidence, "quality_points": quality_points, "checks": checks, "limitations": limitations}


def assess_threat(results: dict) -> dict:
    """Return an auditable 0-100 risk score and a cautious verdict label."""
    attack = results.get("mitre_attack") or {}
    components = [
        _attack_component(attack), _state_component(attack),
        _signature_component(results), _detection_component(results),
        _reputation_component(results),
    ]
    uncapped_score = sum(component["points"] for component in components)
    score = min(100, uncapped_score)
    quality = _quality(attack)
    threshold_verdict = "malicious" if score >= 60 else "suspicious" if score >= 20 else "benign"
    verdict = threshold_verdict
    provisional = False
    if threshold_verdict == "benign":
        provisional = True
        # A low score with missing behavior is absence of telemetry, not benign
        # evidence. Keep the numeric score but refuse a benign classification.
        if not quality["checks"]["behavior_available"]:
            verdict = "inconclusive"

    reasons = []
    for component in components:
        for signal in component["signals"][:3]:
            label = signal.get("id") or signal.get("rule_id") or signal.get("name")
            reasons.append({"category": component["category"], "signal": label, "points": signal.get("points")})
    reasons.sort(key=lambda row: (-int(row.get("points") or 0), str(row.get("signal") or "")))

    return {
        "schema": SCHEMA, "score_version": SCORE_VERSION, "processor_version": PRODUCT_VERSION,
        "score": score, "uncapped_score": uncapped_score, "maximum_score": 100, "verdict": verdict,
        "threshold_verdict": threshold_verdict, "confidence": quality["confidence"],
        "provisional": provisional, "thresholds": THRESHOLDS,
        "components": components, "top_reasons": reasons[:8],
        "quality": quality,
        "interpretation": (
            "The score measures observed risk evidence, not the probability that a file is malware. "
            "A benign label is provisional and means no stronger malicious behavior was observed under the available sensors."
        ),
    }


__all__ = ["SCHEMA", "SCORE_VERSION", "THRESHOLDS", "assess_threat"]
