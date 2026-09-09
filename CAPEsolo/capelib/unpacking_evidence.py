"""One conservative unpacking policy shared by mapping, scoring and finalization.

This evaluates evidence already collected by P3. It never executes an artifact.
An executable allocation, ordinary PE copy or common import names alone cannot
prove that the sample unpacked a payload. Raw signature records stay unchanged.
"""
from __future__ import annotations
import json
import re
from collections import Counter
from pathlib import Path

SIGNATURES = {"unpacker", "compression", "decryption"}


def _read(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _hash(value):
    text = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return text if re.fullmatch(r"[a-f0-9]{64}", text) else None


def evaluate_unpacking(results, analysis_dir=None, classification=None, runtime=None):
    base = Path(analysis_dir) if analysis_dir else None
    runtime = runtime if runtime is not None else _read(base / "frida_p3_runtime.json") if base else {}
    classification = classification if classification is not None else _read(base / "frida_artifact_classification.json") if base else {}
    run_id = runtime.get("run_id") or (runtime.get("run") or {}).get("run_id")
    stale = bool(run_id and classification.get("run_id") != run_id)
    indexed = {}
    if not stale:
        for row in classification.get("artifacts") or []:
            digest = _hash(row.get("sha256")) or _hash(row.get("path"))
            if digest:
                indexed.setdefault(digest, []).append(row)
    target = results.get("target") or {}
    target = target.get("file") or target
    target_hash = _hash(target.get("sha256"))
    tracked = {str(pid) for pid in runtime.get("lineage", {})}
    rows = {}
    for payload in results.get("payloads") or []:
        for path, meta in payload.items() if isinstance(payload, dict) else []:
            if not isinstance(meta, dict):
                continue
            digest = _hash(meta.get("sha256")) or _hash(path)
            if not digest:
                continue
            rows.setdefault(digest, []).append(meta)
    # The finalizer may be evaluating before payload presentation is written.
    for digest, entries in indexed.items():
        if digest not in rows:
            rows[digest] = entries
    decisions = []
    for digest, metas in rows.items():
        classes = indexed.get(digest, [])
        pids = {str(m.get("pid")) for m in metas if m.get("pid") is not None}
        pids.update(str(p) for m in metas + classes for p in m.get("pids", []) or [])
        types = {str(m.get("cape_type") or "").casefold() for m in metas}
        unpacked_pe = "unpacked pe image" in types or any(m.get("cape_type_code") == 8 for m in classes)
        instrumentation = any(m.get("instrumentation") or m.get("classification") == "instrumentation_confirmed" for m in classes)
        uncertain = any(m.get("instrumentation_possible") or m.get("instrumentation_possible_timing_only") for m in classes)
        pe_verified = any(m.get("is_pe") is True and m.get("pe_validation") == "verified_headers"
                          and m.get("content_sha256") == digest for m in classes)
        content_mismatch = any(m.get("content_sha256") and m["content_sha256"] != digest for m in classes)
        if digest == target_hash:
            reason = "identical_to_input_sample"
        elif instrumentation:
            reason = "instrumentation_confirmed"
        elif stale:
            reason = "artifact_classification_run_mismatch"
        elif not target_hash:
            reason = "target_hash_unavailable"
        elif not classes:
            reason = "artifact_provenance_unavailable"
        elif not pids or not tracked or not pids.intersection(tracked):
            reason = "artifact_lineage_unverified"
        elif uncertain:
            reason = "instrumentation_origin_unresolved"
        elif content_mismatch:
            reason = "artifact_content_hash_mismatch"
        elif unpacked_pe and not pe_verified:
            reason = "unpacked_pe_bytes_unverified"
        elif unpacked_pe and pe_verified:
            reason = "distinct_tracked_unpacked_pe"
        else:
            reason = "unpacking_not_corroborated"
        decisions.append({"sha256": digest, "pids": sorted(pids), "reason": reason,
                          "eligible": reason == "distinct_tracked_unpacked_pe"})
    raw = any(str(s.get("name", "")).lower() in SIGNATURES for s in results.get("signatures") or [])
    eligible = [x for x in decisions if x["eligible"]]
    status = "observed" if raw and eligible else "candidate" if raw else "not_observed"
    return {"schema": "capesolo-unpacking-evidence/1.0", "raw_signature": raw,
            "status": status, "confidence": "high" if status == "observed" else "low" if raw else "none",
            "scoreable": status == "observed", "eligible_payloads": len(eligible),
            "retained_pe_payloads": sum(any(c.get("is_pe") is True and not c.get("instrumentation") for c in indexed.get(h, [])) for h in rows),
            "confirmed_instrumentation_artifacts": sum(x["reason"] == "instrumentation_confirmed" for x in decisions),
            "possible_instrumentation_artifacts": sum(x["reason"] == "instrumentation_origin_unresolved" for x in decisions),
            "reasons": dict(Counter(x["reason"] for x in decisions)), "artifacts": decisions,
            "interpretation": "Distinct unpacked PE with verified headers and content hash, tracked PID and artifact provenance are required for observed unpacking. Older metadata-only PE labels and unclassified shellcode stay candidates; absence is not proved."}


def apply_unpacking_policy(results, analysis_dir=None, classification=None, runtime=None):
    result = evaluate_unpacking(results, analysis_dir, classification, runtime)
    results["unpacking_evidence"] = result
    return result
