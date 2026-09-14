"""Bind immutable clean evidence to a run and its raw/presentation behavior.

Hashes establish consistency, not acquisition completeness or authenticity.
An old, already redacted run is explicitly labelled historical_redacted.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path

REVISION = "p32319"
MANIFEST = "behavior.snapshot.json"


def digest_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def behavior_digest(results):
    return hashlib.sha256(json.dumps(results.get("behavior") or {}, ensure_ascii=False,
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def identity(results, runtime):
    target = results.get("target") or {}
    target = target.get("file") or target
    return {"run_id": runtime.get("run_id") or (runtime.get("run") or {}).get("run_id"),
            "target_sha256": str(target.get("sha256") or "").lower()}


def is_redacted(results):
    return bool(results.get("report_redaction")) or any(
        a.get("redacted") is True
        for p in (results.get("behavior") or {}).get("processes") or []
        for c in p.get("calls") or [] for a in c.get("arguments") or [] if isinstance(a, dict))


def validate_calls(results, clean):
    """Allow only the exact clipboard presentation transform, never arbitrary edits."""
    from CAPEsolo.capelib.report_redaction import redact_report_in_place
    originals = {}
    for p in (results.get("behavior") or {}).get("processes") or []:
        for c in p.get("calls") or []:
            key = (int(p["process_id"]), str(c.get("id")))
            if key in originals:
                raise ValueError("snapshot_duplicate_original_call_identity")
            originals[key] = c
    seen = set()
    with Path(clean).open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            key = (int(row["pid"]), str(row["call"].get("id")))
            if key in seen or key not in originals:
                raise ValueError("snapshot_call_identity_mismatch_%d" % n)
            seen.add(key)
            call = row["call"]
            if call == originals[key]:
                continue
            sample = {"behavior": {"processes": [{"calls": [copy.deepcopy(call)]}]}}
            redact_report_in_place(sample)
            if sample["behavior"]["processes"][0]["calls"][0] != originals[key]:
                raise ValueError("snapshot_call_content_mismatch_%d" % n)


def validate_snapshot(base, results, runtime):
    base = Path(base)
    path = base / MANIFEST
    if not path.is_file():
        return None
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("identity") != identity(results, runtime):
        raise ValueError("snapshot_run_or_target_mismatch")
    if behavior_digest(results) not in {manifest.get("source_behavior_sha256"), manifest.get("presentation_behavior_sha256")}:
        raise ValueError("snapshot_source_behavior_mismatch")
    for name, expected in manifest.get("files", {}).items():
        if name not in {"behavior.filtered.jsonl", "behavior.provenance.jsonl"}:
            raise ValueError("snapshot_unexpected_file")
        if not (base / name).is_file() or digest_file(base / name) != expected:
            raise ValueError("snapshot_file_hash_mismatch:" + name)
    if "behavior.filtered.jsonl" not in manifest.get("files", {}):
        raise ValueError("snapshot_clean_hash_missing")
    return manifest


def commit_snapshot(base, results, runtime, origin="acquisition_before_redaction"):
    from CAPEsolo.capelib.capa_integration import atomic_json
    from CAPEsolo.capelib.report_redaction import redact_report_in_place
    base = Path(base)
    existing = validate_snapshot(base, results, runtime) if (base / MANIFEST).is_file() else None
    if existing:
        return existing
    validate_calls(results, base / "behavior.filtered.jsonl")
    presented = {"behavior": copy.deepcopy(results.get("behavior") or {})}
    redact_report_in_place(presented)
    manifest = {"schema": "capesolo-behavior-snapshot/1.0", "processor_revision": REVISION,
                "identity": identity(results, runtime), "origin": "historical_redacted" if is_redacted(results) else origin,
                "source_behavior_sha256": behavior_digest(results),
                "presentation_behavior_sha256": behavior_digest(presented),
                "files": {name: digest_file(base / name) for name in
                          ("behavior.filtered.jsonl", "behavior.provenance.jsonl") if (base / name).is_file()},
                "interpretation": "Byte consistency only; not proof of clean VM, complete telemetry, or original pre-redaction recovery."}
    atomic_json(base / MANIFEST, manifest)
    return manifest


def preserve_existing(base, results, runtime):
    """Return a verified existing snapshot; refuse to overwrite redacted history."""
    base = Path(base)
    path = base / MANIFEST
    if path.is_file():
        previous = json.loads(path.read_text(encoding="utf-8"))
        old = previous.get("identity") or {}
        current = identity(results, runtime)
        if old.get("run_id") and current["run_id"] and old["run_id"] != current["run_id"] and not is_redacted(results):
            # A fresh acquisition may reuse analysis/. Preserve the previous
            # snapshot first; never treat a new target in the SAME run as valid.
            archive = base / "snapshot_history" / digest_file(path)
            for name, digest in previous.get("files", {}).items():
                if name not in {"behavior.filtered.jsonl", "behavior.provenance.jsonl"}:
                    raise ValueError("snapshot_unexpected_file")
                source = base / name
                if source.is_file() and digest_file(source) != digest:
                    raise ValueError("previous_snapshot_hash_mismatch:" + name)
            archive.mkdir(parents=True, exist_ok=True)
            for name in previous.get("files", {}):
                if (base / name).is_file():
                    shutil.copy2(base / name, archive / name)
            os.replace(path, archive / MANIFEST)
            return None
    existing = validate_snapshot(base, results, runtime)
    if existing:
        return existing
    if is_redacted(results) and (base / "behavior.filtered.jsonl").is_file():
        return commit_snapshot(base, results, runtime, "historical_import")
    return None
