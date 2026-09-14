"""Deterministic CAPEsolo result archives for analyst review or full forensics."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION


REVIEW_FILES = (
    "evtx/evtx.zip",
    "evtx_collection.json",
    "evtx_events.jsonl",
    "service_processes.json",
    "analysis.log",
    "report.json",
    "report.html",
    "mitre_attack.json",
    "car_analysis.json",
    "sigma_coverage.json",
    "rule_coverage.json",
    "analysis_quality.json",
    "behavior.snapshot.json",
    "capa_execution.json",
    "report_refresh.json",
    "capa_analysis.json",
    "capa_dynamic_sources.json",
    "capa_dynamic_input.json",
    "capa_dynamic_raw.json",
    "capa_dynamic_raw.cache.json",
    "behavior.provenance.jsonl",
    "frida_behavior_provenance.json",
    "frida_behavior_chains.json",
    "p3_current_run.json",
    "p32318_validation.json",
    "p32319_validation.json",
    "frida_p3_report.json",
    "frida_p3_report.txt",
    "frida_p3_runtime.json",
    "pcap_runtime.json",
    "dump.pcapng",
    "dump.pcap",
    "hashes.json",
    "frida_artifact_classification.json",
    "files.filtered.jsonl",
    "behavior.filtered.jsonl",
    "behavior.compact.jsonl",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_evidence(analysis_dir: Path) -> dict:
    """Audit what the report actually references; never regenerate evidence."""
    base = Path(analysis_dir).resolve()
    required = {"report.json", "behavior.filtered.jsonl", "behavior.snapshot.json"}
    expected = {}
    errors = []
    try:
        report = json.loads((base / "report.json").read_text(encoding="utf-8"))
        capa = report.get("capa") or {}
        if (base / "capa_analysis.json").is_file():
            capa = json.loads((base / "capa_analysis.json").read_text(encoding="utf-8"))
        dynamic = capa.get("dynamic") or {}
        if dynamic.get("status") == "ok":
            required.update({"capa_analysis.json", "capa_execution.json", "capa_dynamic_input.json",
                             "capa_dynamic_sources.json", "capa_dynamic_raw.json"})
            for name, key in (("behavior.filtered.jsonl", "clean_sha256"),
                              ("capa_dynamic_input.json", "input_sha256"),
                              ("capa_dynamic_raw.json", "raw_sha256")):
                if dynamic.get(key): expected[name] = dynamic[key]
        for item in (capa.get("static") or {}).get("files") or []:
            if item.get("status") == "ok" and item.get("raw_result"):
                name = item["raw_result"]
                if Path(name).name != name or "\\" in name or ":" in name:
                    errors.append("invalid_static_result_reference")
                    continue
                required.add(name)
                if item.get("raw_sha256"): expected[name] = item["raw_sha256"]
        service = report.get("service_processes") or {}
        if service:
            required.add("service_processes.json")
            for name, value in (service.get("source_sha256") or {}).items():
                if name not in {"evtx_collection.json", "evtx_events.jsonl", "behavior.filtered.jsonl", "frida_p3_runtime.json"}:
                    errors.append("invalid_service_evidence_reference")
                    continue
                required.add(name); expected[name] = value
        if (base / "evtx_collection.json").is_file():
            required.update({"evtx_collection.json", "evtx_events.jsonl", "evtx/evtx.zip"})
        if (report.get("mitre_attack") or {}).get("car"):
            required.add("car_analysis.json")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        errors.append("report_metadata_unreadable:" + type(exc).__name__)
    missing = sorted(name for name in required if not (base / name).is_file())
    mismatches = sorted(name for name, digest in expected.items()
                        if (base / name).is_file() and _sha256(base / name) != digest)
    return {"status": "complete" if not (missing or mismatches or errors) else "partial",
            "required_files": sorted(required), "missing_required_files": missing,
            "hash_mismatches": mismatches, "errors": errors,
            "meaning": "Export completeness of referenced reports, not completeness of malware behavior or retained binary payloads."}


def select_result_files(analysis_dir: Path, mode: str) -> list[Path]:
    analysis_dir = Path(analysis_dir).resolve()
    mode = str(mode or "").strip().lower()
    if mode not in {"review", "full"}:
        raise ValueError("mode must be 'review' or 'full'")
    if not analysis_dir.is_dir():
        raise FileNotFoundError(f"analysis directory not found: {analysis_dir}")

    if mode == "review":
        selected = [analysis_dir / name for name in REVIEW_FILES if (analysis_dir / name).is_file()]
        selected.extend(sorted(analysis_dir.glob("capa_static_*_raw*.json")))
        return selected
    return sorted((p for p in analysis_dir.rglob("*") if p.is_file()), key=lambda p: p.as_posix().lower())


def build_result_archive(analysis_dir: Path, destination: Path, mode: str = "review") -> tuple[Path, dict]:
    """Create one archive without changing the analysis evidence directory."""
    analysis_dir = Path(analysis_dir).resolve()
    destination = Path(destination).resolve()
    if destination.suffix.lower() != ".zip":
        destination = destination.with_suffix(".zip")
    destination.parent.mkdir(parents=True, exist_ok=True)

    files = [p for p in select_result_files(analysis_dir, mode) if p.resolve() != destination]
    if not files:
        raise FileNotFoundError(f"no {mode} result files found in {analysis_dir}")

    entries = []
    for path in files:
        relative = path.relative_to(analysis_dir).as_posix()
        entries.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)})
    manifest = {
        "schema": "capesolo-result-archive/1.0",
        "version": PRODUCT_VERSION,
        "mode": mode,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_dir": str(analysis_dir),
        "file_count": len(entries),
        "missing_review_files": [name for name in REVIEW_FILES if not (analysis_dir / name).is_file()] if mode == "review" else [],
        "files": entries,
        "evidence_audit": audit_evidence(analysis_dir),
    }

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("P3239_RESULT_MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        archive.writestr("P3_RESULT_MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        for path, item in zip(files, entries):
            archive.write(path, item["path"])
    return destination, manifest
