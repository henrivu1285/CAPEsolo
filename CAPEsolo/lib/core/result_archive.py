"""Deterministic CAPEsolo result archives for analyst review or full forensics."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION


REVIEW_FILES = (
    "analysis.log",
    "report.json",
    "report.html",
    "mitre_attack.json",
    "analysis_quality.json",
    "behavior.snapshot.json",
    "capa_execution.json",
    "report_refresh.json",
    "capa_analysis.json",
    "capa_dynamic_sources.json",
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


def select_result_files(analysis_dir: Path, mode: str) -> list[Path]:
    analysis_dir = Path(analysis_dir).resolve()
    mode = str(mode or "").strip().lower()
    if mode not in {"review", "full"}:
        raise ValueError("mode must be 'review' or 'full'")
    if not analysis_dir.is_dir():
        raise FileNotFoundError(f"analysis directory not found: {analysis_dir}")

    if mode == "review":
        return [analysis_dir / name for name in REVIEW_FILES if (analysis_dir / name).is_file()]
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
        "files": entries,
    }

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("P3239_RESULT_MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        for path, item in zip(files, entries):
            archive.write(path, item["path"])
    return destination, manifest
