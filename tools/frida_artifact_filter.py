#!/usr/bin/env python3
"""P3.2 non-destructive provenance classifier for CAPEsolo artifacts.

P3.2 changes over P3.1:
  * logical run scoping (current P3 runtime / run_id only),
  * manifest filtering to PIDs enrolled in the current attempt,
  * temporal proximity no longer marks a PE payload as possible instrumentation,
  * strong instrumentation evidence remains range overlap or Frida runtime strings.

Original CAPE evidence is never deleted or modified.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from p3_run_scope import current_run_pids, load_runtime_for_analysis, select_run_log
except ImportError:  # versioned standalone fallback
    from p3_run_scope_p32 import current_run_pids, load_runtime_for_analysis, select_run_log

FRIDA_SIGNATURES = (
    b"frida_agent_main",
    b"frida-agent",
    b"re.frida.",
    b"/re/frida/",
    b"pipe:role=client,name=frida-",
    b"gum-js-loop",
)

BASE_RE = re.compile(r";\?(0x[0-9a-fA-F]+);\?")
DETAIL_RANGE_RE = re.compile(
    r"Instrumentation(?:Module|Range).*?base=(0x[0-9a-fA-F]+)\s+"
    r"size=(0x[0-9a-fA-F]+)\s+path=(.*?)(?:',\s*'pid'|$)"
)
STRUCT_RANGE_RE = re.compile(
    r"'hook':\s*'Instrumentation(?:Module|Range)'.*?"
    r"'module_base':\s*'(0x[0-9a-fA-F]+)'.*?"
    r"'module_size':\s*(\d+).*?"
    r"'module_path':\s*'([^']*)'"
)
CAPEMON_DLL_RE = re.compile(
    r"DLL loaded at\s+(0x[0-9a-fA-F]+):\s+(.+?)\s+\((0x[0-9a-fA-F]+) bytes\)\.?$",
    re.I,
)
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")
ATTACH_START_RE = re.compile(r"\[pid=(\d+)\].*Attaching Frida", re.I)
ATTACH_SUCCESS_RE = re.compile(r'"kind":"frida_attach".*?"pid":(\d+).*?"status":"success"', re.I)
AGENT_PID_RE = re.compile(r"\b(\d+):\s+DLL loaded at .*?frida-agent", re.I)
ARTIFACT_UPLOAD_RE = re.compile(r"Uploading file .*? to CAPE[\\/](?P<sha>[0-9a-fA-F]{64})", re.I)


def load_manifest(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("manifest JSON root must be an array")
        return [x for x in data if isinstance(x, dict)]

    out = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at line {number}: {exc}") from exc
        if isinstance(item, dict):
            out.append(item)
    return out


def parse_dump_base(item: dict) -> int | None:
    metadata = str(item.get("metadata") or "")
    m = BASE_RE.search(metadata)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


def parse_cape_type_code(item: dict) -> int | None:
    metadata = str(item.get("metadata") or "")
    head = metadata.split(";", 1)[0].strip()
    try:
        return int(head)
    except Exception:
        return None


def _parse_log_ts(line: str) -> datetime | None:
    m = TS_RE.search(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None


def _instrumentation_path(path: str) -> bool:
    lower = str(path or "").lower()
    return "frida" in lower or "capesolo" in lower or "capemon" in lower


def parse_instrumentation_ranges_text(log_text: str) -> list[dict]:
    ranges: dict[tuple[int, int, str], dict] = {}
    for line in log_text.splitlines():
        parsed = False
        if "InstrumentationModule" in line or "InstrumentationRange" in line:
            m = STRUCT_RANGE_RE.search(line)
            if m:
                base = int(m.group(1), 16)
                size = int(m.group(2))
                path = m.group(3)
                parsed = True
            else:
                m = DETAIL_RANGE_RE.search(line)
                if m:
                    base = int(m.group(1), 16)
                    size = int(m.group(2), 16)
                    path = m.group(3).strip().rstrip("'}")
                    parsed = True

        if not parsed:
            m = CAPEMON_DLL_RE.search(line)
            if m and _instrumentation_path(m.group(2)):
                base = int(m.group(1), 16)
                path = m.group(2).strip()
                size = int(m.group(3), 16)
                parsed = True

        if not parsed or size <= 0:
            continue
        key = (base, size, path.lower())
        ranges[key] = {"base": base, "end": base + size, "size": size, "path": path}
    return sorted(ranges.values(), key=lambda x: (x["base"], x["size"]))


def parse_temporal_provenance_text(log_text: str) -> dict:
    """Build conservative per-PID Frida bootstrap windows and artifact times."""
    starts: dict[int, datetime] = {}
    ends: dict[int, datetime] = {}
    artifact_times: dict[str, datetime] = {}
    for line in log_text.splitlines():
        ts = _parse_log_ts(line)
        if ts is None:
            continue
        m = ATTACH_START_RE.search(line)
        if m:
            starts.setdefault(int(m.group(1)), ts)
        m = ATTACH_SUCCESS_RE.search(line)
        if m:
            pid = int(m.group(1))
            ends[pid] = max(ends.get(pid, ts), ts + timedelta(seconds=2.0))
        m = AGENT_PID_RE.search(line)
        if m:
            pid = int(m.group(1))
            ends[pid] = max(ends.get(pid, ts), ts + timedelta(seconds=2.0))
        m = ARTIFACT_UPLOAD_RE.search(line)
        if m:
            artifact_times[m.group("sha").lower()] = ts

    windows = {}
    for pid, start in starts.items():
        end = ends.get(pid, start + timedelta(seconds=5.0))
        if end < start:
            end = start + timedelta(seconds=5.0)
        windows[pid] = {"start": start, "end": end}
    return {"windows": windows, "artifact_times": artifact_times}


def artifact_candidates(item: dict, analysis_dir: Path, cape_dir: Path) -> Iterable[Path]:
    rel = str(item.get("path") or "").replace("\\", "/")
    basename = Path(rel).name
    if rel:
        yield analysis_dir / rel
    if basename:
        yield cape_dir / basename
        yield analysis_dir / "CAPE" / basename
        yield analysis_dir / basename


def find_artifact_path(item: dict, analysis_dir: Path, cape_dir: Path) -> Path | None:
    seen = set()
    for candidate in artifact_candidates(item, analysis_dir, cape_dir):
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return candidate
    return None


def scan_frida_signatures(path: Path | None, max_bytes: int = 8 * 1024 * 1024) -> list[str]:
    if path is None:
        return []
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return []

    found = []
    lower = data.lower()
    for sig in FRIDA_SIGNATURES:
        if sig.lower() in lower:
            found.append(sig.decode("ascii", errors="replace"))
    return found


def artifact_is_pe(item: dict, path: Path | None) -> bool:
    # CAPE type 8 is explicitly "Unpacked PE Image" in generated reports.
    if parse_cape_type_code(item) == 8:
        return True
    if path is None:
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def classify_item(item: dict, ranges: list[dict], temporal: dict, analysis_dir: Path, cape_dir: Path) -> dict:
    dump_base = parse_dump_base(item)
    reasons: list[dict] = []
    possible_reasons: list[dict] = []
    annotations: list[dict] = []

    if dump_base is not None:
        for r in ranges:
            if r["base"] <= dump_base < r["end"]:
                reasons.append({
                    "kind": "instrumentation_range",
                    "module_path": r["path"],
                    "module_base": f"0x{r['base']:x}",
                    "module_size": r["size"],
                })

    artifact_path = find_artifact_path(item, analysis_dir, cape_dir)
    is_pe = artifact_is_pe(item, artifact_path)
    signatures = scan_frida_signatures(artifact_path)
    if signatures:
        reasons.append({"kind": "frida_runtime_signature", "signatures": signatures})

    basename = Path(str(item.get("path") or "")).name.lower()
    artifact_time = temporal.get("artifact_times", {}).get(basename)
    for raw_pid in item.get("pids", []) or []:
        try:
            pid = int(raw_pid)
        except Exception:
            continue
        window = temporal.get("windows", {}).get(pid)
        if artifact_time is None or window is None:
            continue
        if not (window["start"] <= artifact_time <= window["end"]):
            continue
        temporal_reason = {
            "kind": "frida_bootstrap_temporal_proximity",
            "pid": pid,
            "artifact_time": artifact_time.isoformat(),
            "window_start": window["start"].isoformat(),
            "window_end": window["end"].isoformat(),
        }
        # P3.2: a real PE payload is allowed to be unpacked immediately after
        # Frida attaches. Timing alone must not downgrade it to instrumentation.
        if is_pe:
            temporal_reason["effect"] = "annotation_only_pe_payload"
            annotations.append(temporal_reason)
        else:
            possible_reasons.append(temporal_reason)

    instrumentation = bool(reasons)
    instrumentation_possible = bool(possible_reasons) and not instrumentation
    confidence = "high" if instrumentation else ("possible" if instrumentation_possible else "unclassified")
    return {
        "path": item.get("path"),
        "pids": item.get("pids", []),
        "ppids": item.get("ppids", []),
        "category": item.get("category"),
        "metadata": item.get("metadata"),
        "cape_type_code": parse_cape_type_code(item),
        "dump_base": f"0x{dump_base:x}" if dump_base is not None else None,
        "resolved_path": str(artifact_path) if artifact_path else None,
        "is_pe": is_pe,
        "instrumentation": instrumentation,
        "instrumentation_possible": instrumentation_possible,
        "confidence": confidence,
        "reasons": reasons,
        "possible_reasons": possible_reasons,
        "annotations": annotations,
    }


def choose_default_manifest(analysis_dir: Path) -> Path | None:
    direct = analysis_dir / "files.json"
    if direct.is_file():
        return direct
    candidates = sorted(analysis_dir.glob("files*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _filter_items_to_current_run(items: list[dict], runtime: dict) -> tuple[list[dict], dict]:
    pids = current_run_pids(runtime)
    if not pids:
        return items, {"pid_filter_applied": False, "run_pids": []}
    selected = []
    for item in items:
        item_pids = set()
        for raw in item.get("pids", []) or []:
            try:
                item_pids.add(int(raw))
            except Exception:
                pass
        if item_pids & pids:
            selected.append(item)
    return selected, {"pid_filter_applied": True, "run_pids": sorted(pids), "manifest_before": len(items), "manifest_after": len(selected)}


def classify_analysis(
    analysis_dir: Path,
    analysis_log: Path | None = None,
    files_json: Path | None = None,
    cape_dir: Path | None = None,
    output_dir: Path | None = None,
    runtime: dict | None = None,
) -> dict:
    analysis_dir = Path(analysis_dir).resolve()
    log_path = Path(analysis_log or analysis_dir / "analysis.log").resolve()
    manifest_path = Path(files_json).resolve() if files_json else choose_default_manifest(analysis_dir)
    if manifest_path is None:
        raise FileNotFoundError("files manifest not found")

    cape_dir = Path(cape_dir or analysis_dir / "CAPE").resolve()
    output_dir = Path(output_dir or analysis_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if runtime is None:
        _, runtime = load_runtime_for_analysis(analysis_dir)
    full_log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    scoped_log_text, run_scope = select_run_log(full_log_text, runtime or {})

    items = load_manifest(manifest_path)
    items, manifest_scope = _filter_items_to_current_run(items, runtime or {})
    ranges = parse_instrumentation_ranges_text(scoped_log_text)
    temporal = parse_temporal_provenance_text(scoped_log_text)
    classifications = [classify_item(item, ranges, temporal, analysis_dir, cape_dir) for item in items]

    result = {
        "schema": "capesolo-frida-artifacts/3.2",
        "run_id": (runtime or {}).get("run_id"),
        "run_scope": run_scope,
        "manifest_scope": manifest_scope,
        "analysis_log": str(log_path),
        "files_manifest": str(manifest_path),
        "instrumentation_ranges": ranges,
        "artifacts": classifications,
    }

    class_path = output_dir / "frida_artifact_classification.json"
    class_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    filtered_path = output_dir / "files.filtered.jsonl"
    with filtered_path.open("w", encoding="utf-8", newline="\n") as fh:
        for item, classification in zip(items, classifications):
            if classification["instrumentation"]:
                continue
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")

    result["classification_path"] = str(class_path)
    result["filtered_manifest_path"] = str(filtered_path)
    result["summary"] = {
        "artifacts": len(classifications),
        "instrumentation": sum(bool(c["instrumentation"]) for c in classifications),
        "possible": sum(bool(c.get("instrumentation_possible")) for c in classifications),
        "temporal_annotations": sum(bool(c.get("annotations")) for c in classifications),
        "retained": sum(not bool(c["instrumentation"]) for c in classifications),
        "retained_pe": sum((not bool(c["instrumentation"])) and bool(c.get("is_pe")) for c in classifications),
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=Path("."))
    ap.add_argument("--analysis-log", type=Path)
    ap.add_argument("--files-json", type=Path)
    ap.add_argument("--cape-dir", type=Path)
    ap.add_argument("--output-dir", type=Path)
    args = ap.parse_args()

    result = classify_analysis(
        analysis_dir=args.analysis_dir,
        analysis_log=args.analysis_log,
        files_json=args.files_json,
        cape_dir=args.cape_dir,
        output_dir=args.output_dir,
    )
    s = result["summary"]
    print(
        f"artifacts={s['artifacts']} instrumentation={s['instrumentation']} "
        f"possible={s['possible']} temporal_annotations={s['temporal_annotations']} "
        f"retained={s['retained']} retained_pe={s['retained_pe']}"
    )
    print(result["classification_path"])
    print(result["filtered_manifest_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
