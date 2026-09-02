#!/usr/bin/env python3
"""Read-only ResultServer diagnostics scoped to the current P3 run."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from p3_run_scope import load_runtime_for_analysis, select_run_log

SUMMARY_RE = re.compile(r"ResultServer transfers complete=(\d+) incomplete=(\d+)")
SHUTDOWN_WARNING_RE = re.compile(
    r"ResultServer (?:did not stop via its own hub|thread still alive|did not stop cleanly)",
    re.I,
)
UPLOAD_START_RE = re.compile(r"(?:Uploading file|DEBUG: Uploading file)\s+(.+?)(?:\s+to\s+|$)")
UPLOADED_RE = re.compile(r"Uploaded file\s+(.+?)\s+of length")
CLOSE_RE = re.compile(r"Closing connection handle:\s*([^,]+),\s*fd:\s*(\d+)")


def diagnose(analysis_dir: Path) -> dict:
    analysis_dir = analysis_dir.resolve()
    runtime_path, runtime = load_runtime_for_analysis(analysis_dir)
    log_path = analysis_dir / "analysis.log"
    full = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    scoped, scope = select_run_log(full, runtime)
    lines = scoped.splitlines()

    summaries = SUMMARY_RE.findall(scoped)
    complete, incomplete = (map(int, summaries[-1]) if summaries else (None, None))
    shutdown_warnings = SHUTDOWN_WARNING_RE.findall(scoped)
    if incomplete:
        status = "degraded"
    elif complete is not None and shutdown_warnings:
        status = "complete_with_shutdown_warning"
    elif complete is not None:
        status = "complete"
    else:
        status = "unknown"
    duplicates = [l for l in lines if "Cannot store upload" in l and "already exists" in l]
    close_counts = {}
    for line in lines:
        m = CLOSE_RE.search(line)
        if not m:
            continue
        kind = m.group(1).strip()
        close_counts[kind] = close_counts.get(kind, 0) + 1

    resultserver_lines = [l for l in lines if "resultserver" in l.lower() or "ResultServer" in l]
    return {
        "schema": "capesolo-resultserver-diagnostic/3.2",
        "run_id": runtime.get("run_id"),
        "runtime_path": str(runtime_path) if runtime_path else None,
        "run_scope": scope,
        "summary": {
            "status": status,
            "complete_transfers": complete,
            "incomplete_transfers": incomplete,
            "shutdown_warning_count": len(shutdown_warnings),
            "duplicate_uploads": len(duplicates),
            "closed_connection_types": close_counts,
        },
        "duplicate_examples": duplicates[:20],
        "resultserver_tail": resultserver_lines[-80:],
        "interpretation": [
            "This tool does not patch CAPEsolo ResultServer.",
            "An incomplete transfer after a clean run should be investigated in CAPEsolo transport/storage separately from Frida instrumentation.",
            "BsonStore/LogHandler close lines alone do not prove which transfer was incomplete.",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=Path(r"C:\Users\Public\CAPEsolo\analysis"))
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    result = diagnose(args.analysis_dir)
    output = args.output or (args.analysis_dir / "p3_resultserver_diagnostic.json")
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result["summary"], indent=2, ensure_ascii=False))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
