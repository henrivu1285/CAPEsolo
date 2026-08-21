#!/usr/bin/env python3
"""Logical per-attempt scoping for CAPEsolo + Frida P3.2.

CAPEsolo may append several analysis attempts into one analysis.log and reuse the
same analysis output directory. P3.2 does not mutate CAPEsolo's raw storage; it
selects only the log slice that belongs to the runtime report currently being
finalized.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

P3_EVIDENCE_RE = re.compile(r"\[P3Evidence\]\s+(\{.*\})\s*$")
ANALYZER_START_TOKEN = "Starting analyzer from:"


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def recover_evidence_with_lines(log_text: str) -> list[tuple[int, dict]]:
    out: list[tuple[int, dict]] = []
    for idx, line in enumerate(log_text.splitlines()):
        m = P3_EVIDENCE_RE.search(line)
        if not m:
            continue
        try:
            event = json.loads(m.group(1))
        except Exception:
            continue
        if isinstance(event, dict):
            out.append((idx, event))
    return out


def _runtime_start_wall(runtime: dict) -> float | None:
    value = runtime.get("run_started_wall")
    try:
        if value is not None:
            return float(value)
    except Exception:
        pass
    events = runtime.get("evidence") if isinstance(runtime.get("evidence"), list) else []
    for event in events:
        if isinstance(event, dict) and event.get("kind") == "controller_start":
            try:
                return float(event.get("wall_time"))
            except Exception:
                return None
    return None


def _find_controller_start_line(log_text: str, runtime: dict) -> int | None:
    evidence = recover_evidence_with_lines(log_text)
    run_id = str(runtime.get("run_id") or "").strip()
    if run_id:
        for idx, event in evidence:
            if event.get("kind") == "controller_start" and str(event.get("run_id") or "") == run_id:
                return idx

    start_wall = _runtime_start_wall(runtime)
    if start_wall is not None:
        best: tuple[float, int] | None = None
        for idx, event in evidence:
            if event.get("kind") != "controller_start":
                continue
            try:
                delta = abs(float(event.get("wall_time")) - start_wall)
            except Exception:
                continue
            if best is None or delta < best[0]:
                best = (delta, idx)
        if best is not None and best[0] <= 2.0:
            return best[1]

    # Last controller_start is the safest fallback for a current-runtime alias.
    starts = [idx for idx, event in evidence if event.get("kind") == "controller_start"]
    return starts[-1] if starts else None


def select_run_log(log_text: str, runtime: dict | None = None) -> tuple[str, dict]:
    """Return the logical current-attempt log slice and scope metadata."""
    runtime = runtime or {}
    lines = log_text.splitlines()
    if not lines:
        return "", {
            "run_id": runtime.get("run_id"),
            "selected": False,
            "reason": "empty_log",
            "start_line": None,
            "end_line": None,
            "analyzer_runs_total": 0,
            "mixed_log_detected": False,
        }

    analyzer_starts = [i for i, line in enumerate(lines) if ANALYZER_START_TOKEN in line]
    anchor = _find_controller_start_line(log_text, runtime)

    if anchor is None:
        return log_text, {
            "run_id": runtime.get("run_id"),
            "selected": False,
            "reason": "controller_start_not_found",
            "start_line": 1,
            "end_line": len(lines),
            "analyzer_runs_total": len(analyzer_starts),
            "mixed_log_detected": len(analyzer_starts) > 1,
        }

    start = 0
    preceding = [i for i in analyzer_starts if i <= anchor]
    if preceding:
        start = preceding[-1]
    else:
        start = anchor

    end = len(lines)
    for i in analyzer_starts:
        if i > anchor:
            end = i
            break

    selected = lines[start:end]
    return "\n".join(selected) + ("\n" if selected else ""), {
        "run_id": runtime.get("run_id"),
        "selected": True,
        "reason": "runtime_controller_start",
        "start_line": start + 1,
        "end_line": end,
        "anchor_line": anchor + 1,
        "analyzer_runs_total": len(analyzer_starts),
        "mixed_log_detected": len(analyzer_starts) > 1,
    }


def load_runtime_for_analysis(analysis_dir: Path) -> tuple[Path | None, dict]:
    analysis_dir = Path(analysis_dir)
    direct = analysis_dir / "frida_p3_runtime.json"
    if direct.is_file():
        return direct, load_json(direct)

    marker = load_json(analysis_dir / "p3_current_run.json")
    run_id = str(marker.get("run_id") or "").strip()
    if run_id:
        candidate = analysis_dir / "p3_runs" / run_id / "frida_p3_runtime.json"
        if candidate.is_file():
            return candidate, load_json(candidate)

    candidates = sorted(
        (analysis_dir / "p3_runs").glob("*/frida_p3_runtime.json")
        if (analysis_dir / "p3_runs").is_dir() else [],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0], load_json(candidates[0])
    return None, {}


def current_run_pids(runtime: dict) -> set[int]:
    out: set[int] = set()
    lineage = runtime.get("lineage") if isinstance(runtime.get("lineage"), dict) else {}
    for raw in lineage.keys():
        try:
            out.add(int(raw))
        except Exception:
            pass
    try:
        if runtime.get("target_pid") is not None:
            out.add(int(runtime.get("target_pid")))
    except Exception:
        pass
    return out
