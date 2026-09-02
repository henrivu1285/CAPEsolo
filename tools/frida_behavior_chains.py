#!/usr/bin/env python3
"""P3.2.3 generic high-value behavior chain extraction.

This is a report/presentation layer. It consumes the lossless
``behavior.filtered.jsonl`` clean view and never changes provenance or raw
CAPEsolo evidence.  The goal is to surface analyst-useful chains such as:

- file materialization -> child execution -> Run/RunOnce persistence
- remote-process access that is only an injection *precursor*
- bounded stage hand-off where a parent creates a child and exits

Injection is deliberately conservative: opening another process with
PROCESS_VM_OPERATION is not labeled T1055 by itself.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for search_path in (HERE, PROJECT_ROOT):
    if str(search_path) not in sys.path:
        sys.path.insert(0, str(search_path))

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION, product_version_for_runtime
from p3_run_scope import load_runtime_for_analysis

RUN_KEY_MARKERS = (
    "\\software\\microsoft\\windows\\currentversion\\run\\",
    "\\software\\microsoft\\windows\\currentversion\\runonce\\",
)
REMOTE_MEMORY_APIS = {
    "ntallocatevirtualmemory",
    "ntwritevirtualmemory",
    "writeprocessmemory",
    "ntmapviewofsection",
    "ntprotectvirtualmemory",
}
REMOTE_EXEC_APIS = {
    "ntcreatethreadex",
    "createremotethread",
    "rtlcreateuserthread",
    "queueuserapc",
    "ntqueueapcthread",
    "setthreadcontext",
}
PROCESS_CREATE_APIS = {"createprocessw", "createprocessa", "ntcreateuserprocess"}
FILE_MATERIALIZE_APIS = {
    "copyfilew", "copyfilea", "movefilew", "movefilea",
    "movefileexw", "movefileexa", "ntcreatefile", "createfilew", "createfilea",
}


def _load_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def _call(record: dict) -> dict:
    return record.get("call") if isinstance(record.get("call"), dict) else {}


def _args(record: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arg in _call(record).get("arguments") or []:
        if not isinstance(arg, dict):
            continue
        name = str(arg.get("name") or "").strip()
        if not name:
            continue
        value = arg.get("value")
        if value is None:
            value = arg.get("pretty_value")
        out[name] = value
    return out


def _norm_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    if not text:
        return ""
    # Path normalization is for correlation only; preserve original strings in evidence.
    return os.path.normcase(os.path.normpath(text))


def _record_ref(record: dict) -> dict:
    call = _call(record)
    return {
        "pid": record.get("pid"),
        "process_name": record.get("process_name"),
        "call_id": record.get("call_id"),
        "timestamp": record.get("timestamp"),
        "api": record.get("api"),
        "thread_id": call.get("thread_id"),
    }


def _find_arg(amap: dict, *names: str) -> Any:
    lower = {str(k).lower(): v for k, v in amap.items()}
    for name in names:
        if name in amap:
            return amap[name]
        if name.lower() in lower:
            return lower[name.lower()]
    return None


def _looks_write_access(value: Any) -> bool:
    text = str(value or "").upper()
    if any(x in text for x in ("WRITE", "OVERWRITE", "APPEND", "FILE_WRITE_DATA", "GENERIC_WRITE")):
        return True
    try:
        number = int(str(value), 0)
    except Exception:
        return False
    return bool(number & (0x40000000 | 0x00000002 | 0x00000004))


def _target_from_file_call(record: dict) -> str:
    api = str(record.get("api") or "").lower()
    a = _args(record)
    if api.startswith("copyfile"):
        return _norm_path(_find_arg(a, "NewFileName"))
    if api.startswith("movefile"):
        return _norm_path(_find_arg(a, "NewFileName"))
    if api in {"ntcreatefile", "createfilew", "createfilea"}:
        access = _find_arg(a, "DesiredAccess", "Access")
        disp = str(_find_arg(a, "CreateDisposition", "CreationDisposition") or "")
        if _looks_write_access(access) or any(x in disp.upper() for x in ("CREATE", "OVERWRITE", "SUPERSEDE")):
            return _norm_path(_find_arg(a, "FileName"))
    return ""


def _process_target(record: dict) -> tuple[str, int | None]:
    a = _args(record)
    path = _find_arg(a, "ApplicationName", "ImagePathName", "ImagePath", "ProcessName")
    if not path:
        # CommandLine can contain arguments; only use it as a weak fallback.
        cmd = str(_find_arg(a, "CommandLine") or "").strip()
        if cmd:
            path = cmd.split(" ", 1)[0].strip('"')
    pid = _find_arg(a, "ProcessId", "ProcessID")
    try:
        pid_i = int(str(pid), 0) if pid is not None else None
    except Exception:
        pid_i = None
    return _norm_path(path), pid_i


def _run_key_write(record: dict) -> tuple[str, str] | None:
    api = str(record.get("api") or "").lower()
    if api not in {"regsetvalueexw", "regsetvalueexa", "ntsetvaluekey"}:
        return None
    a = _args(record)
    full = str(_find_arg(a, "FullName", "RegistryPath", "KeyName") or "")
    low = full.lower()
    if not any(marker in low for marker in RUN_KEY_MARKERS):
        return None
    value = _find_arg(a, "Buffer", "Data", "ValueData")
    return full, str(value or "")


def _desired_remote_access(value: Any) -> bool:
    text = str(value or "").upper()
    if any(x in text for x in ("PROCESS_VM_OPERATION", "PROCESS_VM_WRITE", "PROCESS_CREATE_THREAD")):
        return True
    try:
        number = int(str(value), 0)
    except Exception:
        return False
    # PROCESS_CREATE_THREAD=0x2, PROCESS_VM_OPERATION=0x8, PROCESS_VM_WRITE=0x20
    return bool(number & (0x2 | 0x8 | 0x20))


def extract_behavior_chains_from_records(
    records: list[dict],
    run_version: str = PRODUCT_VERSION,
) -> dict:
    file_events: list[tuple[str, dict]] = []
    proc_events: list[tuple[str, int | None, dict]] = []
    run_writes: list[tuple[str, str, dict]] = []
    by_pid: dict[int, list[dict]] = {}

    for record in records:
        try:
            pid = int(record.get("pid") or 0)
        except Exception:
            pid = 0
        by_pid.setdefault(pid, []).append(record)
        api_l = str(record.get("api") or "").lower()
        if api_l in FILE_MATERIALIZE_APIS:
            target = _target_from_file_call(record)
            if target:
                file_events.append((target, record))
        if api_l in PROCESS_CREATE_APIS:
            path, child_pid = _process_target(record)
            if path:
                proc_events.append((path, child_pid, record))
        rk = _run_key_write(record)
        if rk:
            run_writes.append((rk[0], rk[1], record))

    persistence: list[dict] = []
    for key, value, reg_record in run_writes:
        target = _norm_path(value)
        file_match = next((r for path, r in reversed(file_events) if target and path == target), None)
        proc_match = next((r for path, _, r in reversed(proc_events) if target and path == target), None)
        steps = []
        if file_match:
            steps.append({"kind": "file_materialized", "path": value, "evidence": _record_ref(file_match)})
        if proc_match:
            steps.append({"kind": "process_executed", "path": value, "evidence": _record_ref(proc_match)})
        steps.append({"kind": "run_key_write", "registry": key, "value": value, "evidence": _record_ref(reg_record)})
        confidence = "high" if file_match and proc_match else "medium"
        materialization_status = "observed" if file_match else "not_observed"
        persistence.append({
            "chain_type": "persistence_run_key",
            "confidence": confidence,
            "registry": key,
            "target": value,
            "steps": steps,
            "materialization_status": materialization_status,
            "materialization_observed": bool(file_match),
            "missing_steps": [] if file_match else ["file_materialized"],
            "preexisting_target_possible": not bool(file_match),
            "mitre_candidate": "T1547.001",
            "interpretation": (
                "File materialization, execution, and Run/RunOnce persistence were observed dynamically."
                if file_match and proc_match else
                "Run/RunOnce persistence was observed, but file materialization was not; restore a clean VM snapshot and verify the target path is absent before treating this as a complete drop chain."
            ),
        })

    injection_precursors: list[dict] = []
    for source_pid, pid_records in by_pid.items():
        for idx, record in enumerate(pid_records):
            if str(record.get("api") or "").lower() not in {"ntopenprocess", "openprocess"}:
                continue
            a = _args(record)
            desired = _find_arg(a, "DesiredAccess", "Access")
            if not _desired_remote_access(desired):
                continue
            target_pid_v = _find_arg(a, "ProcessIdentifier", "ProcessId", "TargetProcessId")
            try:
                target_pid = int(str(target_pid_v), 0)
            except Exception:
                target_pid = None
            if target_pid is not None and target_pid == source_pid:
                continue
            target_name = str(_find_arg(a, "ProcessName", "TargetProcessName") or "")
            target_handle = str(_find_arg(a, "ProcessHandle", "Handle") or "").lower()
            remote_memory = []
            remote_exec = []
            for follow in pid_records[idx + 1: idx + 128]:
                fa = _args(follow)
                handle = str(_find_arg(fa, "ProcessHandle", "TargetProcessHandle") or "").lower()
                api_l = str(follow.get("api") or "").lower()
                if target_handle and handle and handle != target_handle:
                    continue
                if api_l in REMOTE_MEMORY_APIS and handle and handle not in {"0xffffffff", "-1"}:
                    remote_memory.append(_record_ref(follow))
                if api_l in REMOTE_EXEC_APIS:
                    remote_exec.append(_record_ref(follow))
            confirmed = bool(remote_memory and remote_exec)
            injection_precursors.append({
                "chain_type": "remote_process_injection" if confirmed else "injection_precursor",
                "confidence": "high" if confirmed else "medium",
                "source_pid": source_pid,
                "target_pid": target_pid,
                "target_process": target_name or None,
                "desired_access": desired,
                "target_handle": target_handle or None,
                "open_process": _record_ref(record),
                "remote_memory_evidence": remote_memory[:16],
                "remote_execution_evidence": remote_exec[:16],
                "confirmed_injection_sequence": confirmed,
                "mitre_candidate": "T1055" if confirmed else None,
                "interpretation": (
                    "Remote memory plus execution-transfer evidence observed."
                    if confirmed else
                    "Remote-process access is a precursor only; no matching write+execution chain was observed."
                ),
            })

    stage_handoffs: list[dict] = []
    for source_pid, pid_records in by_pid.items():
        creates = []
        terms = []
        for record in pid_records:
            api_l = str(record.get("api") or "").lower()
            t = _parse_time(record.get("timestamp"))
            if api_l in PROCESS_CREATE_APIS:
                path, child_pid = _process_target(record)
                creates.append((t, path, child_pid, record))
            elif api_l == "ntterminateprocess":
                a = _args(record)
                handle = str(_find_arg(a, "ProcessHandle") or "").lower()
                if handle in {"0xffffffff", "-1", "0x00000000", "0"}:
                    terms.append((t, record))
        for ct, path, child_pid, create_record in creates:
            if ct is None:
                continue
            term = next((x for x in terms if x[0] is not None and 0 <= (x[0] - ct).total_seconds() <= 3.0), None)
            if term:
                stage_handoffs.append({
                    "chain_type": "stage_handoff",
                    "confidence": "high",
                    "parent_pid": source_pid,
                    "child_pid": child_pid,
                    "child_path": path,
                    "create": _record_ref(create_record),
                    "parent_terminate": _record_ref(term[1]),
                    "delay_ms": round((term[0] - ct).total_seconds() * 1000.0, 3),
                    "interpretation": "Parent created a child and then terminated within a bounded hand-off window.",
                })

    def _dedupe(items, key_fn):
        seen = set()
        out = []
        for item in items:
            key = key_fn(item)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    raw_chain_count = len(persistence) + len(injection_precursors) + len(stage_handoffs)
    persistence = _dedupe(
        persistence,
        lambda x: (str(x.get("registry") or "").lower(), _norm_path(x.get("target"))),
    )
    injection_precursors = _dedupe(
        injection_precursors,
        lambda x: (x.get("target_pid"), str(x.get("target_process") or "").lower(), str(x.get("desired_access") or "")),
    )
    stage_handoffs = _dedupe(
        stage_handoffs,
        lambda x: (x.get("child_pid"), _norm_path(x.get("child_path"))),
    )

    chains = persistence + injection_precursors + stage_handoffs
    return {
        "schema": "capesolo-frida-behavior-chains/3.2.3.14",
        "version": run_version,
        "processor_version": PRODUCT_VERSION,
        "available": True,
        "summary": {
            "chains": len(chains),
            "persistence_run_key": len(persistence),
            "injection_precursors": sum(1 for x in injection_precursors if not x.get("confirmed_injection_sequence")),
            "confirmed_injection_sequences": sum(1 for x in injection_precursors if x.get("confirmed_injection_sequence")),
            "stage_handoffs": len(stage_handoffs),
            "persistence_without_materialization": sum(
                1 for item in persistence if not item.get("materialization_observed")
            ),
            "by_type": dict(Counter(str(x.get("chain_type")) for x in chains)),
            "duplicates_collapsed": raw_chain_count - len(chains),
        },
        "chains": chains,
        "source": "behavior.filtered.jsonl",
        "raw_evidence_unchanged": True,
    }


def build_behavior_chains(analysis_dir: Path, output_dir: Path | None = None) -> dict:
    analysis_dir = Path(analysis_dir)
    output_dir = Path(output_dir or analysis_dir)
    source = output_dir / "behavior.filtered.jsonl"
    if not source.is_file():
        source = analysis_dir / "behavior.filtered.jsonl"
    if not source.is_file():
        _, runtime = load_runtime_for_analysis(analysis_dir)
        return {
            "schema": "capesolo-frida-behavior-chains/3.2.3.14",
            "version": product_version_for_runtime(runtime),
            "processor_version": PRODUCT_VERSION,
            "available": False,
            "reason": "behavior.filtered.jsonl not found",
            "summary": {},
            "chains": [],
        }
    _, runtime = load_runtime_for_analysis(analysis_dir)
    result = extract_behavior_chains_from_records(
        _load_jsonl(source),
        run_version=product_version_for_runtime(runtime),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "frida_behavior_chains.json"
    jsonl_path = output_dir / "behavior.chains.jsonl"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    jsonl_path.write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in result.get("chains", []))
        + ("\n" if result.get("chains") else ""),
        encoding="utf-8",
    )
    result["json_path"] = str(json_path)
    result["jsonl_path"] = str(jsonl_path)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path)
    args = ap.parse_args()
    result = build_behavior_chains(args.analysis_dir, args.output_dir)
    print(json.dumps(result.get("summary", {}), indent=2))
    return 0 if result.get("available") else 2


if __name__ == "__main__":
    raise SystemExit(main())
