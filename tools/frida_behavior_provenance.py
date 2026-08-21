#!/usr/bin/env python3
"""P3.2.1 behavior provenance hotfix for CAPEsolo report.json.

P3.2.1 keeps raw CAPEsolo evidence immutable and closes two provenance gaps:
  * confirmed private instrumentation artifacts become address ranges usable by
    the behavior classifier, and
  * narrowly bounded same-thread Frida bootstrap plumbing can inherit Frida
    provenance when strong Frida anchors exist on both sides.

The propagation is deliberately conservative: retained PE payload ranges protect
sample code from inheritance, possible instrumentation ranges are annotation-only,
and raw report.json / behavior.provenance.jsonl are never deleted or rewritten.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from p3_run_scope import current_run_pids, load_runtime_for_analysis, select_run_log
except ImportError:
    from p3_run_scope_p32 import current_run_pids, load_runtime_for_analysis, select_run_log

MONITOR_BASE_RE = re.compile(
    r"(?P<pid>\d+):\s+Monitor initialised:.*?capemon loaded in process\s+(?P=pid)\s+at\s+(?P<base>0x[0-9a-fA-F]+)",
    re.I,
)

FRIDA_TEXT_MARKERS = (
    "frida-agent",
    "frida_agent_main",
    "\\pipe\\frida-",
    "\\namedpipe\\frida-",
    "/re/frida/",
    "re.frida.",
    "agentmessagesink",
    "github.com/frida",
    "gum-js-loop",
)
CAPEMON_TEXT_MARKERS = ("capemon", "capesolo")


# P3.2.1: only framework-plumbing APIs are eligible for same-thread context
# propagation. Malware can call these APIs too, therefore propagation additionally
# requires strong Frida anchors on BOTH sides, the same thread, a short time span,
# and no caller/parentcaller overlap with a retained PE payload range.
THREAD_BRIDGE_MAX_MS = 25.0
THREAD_BRIDGE_MAX_CALLS = 512
THREAD_PROPAGATABLE_APIS = {
    "ntreadvirtualmemory", "ntwritevirtualmemory", "ntqueryvirtualmemory",
    "ntqueryinformationprocess", "ntqueryinformationthread", "ntopenthread",
    "ntsuspendthread", "ntresumethread", "ntprotectvirtualmemory",
    "ntallocatevirtualmemory", "ntfreevirtualmemory", "ntduplicateobject",
    "ntqueryinformationtoken", "ntopenprocesstoken", "ntopenkey",
    "ntqueryvaluekey", "ntclose", "nttestalert", "ntdelayexecution",
    "ntcreatethreadex", "rtladdvectoredexceptionhandler",
    "rtlremovevectoredexceptionhandler", "getsystemtimeasfiletime",
    "getsysteminfo", "ldrgetdllhandle", "ldrgetprocedureaddressforcaller",
    "ldrloaddll",
}

DUMP_ENTIRE_RE = re.compile(
    r"DumpRegion:\s+Dumped entire allocation from\s+(?P<base>0x[0-9a-fA-F]+),\s+size\s*:?\s*(?P<size>\d+)\s+bytes",
    re.I,
)
DUMP_REGION_RE = re.compile(
    r"DumpRegion:\s+Dumped region at\s+(?P<base>0x[0-9a-fA-F]+),\s+size\s*:?\s*(?P<size>\d+)\s+bytes",
    re.I,
)
DUMP_PE_REGION_RE = re.compile(
    r"DumpRegion:\s+Dumped PE image\(s\) from base address\s+(?P<base>0x[0-9a-fA-F]+),\s+size\s+(?P<size>\d+)\s+bytes",
    re.I,
)


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def choose_report_json(analysis_dir: Path) -> Path | None:
    direct = analysis_dir / "report.json"
    if direct.is_file():
        return direct
    candidates = [
        p for p in analysis_dir.glob("report*.json")
        if not p.name.lower().startswith("frida_p3_report")
    ]
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def parse_address(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except Exception:
        return None


def _in_range(address: int | None, ranges: list[dict]) -> dict | None:
    if address is None:
        return None
    for r in ranges:
        try:
            if int(r["base"]) <= address < int(r["end"]):
                return r
        except Exception:
            continue
    return None


def pe_size_of_image(path: Path) -> int | None:
    """Read PE OptionalHeader.SizeOfImage without external dependencies."""
    try:
        with path.open("rb") as fh:
            dos = fh.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            fh.seek(e_lfanew)
            if fh.read(4) != b"PE\0\0":
                return None
            file_header = fh.read(20)
            if len(file_header) != 20:
                return None
            size_opt = struct.unpack_from("<H", file_header, 16)[0]
            opt = fh.read(size_opt)
            if len(opt) < 60:
                return None
            magic = struct.unpack_from("<H", opt, 0)[0]
            if magic not in (0x10B, 0x20B):
                return None
            return struct.unpack_from("<I", opt, 56)[0]
    except OSError:
        return None


def _runtime_capemon_path(runtime: dict, pid: int) -> str | None:
    lineage = runtime.get("lineage") if isinstance(runtime.get("lineage"), dict) else {}
    meta = lineage.get(str(pid)) or lineage.get(pid)
    if isinstance(meta, dict):
        value = meta.get("capemon_mapping")
        return str(value) if value else None
    return None


def build_capemon_ranges(scoped_log_text: str, runtime: dict) -> list[dict]:
    ranges = []
    seen = set()
    for line in scoped_log_text.splitlines():
        m = MONITOR_BASE_RE.search(line)
        if not m:
            continue
        pid = int(m.group("pid"))
        base = int(m.group("base"), 16)
        raw_path = _runtime_capemon_path(runtime, pid)
        size = None
        if raw_path:
            size = pe_size_of_image(Path(raw_path))
        # No guessed range when the monitor file is unavailable. Address-based
        # CAPEMON filtering must stay conservative.
        if not size:
            continue
        key = (pid, base, size, str(raw_path).lower())
        if key in seen:
            continue
        seen.add(key)
        ranges.append({
            "pid": pid,
            "base": base,
            "end": base + size,
            "size": size,
            "path": raw_path,
        })
    return ranges


def _flatten_argument_text(arguments: Any, limit_each: int = 1024) -> str:
    pieces: list[str] = []
    if not isinstance(arguments, list):
        return ""
    for arg in arguments:
        if not isinstance(arg, dict):
            continue
        for key in ("name", "value", "pretty_value"):
            value = arg.get(key)
            if value is None:
                continue
            text = str(value)
            if len(text) > limit_each:
                text = text[:limit_each]
            pieces.append(text)
    return " ".join(pieces).lower()


def _marker_hits(text: str, markers: tuple[str, ...]) -> list[str]:
    return [marker for marker in markers if marker in text]


def _range_reason(kind: str, which: str, address: int, r: dict) -> dict:
    return {
        "kind": kind,
        "field": which,
        "address": f"0x{address:x}",
        "range_base": f"0x{int(r['base']):x}",
        "range_end": f"0x{int(r['end']):x}",
        "module_path": r.get("path"),
    }


def _page_align(value: int, page: int = 0x1000) -> int:
    if value <= 0:
        return page
    return ((value + page - 1) // page) * page


def _parse_log_region_sizes(scoped_log_text: str) -> dict[int, int]:
    """Best-effort extent map for private/CAPE regions observed in this run."""
    sizes: dict[int, int] = {}
    for line in scoped_log_text.splitlines():
        for regex in (DUMP_ENTIRE_RE, DUMP_REGION_RE, DUMP_PE_REGION_RE):
            m = regex.search(line)
            if not m:
                continue
            try:
                base = int(m.group("base"), 16)
                size = int(m.group("size"))
            except Exception:
                continue
            if size > 0:
                sizes[base] = max(sizes.get(base, 0), size)
            break
    return sizes


def _artifact_extent(item: dict, log_sizes: dict[int, int]) -> tuple[int | None, int | None]:
    base = parse_address(item.get("dump_base"))
    if base is None:
        return None, None
    size = log_sizes.get(base)
    if not size:
        path = item.get("resolved_path")
        if path:
            try:
                size = Path(path).stat().st_size
            except OSError:
                size = None
    if not size:
        # A confirmed artifact with an exact base but no available backing file
        # still receives a single page. This is intentionally narrow.
        size = 0x1000
    return base, _page_align(int(size))


def build_private_artifact_ranges(artifact_result: dict, scoped_log_text: str) -> tuple[list[dict], list[dict], list[dict]]:
    """Return confirmed framework, possible framework, and retained-PE ranges."""
    log_sizes = _parse_log_region_sizes(scoped_log_text)
    confirmed: list[dict] = []
    possible: list[dict] = []
    retained_pe: list[dict] = []
    items = artifact_result.get("artifacts") if isinstance(artifact_result.get("artifacts"), list) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        base, size = _artifact_extent(item, log_sizes)
        if base is None or not size:
            continue
        entry = {
            "base": base, "end": base + size, "size": size,
            "path": item.get("resolved_path") or item.get("path"),
            "source": "artifact_provenance",
            "artifact_path": item.get("path"),
            "confidence": item.get("confidence"),
        }
        if item.get("instrumentation") and str(item.get("confidence") or "").lower() == "high":
            confirmed.append(entry)
        elif item.get("instrumentation_possible") and not item.get("instrumentation"):
            possible.append(entry)
        elif item.get("is_pe") and not item.get("instrumentation"):
            retained_pe.append(entry)
    return confirmed, possible, retained_pe


def build_main_sample_ranges(report: dict) -> list[dict]:
    """Protect the submitted PE image from thread-context propagation."""
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    pe = target.get("pe") if isinstance(target.get("pe"), dict) else {}
    base = parse_address(pe.get("imagebase"))
    sections = pe.get("sections") if isinstance(pe.get("sections"), list) else []
    if base is None or not sections:
        return []
    max_end = 0
    for sec in sections:
        if not isinstance(sec, dict):
            continue
        va = parse_address(sec.get("virtual_address")) or 0
        vs = parse_address(sec.get("virtual_size")) or 0
        raw = parse_address(sec.get("size_of_data")) or 0
        max_end = max(max_end, va + max(vs, raw))
    if max_end <= 0:
        return []
    size = _page_align(max_end)
    return [{
        "base": base, "end": base + size, "size": size,
        "path": target.get("path") or target.get("name"),
        "source": "submitted_pe",
    }]


def _parse_call_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def _protected_by_sample_range(record: dict, ranges: list[dict]) -> bool:
    call = record.get("call") if isinstance(record.get("call"), dict) else {}
    for field in ("caller", "parentcaller"):
        address = parse_address(call.get(field))
        if _in_range(address, ranges) is not None:
            return True
    return False


def _eligible_thread_plumbing(record: dict) -> bool:
    return str(record.get("api") or "").strip().lower() in THREAD_PROPAGATABLE_APIS


def propagate_frida_thread_context(records: list[dict], sample_protected_ranges: list[dict]) -> dict:
    """Conservatively bridge short candidate gaps between strong Frida anchors."""
    by_thread: dict[tuple[int, str], list[int]] = defaultdict(list)
    for idx, rec in enumerate(records):
        call = rec.get("call") if isinstance(rec.get("call"), dict) else {}
        tid = str(call.get("thread_id") or "")
        if tid:
            by_thread[(int(rec.get("pid") or 0), tid)].append(idx)

    propagated = 0
    windows = 0
    by_api = Counter()
    for (_pid, tid), indices in by_thread.items():
        anchor_positions = [
            pos for pos, idx in enumerate(indices)
            if records[idx].get("provenance") == "framework_frida"
            and records[idx].get("confidence") == "high"
        ]
        for left_pos, right_pos in zip(anchor_positions, anchor_positions[1:]):
            if right_pos <= left_pos + 1:
                continue
            gap_count = right_pos - left_pos - 1
            if gap_count > THREAD_BRIDGE_MAX_CALLS:
                continue
            left = records[indices[left_pos]]
            right = records[indices[right_pos]]
            lt = _parse_call_time(left.get("timestamp"))
            rt = _parse_call_time(right.get("timestamp"))
            if lt is None or rt is None:
                continue
            delta_ms = (rt - lt).total_seconds() * 1000.0
            if delta_ms < 0 or delta_ms > THREAD_BRIDGE_MAX_MS:
                continue

            changed_here = 0
            for pos in range(left_pos + 1, right_pos):
                rec = records[indices[pos]]
                if rec.get("provenance") != "malware_candidate":
                    continue
                if not _eligible_thread_plumbing(rec):
                    continue
                if _protected_by_sample_range(rec, sample_protected_ranges):
                    continue
                rec["provenance"] = "framework_frida"
                rec["confidence"] = "high"
                rec["filter_from_clean_view"] = True
                rec.setdefault("reasons", []).append({
                    "kind": "frida_thread_context",
                    "thread_id": tid,
                    "left_anchor_call_id": left.get("call_id"),
                    "right_anchor_call_id": right.get("call_id"),
                    "anchor_span_ms": round(delta_ms, 3),
                    "rule": "bounded_strong_frida_anchors",
                })
                propagated += 1
                changed_here += 1
                by_api[str(rec.get("api") or "<none>")] += 1
            if changed_here:
                windows += 1

    return {
        "propagated_calls": propagated,
        "bounded_windows": windows,
        "by_api": dict(by_api),
        "max_span_ms": THREAD_BRIDGE_MAX_MS,
        "max_gap_calls": THREAD_BRIDGE_MAX_CALLS,
    }


def classify_call(call: dict, pid: int, tracked_pids: set[int], frida_ranges: list[dict], capemon_ranges: list[dict], confirmed_private_ranges: list[dict], possible_private_ranges: list[dict]) -> dict:
    caller = parse_address(call.get("caller"))
    parentcaller = parse_address(call.get("parentcaller"))
    arg_text = _flatten_argument_text(call.get("arguments"))

    reasons: list[dict] = []
    possible_reasons: list[dict] = []

    for which, address in (("caller", caller), ("parentcaller", parentcaller)):
        r = _in_range(address, frida_ranges)
        if r is not None and address is not None:
            reasons.append(_range_reason("frida_address_range", which, address, r))
        pr = _in_range(address, confirmed_private_ranges)
        if pr is not None and address is not None:
            reasons.append(_range_reason("frida_private_artifact_range", which, address, pr))
        ppr = _in_range(address, possible_private_ranges)
        if ppr is not None and address is not None:
            possible_reasons.append(_range_reason("possible_private_artifact_range", which, address, ppr))

    frida_hits = _marker_hits(arg_text, FRIDA_TEXT_MARKERS)
    if frida_hits:
        reasons.append({"kind": "frida_argument_signature", "markers": frida_hits[:10]})

    caller_capemon = _in_range(caller, capemon_ranges)
    parent_capemon = _in_range(parentcaller, capemon_ranges)
    if caller_capemon is not None and caller is not None:
        reasons.append(_range_reason("capemon_caller_range", "caller", caller, caller_capemon))
    elif parent_capemon is not None and parentcaller is not None:
        possible_reasons.append(_range_reason("capemon_parentcaller_range", "parentcaller", parentcaller, parent_capemon))

    cape_hits = _marker_hits(arg_text, CAPEMON_TEXT_MARKERS)
    if cape_hits:
        possible_reasons.append({"kind": "capemon_argument_signature", "markers": cape_hits[:10]})

    if any(r.get("kind", "").startswith("frida_") for r in reasons):
        provenance = "framework_frida"
        confidence = "high"
        filter_from_clean_view = True
    elif any(r.get("kind") == "capemon_caller_range" for r in reasons):
        provenance = "framework_capemon"
        confidence = "high"
        filter_from_clean_view = True
    elif possible_reasons:
        provenance = "framework_possible"
        confidence = "possible"
        filter_from_clean_view = False
    elif pid in tracked_pids:
        provenance = "malware_candidate"
        confidence = "candidate"
        filter_from_clean_view = False
    else:
        provenance = "unknown"
        confidence = "unclassified"
        filter_from_clean_view = False

    return {
        "provenance": provenance,
        "confidence": confidence,
        "filter_from_clean_view": filter_from_clean_view,
        "reasons": reasons,
        "possible_reasons": possible_reasons,
    }


def classify_behavior(
    analysis_dir: Path,
    report_json: Path | None = None,
    output_dir: Path | None = None,
    runtime: dict | None = None,
    artifact_result: dict | None = None,
) -> dict:
    analysis_dir = Path(analysis_dir).resolve()
    output_dir = Path(output_dir or analysis_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if runtime is None:
        _, runtime = load_runtime_for_analysis(analysis_dir)
    runtime = runtime or {}

    report_path = Path(report_json).resolve() if report_json else choose_report_json(analysis_dir)
    if report_path is None or not report_path.is_file():
        result = {
            "schema": "capesolo-frida-behavior/3.2.1",
            "run_id": runtime.get("run_id"),
            "available": False,
            "reason": "cape_report_json_not_found",
            "summary": {},
        }
        (output_dir / "frida_behavior_provenance.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return result

    report = _load_json(report_path)
    full_log = (analysis_dir / "analysis.log").read_text(encoding="utf-8", errors="replace") if (analysis_dir / "analysis.log").exists() else ""
    scoped_log, run_scope = select_run_log(full_log, runtime)

    if artifact_result is None:
        artifact_path = output_dir / "frida_artifact_classification.json"
        artifact_result = _load_json(artifact_path) if artifact_path.is_file() else {}

    all_instrumentation_ranges = artifact_result.get("instrumentation_ranges") if isinstance(artifact_result.get("instrumentation_ranges"), list) else []
    frida_ranges = [r for r in all_instrumentation_ranges if "frida" in str(r.get("path") or "").lower()]
    capemon_ranges = build_capemon_ranges(scoped_log, runtime)
    confirmed_private_ranges, possible_private_ranges, retained_pe_ranges = build_private_artifact_ranges(artifact_result, scoped_log)
    main_sample_ranges = build_main_sample_ranges(report)
    sample_protected_ranges = main_sample_ranges + retained_pe_ranges
    tracked_pids = current_run_pids(runtime)

    records = []
    behavior = report.get("behavior") if isinstance(report.get("behavior"), dict) else {}
    processes = behavior.get("processes") if isinstance(behavior.get("processes"), list) else []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        try:
            pid = int(proc.get("process_id"))
        except Exception:
            continue
        # Current run only when lineage exists. This prevents a reused report or
        # mixed output directory from contaminating P3.2 summaries.
        if tracked_pids and pid not in tracked_pids:
            continue
        calls = proc.get("calls") if isinstance(proc.get("calls"), list) else []
        for call in calls:
            if not isinstance(call, dict):
                continue
            cls = classify_call(call, pid, tracked_pids, frida_ranges, capemon_ranges, confirmed_private_ranges, possible_private_ranges)
            records.append({
                "pid": pid,
                "process_name": proc.get("process_name"),
                "process_path": proc.get("module_path"),
                "call_id": call.get("id"),
                "timestamp": call.get("timestamp"),
                "category": call.get("category"),
                "api": call.get("api"),
                **cls,
                "call": call,
            })

    thread_context = propagate_frida_thread_context(records, sample_protected_ranges)

    provenance_counts = Counter(r["provenance"] for r in records)
    filtered = [r for r in records if not r.get("filter_from_clean_view")]
    filtered_category_counts = Counter(str(r.get("category") or "<none>") for r in filtered)
    filtered_api_counts = Counter(str(r.get("api") or "<none>") for r in filtered)
    network_candidates = [r for r in filtered if str(r.get("category") or "").lower() == "network"]
    framework_network = [r for r in records if r.get("filter_from_clean_view") and str(r.get("category") or "").lower() == "network"]

    summary = {
        "calls_total": len(records),
        "calls_filtered_clean_view": len(filtered),
        "framework_removed_from_clean_view": len(records) - len(filtered),
        "by_provenance": dict(provenance_counts),
        "filtered_by_category": dict(filtered_category_counts),
        "filtered_top_apis": filtered_api_counts.most_common(30),
        "network_candidate_calls": len(network_candidates),
        "network_framework_calls": len(framework_network),
        "network_candidate_apis": Counter(str(r.get("api") or "<none>") for r in network_candidates).most_common(20),
        "thread_context": thread_context,
    }

    result = {
        "schema": "capesolo-frida-behavior/3.2.1",
        "run_id": runtime.get("run_id"),
        "available": True,
        "source_report": str(report_path),
        "run_scope": run_scope,
        "tracked_pids": sorted(tracked_pids),
        "frida_ranges": frida_ranges,
        "confirmed_private_ranges": confirmed_private_ranges,
        "possible_private_ranges": possible_private_ranges,
        "sample_protected_ranges": sample_protected_ranges,
        "capemon_ranges": capemon_ranges,
        "summary": summary,
        "notes": [
            "Raw CAPEsolo report.json is unchanged.",
            "Confirmed high-confidence instrumentation artifacts contribute narrow private address ranges.",
            "Possible instrumentation artifact ranges are annotation-only and stay in the clean view.",
            "Thread-context propagation requires strong Frida anchors on both sides, a short span, a plumbing API, and no retained-PE caller overlap.",
            "framework_possible calls remain in the clean view because provenance is not high-confidence.",
            "malware_candidate means associated with an enrolled sample process, not a malicious verdict.",
        ],
    }

    summary_path = output_dir / "frida_behavior_provenance.json"
    all_path = output_dir / "behavior.provenance.jsonl"
    filtered_path = output_dir / "behavior.filtered.jsonl"
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    with all_path.open("w", encoding="utf-8", newline="\n") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    with filtered_path.open("w", encoding="utf-8", newline="\n") as fh:
        for record in filtered:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    result["summary_path"] = str(summary_path)
    result["provenance_jsonl"] = str(all_path)
    result["filtered_jsonl"] = str(filtered_path)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=Path("."))
    ap.add_argument("--report-json", type=Path)
    ap.add_argument("--output-dir", type=Path)
    args = ap.parse_args()
    result = classify_behavior(args.analysis_dir, args.report_json, args.output_dir)
    print(json.dumps(result.get("summary", {}), indent=2, ensure_ascii=False))
    if result.get("summary_path"):
        print(result["summary_path"])
        print(result["filtered_jsonl"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
