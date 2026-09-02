#!/usr/bin/env python3
"""P3.2.3.14 semantic behavior compaction and per-API coverage accounting.

This module is display/report-layer only. It never rewrites CAPEsolo report.json,
behavior.provenance.jsonl, or behavior.filtered.jsonl.  The clean-view JSONL
remains the lossless analyst evidence stream; this module builds an additional
compact semantic view for high-volume observational API bursts.

P3.2.3 deliberately does NOT reclassify calls as Frida.  Provenance decisions are
inherited from P3.2.1.  Compaction only reduces repetitive presentation while
preserving a reversible source-count invariant and explicit coverage warnings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for search_path in (HERE, PROJECT_ROOT):
    if str(search_path) not in sys.path:
        sys.path.insert(0, str(search_path))

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION, product_version_for_runtime
from p3_run_scope import load_runtime_for_analysis, select_run_log

API_RATE_CAP_RE = re.compile(
    r"api-rate-cap:\s+([A-Za-z0-9_]+)\s+hook disabled due to rate", re.I
)

# Only APIs whose repeated calls are primarily observational/wait/query plumbing
# are eligible for display compaction.  Write/execute/network/file-mutation APIs
# are intentionally excluded because individual arguments may be analyst-significant.
COMPACTABLE_APIS = {
    "ntreadvirtualmemory",
    "ntqueryvirtualmemory",
    "ntqueryinformationprocess",
    "ntqueryinformationthread",
    "ntqueryinformationtoken",
    "nttestalert",
    "ntwaitforsingleobject",
    "ntdelayexecution",
    "getsystemtimeasfiletime",
    "ntclose",
    "process32nextw",
    "process32nexta",
    "process32next",
}
COMPACT_MIN_GROUP_COUNT = 8
COMPACT_MAX_GROUP_SPAN_MS = 1000.0
MAX_VALUE_EXAMPLES = 6
MAX_CALL_ID_SAMPLES = 12

# Argument names that identify the semantic target of a repeated read/query API.
# Other arguments are summarized as variable values but do not split the burst.
STABLE_ARGUMENTS = {
    "ntreadvirtualmemory": ("ProcessHandle",),
    "ntqueryvirtualmemory": ("ProcessHandle", "MemoryInformationClass"),
    "ntqueryinformationprocess": ("ProcessHandle", "ProcessInformationClass"),
    "ntqueryinformationthread": ("ThreadHandle", "ThreadInformationClass"),
    "ntqueryinformationtoken": ("TokenInformationClass",),
    "ntwaitforsingleobject": ("Handle", "Alertable"),
    "ntdelayexecution": ("Alertable",),
    # NtClose/Process32Next* intentionally have no stable argument. Their
    # per-call values are summarized as variable examples; the lossless
    # behavior.filtered.jsonl remains the authoritative expansion source.
}


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return records
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def _arg_map(record: dict) -> dict[str, Any]:
    call = record.get("call") if isinstance(record.get("call"), dict) else {}
    args = call.get("arguments") if isinstance(call.get("arguments"), list) else []
    out: dict[str, Any] = {}
    for arg in args:
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


def _norm(value: Any) -> str:
    return str(value if value is not None else "").strip().lower()


def _semantic_key(record: dict) -> tuple:
    call = record.get("call") if isinstance(record.get("call"), dict) else {}
    api = str(record.get("api") or "")
    api_l = api.lower()
    args = _arg_map(record)
    stable = tuple((name, _norm(args.get(name))) for name in STABLE_ARGUMENTS.get(api_l, ()))
    return (
        int(record.get("pid") or 0),
        str(call.get("thread_id") or ""),
        api_l,
        str(record.get("category") or ""),
        str(record.get("provenance") or ""),
        str(record.get("confidence") or ""),
        _norm(call.get("caller")),
        _norm(call.get("parentcaller")),
        stable,
    )


def _parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except Exception:
        return None


def _value_summary(values: list[Any]) -> dict:
    # Buffer payloads can be huge.  Keep only cardinality/length metadata for them.
    normalized = [str(v) for v in values if v is not None]
    unique = list(dict.fromkeys(normalized))
    numeric = [_parse_int(v) for v in values]
    numeric = [v for v in numeric if v is not None]
    out = {
        "observed": len(normalized),
        "unique": len(unique),
        "examples": unique[:MAX_VALUE_EXAMPLES],
    }
    if numeric:
        out["min_numeric"] = min(numeric)
        out["max_numeric"] = max(numeric)
    return out


def _summarize_arguments(group: list[dict], api_l: str) -> tuple[dict, dict]:
    maps = [_arg_map(r) for r in group]
    stable_names = set(STABLE_ARGUMENTS.get(api_l, ()))
    stable: dict[str, Any] = {}
    variable: dict[str, dict] = {}
    names = []
    seen_names = set()
    for amap in maps:
        for name in amap:
            if name not in seen_names:
                seen_names.add(name)
                names.append(name)
    for name in names:
        vals = [m.get(name) for m in maps if name in m]
        if name in stable_names:
            uniq = list(dict.fromkeys(str(v) for v in vals))
            stable[name] = uniq[0] if len(uniq) == 1 else uniq[:MAX_VALUE_EXAMPLES]
            continue
        if name.lower() in {"buffer", "tokeninformation"}:
            lengths = [len(str(v)) for v in vals if v is not None]
            variable[name] = {
                "observed": len(vals),
                "content_omitted": True,
                "min_rendered_length": min(lengths) if lengths else 0,
                "max_rendered_length": max(lengths) if lengths else 0,
            }
        else:
            variable[name] = _value_summary(vals)
    return stable, variable


def _coverage_map(all_records: list[dict], filtered_records: list[dict], scoped_log: str) -> dict:
    rate_cap_lines = [line for line in scoped_log.splitlines() if API_RATE_CAP_RE.search(line)]
    disabled = []
    for line in rate_cap_lines:
        m = API_RATE_CAP_RE.search(line)
        if m and m.group(1) not in disabled:
            disabled.append(m.group(1))

    total = Counter(str(r.get("api") or "<none>") for r in all_records)
    clean = Counter(str(r.get("api") or "<none>") for r in filtered_records)
    framework = Counter(
        str(r.get("api") or "<none>")
        for r in all_records if r.get("filter_from_clean_view")
    )
    disabled_lower = {x.lower(): x for x in disabled}
    names = list(dict.fromkeys(list(total.keys()) + disabled))
    result: dict[str, dict] = {}
    framework_only_caps = []
    for name in names:
        capped = name.lower() in disabled_lower
        observed_total = int(total.get(name, 0))
        clean_calls = int(clean.get(name, 0))
        framework_calls = int(framework.get(name, 0))
        framework_only = bool(
            capped
            and observed_total > 0
            and clean_calls == 0
            and framework_calls >= observed_total
        )
        if framework_only:
            framework_only_caps.append(name)
        result[name] = {
            "state": "rate_capped" if capped else "observed",
            "count_semantics": "lower_bound" if capped else "observed",
            "observed_total": observed_total,
            "clean_view_calls": clean_calls,
            "framework_calls": framework_calls,
            "rate_cap_detected": capped,
            "coverage_impact": (
                "framework_only" if framework_only
                else ("malware_visible_or_unknown" if capped else "none")
            ),
        }
        if capped:
            result[name]["interpretation"] = (
                "CAPEMON disabled this API hook due to rate; observed counts are a lower bound "
                "and absence after the rate-cap event is not evidence of no activity."
            )
    if not disabled:
        status = "full_observed"
    elif len(framework_only_caps) == len(disabled):
        status = "expected_framework_rate_cap"
    else:
        status = "degraded"
    return {
        "status": status,
        "disabled_hooks": disabled,
        "framework_only_rate_caps": framework_only_caps,
        "rate_cap_event_count": len(rate_cap_lines),
        "by_api": result,
        "examples": rate_cap_lines[:10],
    }


def _burst_record(group: list[dict], coverage: dict) -> dict:
    first = group[0]
    call = first.get("call") if isinstance(first.get("call"), dict) else {}
    api = str(first.get("api") or "<none>")
    api_l = api.lower()
    times = [_parse_time(r.get("timestamp")) for r in group]
    valid_times = [t for t in times if t is not None]
    duration_ms = 0.0
    if valid_times:
        duration_ms = max(0.0, (max(valid_times) - min(valid_times)).total_seconds() * 1000.0)
    call_ids = [r.get("call_id") for r in group if r.get("call_id") is not None]
    stable, variable = _summarize_arguments(group, api_l)
    api_cov = ((coverage.get("by_api") or {}).get(api) or {})
    if api_cov.get("state") == "rate_capped":
        interpretation = "high_volume_uncertain_rate_capped"
    else:
        interpretation = "high_volume_observation"
    samples = call_ids[: MAX_CALL_ID_SAMPLES // 2]
    if len(call_ids) > MAX_CALL_ID_SAMPLES:
        samples += call_ids[-(MAX_CALL_ID_SAMPLES // 2):]
    elif len(call_ids) > len(samples):
        samples = call_ids
    return {
        "record_type": "burst",
        "semantic_class": interpretation,
        "pid": first.get("pid"),
        "process_name": first.get("process_name"),
        "process_path": first.get("process_path"),
        "thread_id": call.get("thread_id"),
        "category": first.get("category"),
        "api": api,
        "provenance": first.get("provenance"),
        "confidence": first.get("confidence"),
        "caller": call.get("caller"),
        "parentcaller": call.get("parentcaller"),
        "count": len(group),
        "first_call_id": call_ids[0] if call_ids else None,
        "last_call_id": call_ids[-1] if call_ids else None,
        "call_id_samples": samples,
        "first_timestamp": group[0].get("timestamp"),
        "last_timestamp": group[-1].get("timestamp"),
        "duration_ms": round(duration_ms, 3),
        "stable_arguments": stable,
        "variable_arguments": variable,
        "coverage": api_cov,
        "source": "behavior.filtered.jsonl",
        "reversible_via_raw_clean_view": True,
        "provenance_unchanged": True,
    }


def compact_records(filtered_records: list[dict], coverage: dict) -> tuple[list[dict], dict]:
    groups: dict[tuple, list[int]] = defaultdict(list)
    for idx, record in enumerate(filtered_records):
        api_l = str(record.get("api") or "").lower()
        if api_l in COMPACTABLE_APIS:
            groups[_semantic_key(record)].append(idx)

    burst_for_index: dict[int, dict] = {}
    consumed: set[int] = set()
    burst_counts = Counter()
    source_calls_compacted = 0
    for indices in groups.values():
        if len(indices) < COMPACT_MIN_GROUP_COUNT:
            continue
        group = [filtered_records[i] for i in indices]
        times = [_parse_time(r.get("timestamp")) for r in group]
        valid_times = [t for t in times if t is not None]
        if len(valid_times) != len(group):
            continue
        span_ms = (max(valid_times) - min(valid_times)).total_seconds() * 1000.0
        if span_ms < 0 or span_ms > COMPACT_MAX_GROUP_SPAN_MS:
            continue
        burst = _burst_record(group, coverage)
        first_idx = indices[0]
        burst_for_index[first_idx] = burst
        consumed.update(indices)
        burst_counts[str(burst.get("api") or "<none>")] += 1
        source_calls_compacted += len(indices)

    compact: list[dict] = []
    for idx, record in enumerate(filtered_records):
        if idx in burst_for_index:
            compact.append(burst_for_index[idx])
            continue
        if idx in consumed:
            continue
        compact.append({
            "record_type": "event",
            "count": 1,
            "pid": record.get("pid"),
            "process_name": record.get("process_name"),
            "process_path": record.get("process_path"),
            "call_id": record.get("call_id"),
            "timestamp": record.get("timestamp"),
            "category": record.get("category"),
            "api": record.get("api"),
            "provenance": record.get("provenance"),
            "confidence": record.get("confidence"),
            "call": record.get("call"),
            "possible_reasons": record.get("possible_reasons", []),
            "source": "behavior.filtered.jsonl",
        })

    expanded_count = sum(int(r.get("count") or 0) for r in compact)
    summary = {
        "raw_clean_calls": len(filtered_records),
        "semantic_records": len(compact),
        "burst_records": sum(burst_counts.values()),
        "source_calls_compacted": source_calls_compacted,
        "display_records_saved": len(filtered_records) - len(compact),
        "compaction_ratio": round((len(compact) / len(filtered_records)), 4) if filtered_records else 1.0,
        "expanded_source_call_count": expanded_count,
        "expansion_invariant_ok": expanded_count == len(filtered_records),
        "bursts_by_api": dict(burst_counts),
        "minimum_group_count": COMPACT_MIN_GROUP_COUNT,
        "maximum_group_span_ms": COMPACT_MAX_GROUP_SPAN_MS,
        "compactable_apis": sorted(COMPACTABLE_APIS),
    }
    return compact, summary


def build_compact_view(
    analysis_dir: Path,
    output_dir: Path | None = None,
    runtime: dict | None = None,
) -> dict:
    analysis_dir = Path(analysis_dir).resolve()
    output_dir = Path(output_dir or analysis_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if runtime is None:
        _, runtime = load_runtime_for_analysis(analysis_dir)
    runtime = runtime or {}

    provenance_path = output_dir / "behavior.provenance.jsonl"
    filtered_path = output_dir / "behavior.filtered.jsonl"
    all_records = _load_jsonl(provenance_path)
    filtered_records = _load_jsonl(filtered_path)
    if not filtered_path.is_file():
        result = {
            "schema": "capesolo-frida-behavior-compact/3.2.3",
            "version": product_version_for_runtime(runtime),
            "processor_version": PRODUCT_VERSION,
            "run_id": runtime.get("run_id"),
            "available": False,
            "reason": "behavior_filtered_jsonl_not_found",
            "summary": {},
        }
        (output_dir / "frida_behavior_compact.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return result

    full_log = ""
    log_path = analysis_dir / "analysis.log"
    if log_path.is_file():
        full_log = log_path.read_text(encoding="utf-8", errors="replace")
    scoped_log, run_scope = select_run_log(full_log, runtime)
    coverage = _coverage_map(all_records, filtered_records, scoped_log)
    compact, summary = compact_records(filtered_records, coverage)

    compact_path = output_dir / "behavior.compact.jsonl"
    with compact_path.open("w", encoding="utf-8", newline="\n") as fh:
        for record in compact:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    result = {
        "schema": "capesolo-frida-behavior-compact/3.2.3",
        "version": product_version_for_runtime(runtime),
        "processor_version": PRODUCT_VERSION,
        "run_id": runtime.get("run_id"),
        "available": True,
        "run_scope": run_scope,
        "source_filtered": str(filtered_path),
        "source_provenance": str(provenance_path),
        "compact_jsonl": str(compact_path),
        "summary": summary,
        "api_coverage": coverage,
        "notes": [
            "P3.2.2 compact view is presentation-only; behavior.filtered.jsonl remains the lossless clean evidence stream.",
            "Compaction does not change provenance labels or infer Frida attribution.",
            "Only high-volume observational/query APIs are eligible for burst compaction.",
            "Rate-capped API counts are lower bounds; missing calls after CAPEMON disables a hook are not interpreted as absence of activity.",
            "Framework-only rate caps are separated from malware-visible or unknown coverage loss.",
        ],
    }
    summary_path = output_dir / "frida_behavior_compact.json"
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    result["summary_path"] = str(summary_path)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=Path("."))
    ap.add_argument("--output-dir", type=Path)
    args = ap.parse_args()
    result = build_compact_view(args.analysis_dir, args.output_dir)
    print(json.dumps({
        "summary": result.get("summary", {}),
        "api_coverage": result.get("api_coverage", {}),
    }, indent=2, ensure_ascii=False))
    if result.get("compact_jsonl"):
        print(result["compact_jsonl"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
