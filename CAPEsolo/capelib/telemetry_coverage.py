"""Per-PID hook caps; unrelated processes never degrade tracked API counts."""
from __future__ import annotations
import re
from collections import Counter

CAP_RE = re.compile(r"api-rate-cap:\s+([A-Za-z0-9_]+)\s+hook disabled due to rate", re.I)
PID_RE = re.compile(r"\b(\d+):\s*api-rate-cap:", re.I)


def rate_cap_events(text, tracked_pids):
    tracked = {int(p) for p in tracked_pids}
    events = []
    for line in text.splitlines():
        match = CAP_RE.search(line)
        if not match:
            continue
        pid_match = PID_RE.search(line)
        pid = int(pid_match.group(1)) if pid_match else None
        scope = "unknown" if pid is None or not tracked else "tracked" if pid in tracked else "background"
        events.append({"pid": pid, "api": match.group(1), "scope": scope, "line": line})
    return events


def coverage_map(all_records, filtered_records, scoped_log, tracked_pids=None):
    def key(row):
        return row.get("pid"), str(row.get("api") or (row.get("call") or {}).get("api") or "<none>")
    total = Counter(key(r) for r in all_records)
    clean = Counter(key(r) for r in filtered_records)
    framework = Counter(key(r) for r in all_records if r.get("filter_from_clean_view") and r.get("provenance") != "untracked_process")
    tracked = set(tracked_pids or (r.get("pid") for r in filtered_records if r.get("pid") is not None))
    events = rate_cap_events(scoped_log, tracked)
    relevant = [e for e in events if e["scope"] != "background"]
    by_pid = {}
    for pid, name in dict.fromkeys(list(total) + list(clean) + [(e["pid"], e["api"]) for e in events]):
        capped = any(e["api"].lower() == name.lower() and (e["pid"] is None or e["pid"] == pid) for e in relevant)
        observed, visible, removed = total[pid, name], clean[pid, name], framework[pid, name]
        framework_only = bool(capped and observed > 0 and visible == 0 and removed == observed)
        by_pid[f"{pid}:{name}"] = {"pid": pid, "api": name, "state": "rate_capped" if capped else "observed",
            "count_semantics": "lower_bound" if capped else "observed", "observed_total": observed,
            "clean_view_calls": visible, "framework_calls": removed, "rate_cap_detected": capped,
            "coverage_impact": "framework_only" if framework_only else "malware_visible_or_unknown" if capped else "none"}
    disabled = list(dict.fromkeys(e["api"] for e in relevant))
    by_api = {}
    framework_only_caps = []
    for name in dict.fromkeys([n for _, n in total] + [n for _, n in clean] + disabled):
        rows = [r for r in by_pid.values() if r["api"] == name and (not tracked or r["pid"] in tracked or r["pid"] is None)]
        caps = [r for r in rows if r["rate_cap_detected"]]
        framework_only = bool(caps and all(r["coverage_impact"] == "framework_only" for r in caps))
        if framework_only:
            framework_only_caps.append(name)
        by_api[name] = {"state": "rate_capped" if caps else "observed", "count_semantics": "lower_bound" if caps else "observed",
            "observed_total": sum(r["observed_total"] for r in rows), "clean_view_calls": sum(r["clean_view_calls"] for r in rows),
            "framework_calls": sum(r["framework_calls"] for r in rows), "rate_cap_detected": bool(caps),
            "coverage_impact": "framework_only" if framework_only else "malware_visible_or_unknown" if caps else "none",
            "affected_pids": sorted({r["pid"] for r in caps if r["pid"] is not None})}
    return {"status": "full_observed" if not disabled else "expected_framework_rate_cap" if len(framework_only_caps) == len(disabled) else "degraded",
            "disabled_hooks": disabled, "framework_only_rate_caps": framework_only_caps,
            "rate_cap_event_count": len(relevant), "all_rate_cap_event_count": len(events),
            "background_rate_caps": [e for e in events if e["scope"] == "background"],
            "unknown_pid_rate_caps": [e for e in events if e["scope"] == "unknown"],
            "events": events, "by_api": by_api, "by_pid_api": by_pid,
            "examples": [e["line"] for e in relevant[:10]]}
