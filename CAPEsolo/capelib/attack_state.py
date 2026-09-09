"""Small deterministic state-machine primitives for ATT&CK analytics.

P3.2.3.16 normalizes sensor output before evaluating a rule.  These classes do
not inspect strings or API names; they consume semantic events produced by the
sensor adapters in :mod:`mitre_attack`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from collections import deque
from typing import Any, Iterable


def parse_timestamp(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    try:
        number = float(text)
        return number if math.isfinite(number) else None
    except (ValueError, TypeError):
        pass
    try:
        parsed = datetime.fromisoformat(text.replace(",", ".").replace("Z", "+00:00"))
        # CAPE timestamps are naive guest times: use a stable UTC coordinate for
        # within-stream deltas, never the reviewing machine's local timezone.
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


@dataclass(frozen=True)
class EvidenceEvent:
    kind: str
    pid: str
    target: str
    timestamp: float | None
    evidence: dict[str, Any]
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SequenceRule:
    rule_id: str
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()
    window_seconds: float = 600.0
    require_same_target: bool = True


def evaluate_sequence(rule: SequenceRule, events: Iterable[EvidenceEvent]) -> dict[str, Any]:
    """Keep the newest viable prefix for each state; never correlate unknown keys.

    Time-less single events can prove an API operation, but not a multi-event
    sequence or optional corroboration. Equal timestamps preserve input order.
    """
    best = {"complete": False, "matched": [], "missing": list(rule.required), "optional": [], "key": None}
    grouped = {}
    for event in events:
        if not event.pid or str(event.pid).lower() in {"0", "unknown", "none"}:
            continue
        target = event.target if rule.require_same_target else "*"
        if not target or str(target).lower() in {"unknown", "none"}:
            continue
        grouped.setdefault((str(event.pid), str(target)), []).append(event)
    for key, group in grouped.items():
        ordered = sorted(group, key=lambda e: (e.timestamp is None, e.timestamp or 0.0))
        prefixes = {}
        for event in ordered:
            for n, prefix in list(prefixes.items()):
                if event.timestamp is None or prefix[0].timestamp is None or event.timestamp - prefix[0].timestamp > rule.window_seconds:
                    del prefixes[n]
            # Descending states prevents one event satisfying repeated states.
            for n in range(len(rule.required) - 1, -1, -1):
                if event.kind != rule.required[n] or (n and n not in prefixes):
                    continue
                matched = (prefixes[n] if n else []) + [event]
                prefixes[n + 1] = matched
                optional = [e for e in ordered if e.kind in rule.optional
                            and e.timestamp is not None and matched[0].timestamp is not None
                            and abs(e.timestamp - matched[0].timestamp) <= rule.window_seconds]
                candidate = {"complete": n + 1 == len(rule.required), "matched": matched,
                             "missing": list(rule.required[n + 1:]), "optional": optional,
                             "key": {"pid": key[0], "target": key[1]}}
                if (candidate["complete"], len(matched), len(optional)) > (best["complete"], len(best["matched"]), len(best["optional"])):
                    best = candidate
    best["state_trace"] = [event.kind for event in best["matched"]]
    best["optional_states"] = sorted({event.kind for event in best["optional"]})
    return best


def evaluate_distinct(rule_id: str, events: Iterable[EvidenceEvent], minimum: int,
                      window_seconds: float = 30.0, *, attribute: str = "check_type",
                      target_label: str = "environment",
                      missing_label: str = "distinct system check(s)") -> dict[str, Any]:
    """Evaluate a compound analytic requiring distinct normalized states.

    ``attribute`` selects the semantic-event attribute used for distinctness.
    Keeping this in the state engine prevents ATT&CK adapters from falling back
    to substring/count-only rules.  The defaults preserve the environment-check
    behavior introduced in P3.2.3.12.
    """
    grouped = {}
    for event in events:
        if event.pid and str(event.pid).lower() not in {"unknown", "none", "0"}:
            grouped.setdefault(str(event.pid), []).append(event)
    best = {"complete": False, "matched": [], "missing_count": minimum, "key": None}
    for pid, group in grouped.items():
        window = deque()
        buckets = {}
        ordered = sorted(group, key=lambda e: (e.timestamp is None, e.timestamp or 0.0))
        for event in ordered:
            while window and (event.timestamp is None or window[0].timestamp is None or event.timestamp - window[0].timestamp > window_seconds):
                old = window.popleft()
                tag = str(old.attributes.get(attribute) or old.kind)
                buckets[tag].popleft()
                if not buckets[tag]:
                    del buckets[tag]
            tag = str(event.attributes.get(attribute) or event.kind)
            window.append(event)
            buckets.setdefault(tag, deque()).append(event)
            if len(buckets) > len(best["matched"]):
                matched = [values[0] for values in buckets.values()]
                best = {"complete": len(matched) >= minimum, "matched": matched,
                        "missing_count": max(0, minimum - len(matched)),
                        "key": {"pid": pid, "target": target_label}}
    best["state_trace"] = [str(event.attributes.get(attribute) or event.kind) for event in best["matched"]]
    best["missing"] = [] if best["complete"] else [f"{best['missing_count']} additional {missing_label}"]
    return best
