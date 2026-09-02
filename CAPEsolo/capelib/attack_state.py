"""Small deterministic state-machine primitives for ATT&CK analytics.

P3.2.3.14 normalizes sensor output before evaluating a rule.  These classes do
not inspect strings or API names; they consume semantic events produced by the
sensor adapters in :mod:`mitre_attack`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


def parse_timestamp(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            pass
    try:
        return float(value)
    except (TypeError, ValueError):
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
    """Evaluate ordered required states inside one PID/target correlation key."""
    grouped: dict[tuple[str, str], list[EvidenceEvent]] = {}
    for event in events:
        target = event.target if rule.require_same_target else "*"
        grouped.setdefault((event.pid, target), []).append(event)

    best = {"complete": False, "matched": [], "missing": list(rule.required), "optional": [], "key": None}
    for key, group in grouped.items():
        ordered = sorted(group, key=lambda item: (item.timestamp is None, item.timestamp or 0.0))
        matched: list[EvidenceEvent] = []
        cursor = 0
        start = None
        for event in ordered:
            if cursor >= len(rule.required) or event.kind != rule.required[cursor]:
                continue
            if start is None:
                start = event.timestamp
            if start is not None and event.timestamp is not None and event.timestamp - start > rule.window_seconds:
                continue
            matched.append(event)
            cursor += 1
        optional = [event for event in ordered if event.kind in rule.optional]
        candidate = {
            "complete": cursor == len(rule.required),
            "matched": matched,
            "missing": list(rule.required[cursor:]),
            "optional": optional,
            "key": {"pid": key[0], "target": key[1]},
        }
        if (candidate["complete"], len(candidate["matched"]), len(candidate["optional"])) > (
            best["complete"], len(best["matched"]), len(best["optional"])
        ):
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
    grouped: dict[str, list[EvidenceEvent]] = {}
    for event in events:
        grouped.setdefault(event.pid, []).append(event)
    best = {"complete": False, "matched": [], "missing_count": minimum, "key": None}
    for pid, group in grouped.items():
        ordered = sorted(group, key=lambda item: (item.timestamp is None, item.timestamp or 0.0))
        for index, first in enumerate(ordered):
            window = [first]
            for event in ordered[index + 1:]:
                if first.timestamp is not None and event.timestamp is not None and event.timestamp - first.timestamp > window_seconds:
                    break
                window.append(event)
            distinct = {}
            for event in window:
                distinct.setdefault(str(event.attributes.get(attribute) or event.kind), event)
            candidate = {
                "complete": len(distinct) >= minimum,
                "matched": list(distinct.values()),
                "missing_count": max(0, minimum - len(distinct)),
                "key": {"pid": pid, "target": target_label},
            }
            if (candidate["complete"], len(candidate["matched"])) > (best["complete"], len(best["matched"])):
                best = candidate
    best["state_trace"] = [str(event.attributes.get(attribute) or event.kind) for event in best["matched"]]
    best["missing"] = [] if best["complete"] else [f"{best['missing_count']} additional {missing_label}"]
    return best
