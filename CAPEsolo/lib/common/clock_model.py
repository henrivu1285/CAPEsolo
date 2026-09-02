"""Segment-aware clock correlation for CAPEsolo network evidence.

The capture agent timestamps packets in the Ubuntu wall-clock domain while
Sysmon timestamps events in the Windows guest wall-clock domain.  A sequence
of midpoint samples measures ``agent_time - guest_time``.  This module keeps
the original timestamps intact and describes whether each interval is stable,
continuously slewing, or unsafe because it contains a likely clock step.

The classifier is deliberately conservative for sparse legacy samples.  Two
points separated by a large offset change cannot distinguish a step from a
slew and therefore remain unusable.  Three or more points can establish a
same-direction continuation; only then may a large interval be treated as
slew.  New P3.2.3.14 samples also carry monotonic clocks for diagnostics.
"""

from __future__ import annotations


DEFAULT_MAX_UNCERTAINTY_NS = 250 * 1000 * 1000
DEFAULT_SLEW_THRESHOLD_NS = 500 * 1000 * 1000
DEFAULT_DISCONTINUITY_NS = 2 * 1000 * 1000 * 1000
MIN_SLEW_CONTINUATION_NS = 250 * 1000 * 1000


def _integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sign(value):
    return 1 if value > 0 else (-1 if value < 0 else 0)


def _neighbor_support(deltas, index):
    """Return whether a large delta belongs to a continuing same-sign trend."""
    current = deltas[index]
    required = max(MIN_SLEW_CONTINUATION_NS, int(abs(current) * 0.20))
    neighbors = []
    if index:
        neighbors.append(deltas[index - 1])
    if index + 1 < len(deltas):
        neighbors.append(deltas[index + 1])
    return any(
        _sign(value) == _sign(current) and abs(value) >= required
        for value in neighbors
    )


def analyze_clock_samples(
    raw_points,
    max_uncertainty_ns=DEFAULT_MAX_UNCERTAINTY_NS,
    slew_threshold_ns=DEFAULT_SLEW_THRESHOLD_NS,
    discontinuity_ns=DEFAULT_DISCONTINUITY_NS,
):
    """Return a JSON-serializable segment/slew model for midpoint samples."""
    points = []
    all_points = []
    for raw in raw_points or []:
        if not isinstance(raw, dict):
            continue
        server_ns = _integer(raw.get("server_time_ns"))
        offset_ns = _integer(raw.get("offset_ns"))
        uncertainty_ns = _integer(raw.get("uncertainty_ns"), 0)
        if server_ns is None or offset_ns is None:
            continue
        item = dict(raw)
        item["server_time_ns"] = server_ns
        item["offset_ns"] = offset_ns
        item["uncertainty_ns"] = max(0, uncertainty_ns or 0)
        all_points.append(item)
        if (
            str(item.get("status") or "") != "unreliable"
            and item["uncertainty_ns"] <= int(max_uncertainty_ns)
        ):
            points.append(item)
    all_points.sort(key=lambda item: item["server_time_ns"])
    points.sort(key=lambda item: item["server_time_ns"])

    offsets = [item["offset_ns"] for item in points]
    deltas = [right - left for left, right in zip(offsets, offsets[1:])]
    intervals = []
    unsafe = []
    slew = []
    max_step_ns = 0
    for index, (left, right) in enumerate(zip(points, points[1:])):
        delta_ns = deltas[index]
        absolute_ns = abs(delta_ns)
        max_step_ns = max(max_step_ns, absolute_ns)
        server_span_ns = max(0, right["server_time_ns"] - left["server_time_ns"])
        if absolute_ns <= int(slew_threshold_ns):
            classification = "stable"
            reason = "offset_change_within_stable_threshold"
        elif absolute_ns <= int(discontinuity_ns):
            classification = "slew"
            reason = "bounded_continuous_offset_change"
        elif len(points) >= 3 and _neighbor_support(deltas, index):
            classification = "slew"
            reason = "same_direction_neighbor_continuation"
        else:
            classification = "discontinuity"
            reason = "large_isolated_offset_step"

        client_wall_span_ns = None
        client_mono_span_ns = None
        server_mono_span_ns = None
        client_wall_adjustment_ns = None
        server_wall_adjustment_ns = None
        left_client_wall = _integer(left.get("client_midpoint_time_ns"))
        right_client_wall = _integer(right.get("client_midpoint_time_ns"))
        left_client_mono = _integer(left.get("client_midpoint_monotonic_ns"))
        right_client_mono = _integer(right.get("client_midpoint_monotonic_ns"))
        left_server_mono = _integer(left.get("server_monotonic_ns"))
        right_server_mono = _integer(right.get("server_monotonic_ns"))
        if left_client_wall is not None and right_client_wall is not None:
            client_wall_span_ns = right_client_wall - left_client_wall
        if left_client_mono is not None and right_client_mono is not None:
            client_mono_span_ns = right_client_mono - left_client_mono
        if left_server_mono is not None and right_server_mono is not None:
            server_mono_span_ns = right_server_mono - left_server_mono
        if client_wall_span_ns is not None and client_mono_span_ns is not None:
            client_wall_adjustment_ns = client_wall_span_ns - client_mono_span_ns
        if server_mono_span_ns is not None:
            server_wall_adjustment_ns = server_span_ns - server_mono_span_ns

        interval = {
            "index": index,
            "server_start_ns": left["server_time_ns"],
            "server_end_ns": right["server_time_ns"],
            "offset_before_ns": left["offset_ns"],
            "offset_after_ns": right["offset_ns"],
            "offset_delta_ns": delta_ns,
            "step_ns": absolute_ns,
            "step_ms": round(absolute_ns / 1_000_000.0, 3),
            "server_span_ns": server_span_ns,
            "classification": classification,
            "reason": reason,
            "client_wall_span_ns": client_wall_span_ns,
            "client_monotonic_span_ns": client_mono_span_ns,
            "server_monotonic_span_ns": server_mono_span_ns,
            "client_wall_adjustment_ns": client_wall_adjustment_ns,
            "server_wall_adjustment_ns": server_wall_adjustment_ns,
        }
        intervals.append(interval)
        if classification == "discontinuity":
            unsafe.append(dict(interval))
        elif classification == "slew":
            slew.append(dict(interval))

    offset_span_ns = max(offsets) - min(offsets) if len(offsets) > 1 else 0
    if not points:
        status, model, usable = "unreliable", "unavailable", False
    elif len(points) == 1:
        status = str(points[0].get("status") or "offset_compensated")
        model, usable = "single_sample", True
    elif unsafe and len(points) == 2:
        status, model, usable = "clock_discontinuity", "rejected_discontinuity", False
    elif unsafe:
        status, model, usable = "clock_segmented", "piecewise_segmented", True
    elif slew:
        status, model, usable = "clock_slew_compensated", "piecewise_linear_slew", True
    else:
        status = str(min(points, key=lambda item: item.get("uncertainty_ns", 0)).get("status") or "offset_compensated")
        model = "linear_interpolation" if len(points) == 2 else "piecewise_linear"
        usable = True

    segments = []
    segment_start = None
    for item in unsafe:
        segments.append({
            "server_start_ns": segment_start,
            "server_end_ns": item["server_start_ns"],
            "usable": True,
        })
        segments.append({
            "server_start_ns": item["server_start_ns"],
            "server_end_ns": item["server_end_ns"],
            "usable": False,
            "reason": "clock_discontinuity_interval",
        })
        segment_start = item["server_end_ns"]
    if unsafe:
        segments.append({"server_start_ns": segment_start, "server_end_ns": None, "usable": True})
    elif points:
        segments.append({"server_start_ns": None, "server_end_ns": None, "usable": True})

    return {
        "sample_points": all_points,
        "reliable_points": points,
        "samples": len(all_points),
        "reliable_samples": len(points),
        "status": status,
        "model": model,
        "usable": usable,
        "full_capture_usable": bool(usable and not unsafe),
        "fallback_allowed": not bool(unsafe),
        "slew_detected": bool(slew),
        "slew_intervals": slew,
        "discontinuity_detected": bool(unsafe),
        "discontinuity_intervals": unsafe,
        "unusable_intervals": unsafe,
        "segments": segments,
        "offset_span_ns": offset_span_ns,
        "max_step_ns": max_step_ns,
        "drift_detected": offset_span_ns > int(slew_threshold_ns),
    }
