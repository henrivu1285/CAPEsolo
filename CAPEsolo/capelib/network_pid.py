"""Conservative PCAP-to-process correlation for CAPEsolo P3.2.3.14.

PCAP does not contain a Windows PID.  Sysmon Event ID 3 provides the process
identity and the 5-tuple at connect time; Event ID 22 provides the process that
requested a DNS name.  This module joins those independent observations without
inventing a process owner when the evidence is absent or ambiguous.
"""

from __future__ import annotations

import ipaddress
import json
import statistics
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

try:
    from .network import CollapseEvents
except ImportError:  # standalone tools/self-tests load this file by path
    from CAPEsolo.capelib.network import CollapseEvents

try:
    from CAPEsolo.lib.common.clock_model import analyze_clock_samples
except ImportError:  # pragma: no cover - package import is present in CAPEsolo
    from lib.common.clock_model import analyze_clock_samples


CLOCK_DISCONTINUITY_SECONDS = 2.0


def _load_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def discover_task_capture(analysis_dir):
    """Find only a capture bound to the current run (or a legacy/manual file).

    Once pcap_runtime.json exists, its run/status is authoritative. This keeps a
    dump.pcapng left by a failed previous attempt from entering a new report.
    """
    base = Path(analysis_dir)
    pcap_runtime = _load_json(base / "pcap_runtime.json")
    frida_runtime = _load_json(base / "frida_p3_runtime.json")
    if pcap_runtime:
        pcap_run = str(pcap_runtime.get("run_id") or "")
        current_run = str(frida_runtime.get("run_id") or "")
        if current_run and pcap_run != current_run:
            return None
        if str(pcap_runtime.get("status") or "").lower() != "complete":
            return None
        if not pcap_runtime.get("fetched"):
            return None
    for name in ("dump.pcapng", "dump.pcap"):
        candidate = base / name
        if candidate.is_file() and candidate.stat().st_size >= 24:
            return candidate
    return None


def load_network_evidence(analysis_dir, runtime=None):
    runtime = runtime if isinstance(runtime, dict) else _load_json(Path(analysis_dir) / "frida_p3_runtime.json")
    sysmon = runtime.get("sysmon") if isinstance(runtime.get("sysmon"), dict) else {}
    events = sysmon.get("network_events") if isinstance(sysmon.get("network_events"), list) else []
    lineage = runtime.get("lineage") if isinstance(runtime.get("lineage"), dict) else {}
    return events, lineage


def load_clock_sync(analysis_dir):
    """Load measured clock metadata, with a bounded legacy fallback.

    New agents provide an NTP-style request-midpoint sample. Older agents only
    recorded capture start/stop boundaries; their median offset remains usable
    when the estimated uncertainty fits inside the normal correlation window.
    """
    runtime = _load_json(Path(analysis_dir) / "pcap_runtime.json")
    measured = runtime.get("clock_sync") if isinstance(runtime.get("clock_sync"), dict) else {}
    if measured:
        if measured.get("sample_points"):
            modeled = analyze_clock_samples(measured.get("sample_points"))
            measured = {
                **measured,
                "schema": "capesolo-clock-correlation/1.3",
                "status": modeled["status"],
                "model": modeled["model"],
                "usable": modeled["usable"],
                "full_capture_usable": modeled["full_capture_usable"],
                "fallback_allowed": modeled["fallback_allowed"],
                "reliable_samples": modeled["reliable_samples"],
                "offset_span_ns": modeled["offset_span_ns"],
                "max_step_ns": modeled["max_step_ns"],
                "drift_detected": modeled["drift_detected"],
                "slew_detected": modeled["slew_detected"],
                "slew_intervals": modeled["slew_intervals"],
                "discontinuity_detected": modeled["discontinuity_detected"],
                "discontinuity_intervals": modeled["discontinuity_intervals"],
                "unusable_intervals": modeled["unusable_intervals"],
                "segments": modeled["segments"],
                "raw_timestamps_modified": False,
            }
        return measured
    pairs = (
        ("capture_started_utc", "start_requested_utc"),
        ("capture_stopped_utc", "stop_requested_utc"),
    )
    offsets = []
    for agent_key, guest_key in pairs:
        agent_stamp = _timestamp(runtime.get(agent_key))
        guest_stamp = _timestamp(runtime.get(guest_key))
        if agent_stamp is not None and guest_stamp is not None:
            offsets.append(agent_stamp - guest_stamp)
    if not offsets:
        return {"status": "unavailable", "source": "none", "usable": False}
    offset = float(statistics.median(offsets))
    spread = (max(offsets) - min(offsets)) / 2.0 if len(offsets) > 1 else 0.0
    uncertainty = spread + 1.0
    return {
        "schema": "capesolo-clock-correlation/1.0",
        "status": "legacy_boundary_estimate",
        "source": "capture_start_stop_boundaries",
        "offset_semantics": "agent_time_minus_windows_guest_time",
        "offset_ns": int(offset * 1_000_000_000),
        "offset_ms": round(offset * 1000.0, 3),
        "uncertainty_ns": int(uncertainty * 1_000_000_000),
        "uncertainty_ms": round(uncertainty * 1000.0, 3),
        "samples": len(offsets),
        "usable": uncertainty <= 5.0,
        "fallback_allowed": True,
        "raw_timestamps_modified": False,
    }


def _timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def _ip(value):
    text = str(value or "").strip().strip("[]")
    try:
        address = ipaddress.ip_address(text)
        if getattr(address, "ipv4_mapped", None) is not None:
            address = address.ipv4_mapped
        return str(address)
    except ValueError:
        return text.lower()


def _port(value):
    text = str(value or "0").strip()
    try:
        return int(text, 0)
    except Exception:
        try:
            return int(text, 10)
        except Exception:
            return 0


def _protocol(value):
    text = str(value or "").strip().lower()
    if text in ("6", "tcp"):
        return "tcp"
    if text in ("17", "udp"):
        return "udp"
    return text


def _process_meta(event, lineage):
    pid = _port(event.get("process_id"))
    meta = lineage.get(str(pid), lineage.get(pid, {}))
    if not isinstance(meta, dict):
        meta = {}
    event_guid = str(event.get("process_guid") or "").strip("{}").upper()
    known_guid = str(meta.get("sysmon_guid") or "").strip("{}").upper()
    # ProcessGuid is the PID-reuse guard. A known mismatch invalidates the event
    # for this analysis lineage instead of silently assigning it to a reused PID.
    tracked = bool(meta) and not (event_guid and known_guid and event_guid != known_guid)
    return {
        "pid": pid or None,
        "process_guid": event_guid or None,
        "process": event.get("image") or meta.get("exe") or "",
        "role": meta.get("role") if tracked else None,
        "tracked": tracked,
    }


def _flow_tuple(flow):
    return (
        _ip(flow.get("src_ip")),
        _port(flow.get("src_port")),
        _ip(flow.get("dst_ip")),
        _port(flow.get("dst_port")),
        _protocol(flow.get("protocol")),
    )


def _event_tuple(event):
    return (
        _ip(event.get("source_ip")),
        _port(event.get("source_port")),
        _ip(event.get("destination_ip")),
        _port(event.get("destination_port")),
        _protocol(event.get("protocol")),
    )


def _clock_context(clock_sync, tolerance):
    value = clock_sync if isinstance(clock_sync, dict) else {}
    raw_points = value.get("sample_points") or []
    analysis = analyze_clock_samples(
        raw_points,
        max_uncertainty_ns=int(float(tolerance) * 1_000_000_000),
        slew_threshold_ns=500_000_000,
        discontinuity_ns=int(CLOCK_DISCONTINUITY_SECONDS * 1_000_000_000),
    ) if raw_points else None
    status = str((analysis or {}).get("status") or value.get("status") or "unavailable")
    try:
        offset = float(value.get("offset_ns")) / 1_000_000_000.0
        uncertainty = float(value.get("uncertainty_ns") or 0) / 1_000_000_000.0
    except (TypeError, ValueError):
        offset, uncertainty = 0.0, float("inf")
    usable_status = status in {
        "synchronized",
        "offset_compensated",
        "clock_slew_compensated",
        "clock_segmented",
        "legacy_boundary_estimate",
        "tuple_consensus_estimate",
    }
    explicit_usable = value.get("usable")
    usable = usable_status and uncertainty <= float(tolerance)
    # Re-evaluate legacy P3.2.3.13 sample points with the segment-aware model;
    # its old all-or-nothing ``usable=false`` must not veto a proven slew.
    if analysis is not None:
        usable = bool(analysis.get("usable"))
    elif isinstance(explicit_usable, bool):
        usable = usable and explicit_usable
    points = []
    reliable_source = (analysis or {}).get("reliable_points") or raw_points
    for item in reliable_source:
        if not isinstance(item, dict):
            continue
        try:
            server_time = float(item.get("server_time_ns")) / 1_000_000_000.0
            point_offset = float(item.get("offset_ns")) / 1_000_000_000.0
            point_uncertainty = float(item.get("uncertainty_ns") or 0) / 1_000_000_000.0
        except (TypeError, ValueError):
            continue
        if item.get("status") == "unreliable" or point_uncertainty > float(tolerance):
            continue
        points.append(
            {
                "server_time_seconds": server_time,
                "offset_seconds": point_offset,
                "uncertainty_seconds": point_uncertainty,
            }
        )
    points.sort(key=lambda item: item["server_time_seconds"])
    def _interval_seconds(item):
        start = item.get("server_start_ns")
        end = item.get("server_end_ns")
        return {
            **item,
            "server_start_seconds": (
                float(start) / 1_000_000_000.0 if start is not None else None
            ),
            "server_end_seconds": (
                float(end) / 1_000_000_000.0 if end is not None else None
            ),
            "offset_before_seconds": float(item.get("offset_before_ns") or 0) / 1_000_000_000.0,
            "offset_after_seconds": float(item.get("offset_after_ns") or 0) / 1_000_000_000.0,
            "step_seconds": float(item.get("step_ns") or 0) / 1_000_000_000.0,
        }

    configured_intervals = (
        (analysis or {}).get("discontinuity_intervals")
        if analysis is not None
        else value.get("unusable_intervals") or value.get("discontinuity_intervals") or []
    )
    unusable_intervals = [
        _interval_seconds(item) for item in configured_intervals
        if isinstance(item, dict)
    ]
    discontinuity = bool(unusable_intervals)
    if status == "clock_discontinuity":
        usable = False
    model = str((analysis or {}).get("model") or value.get("model") or "")
    if not model:
        if usable and len(points) >= 3:
            model = "piecewise_linear"
        elif usable and len(points) == 2:
            model = "linear_interpolation"
        elif usable:
            model = "single_sample"
        else:
            model = "unavailable"
    modeled_offset_span = (analysis or {}).get("offset_span_ns")
    offset_span_seconds = (
        float(modeled_offset_span) / 1_000_000_000.0
        if modeled_offset_span is not None else (
        float(value.get("offset_span_ns") or 0) / 1_000_000_000.0
        if value.get("offset_span_ns") is not None else (
            max((item["offset_seconds"] for item in points), default=0.0)
            - min((item["offset_seconds"] for item in points), default=0.0)
        ))
    )
    return {
        "status": status,
        "source": value.get("source") or "none",
        "offset_seconds": offset if usable else 0.0,
        "uncertainty_seconds": uncertainty if uncertainty != float("inf") else None,
        "compensation_applied": bool(usable and offset),
        "usable": usable,
        "fallback_allowed": bool(
            (analysis or {}).get("fallback_allowed", value.get("fallback_allowed", not discontinuity))
        ),
        "model": model,
        "sample_points": points,
        "drift_detected": bool((analysis or {}).get("drift_detected", value.get("drift_detected"))) or offset_span_seconds > 0.5,
        "slew_detected": bool((analysis or {}).get("slew_detected", value.get("slew_detected"))),
        "discontinuity_detected": discontinuity,
        "discontinuity_intervals": unusable_intervals,
        "unusable_intervals": unusable_intervals,
        "full_capture_usable": bool(usable and not discontinuity),
        "segments": (analysis or {}).get("segments", value.get("segments") or []),
        "offset_span_seconds": offset_span_seconds,
        "raw_timestamps_modified": False,
    }


def _offset_for_agent_stamp(stamp, clock):
    points = clock.get("sample_points") or []
    if len(points) < 2:
        return float(clock.get("offset_seconds") or 0.0)
    if stamp <= points[0]["server_time_seconds"]:
        return float(points[0]["offset_seconds"])
    if stamp >= points[-1]["server_time_seconds"]:
        return float(points[-1]["offset_seconds"])
    for left, right in zip(points, points[1:]):
        start = left["server_time_seconds"]
        end = right["server_time_seconds"]
        if start <= stamp <= end:
            width = end - start
            if width <= 0:
                return float(right["offset_seconds"])
            ratio = (stamp - start) / width
            return float(left["offset_seconds"]) + ratio * (
                float(right["offset_seconds"]) - float(left["offset_seconds"])
            )
    return float(clock.get("offset_seconds") or 0.0)


def _pcap_time_on_windows(value, clock):
    stamp = _timestamp(value)
    if stamp is None or not clock.get("usable"):
        return None
    for interval in clock.get("unusable_intervals") or []:
        start = interval.get("server_start_seconds")
        end = interval.get("server_end_seconds")
        if start is not None and end is not None and start < stamp < end:
            return None
    # Runtime offset semantics are agent_time - Windows_guest_time.
    return stamp - _offset_for_agent_stamp(stamp, clock)


def _range_intersects_unusable(first, last, clock):
    first_stamp = _timestamp(first)
    last_stamp = _timestamp(last)
    if first_stamp is None:
        return False
    if last_stamp is None:
        last_stamp = first_stamp
    low, high = sorted((first_stamp, last_stamp))
    for interval in clock.get("unusable_intervals") or []:
        start = interval.get("server_start_seconds")
        end = interval.get("server_end_seconds")
        if start is None or end is None:
            continue
        if low < end and high > start:
            return True
    return False


def _canonical_connection(key):
    left = (key[0], key[1])
    right = (key[2], key[3])
    return (min(left, right), max(left, right), key[4])


def _tuple_clock_context(flows, connects, tolerance, fallback):
    """Derive an offset only from a multi-connection 5-tuple consensus.

    This is a compatibility path for older agents. A single matching socket is
    never enough: at least two independent canonical connections must land in
    the same bounded offset cluster.
    """
    candidates = []
    for flow in flows or []:
        key = _flow_tuple(flow)
        flow_stamp = _timestamp(flow.get("first_seen", flow.get("time")))
        if flow_stamp is None:
            continue
        canonical = _canonical_connection(key)
        for event in connects:
            event_key = _event_tuple(event)
            if event_key != key and event_key != (key[2], key[3], key[0], key[1], key[4]):
                continue
            event_stamp = _timestamp(event.get("utc_time"))
            if event_stamp is not None:
                candidates.append((flow_stamp - event_stamp, canonical))
    if len(candidates) < 2:
        return fallback

    ordered = sorted(candidates, key=lambda item: item[0])
    best = []
    left = 0
    for right in range(len(ordered)):
        while ordered[right][0] - ordered[left][0] > float(tolerance):
            left += 1
        cluster = ordered[left : right + 1]
        if len(cluster) > len(best):
            best = cluster
    unique_connections = {item[1] for item in best}
    if len(best) < 2 or len(unique_connections) < 2:
        return fallback
    offsets = [item[0] for item in best]
    offset = float(statistics.median(offsets))
    uncertainty = max(abs(value - offset) for value in offsets) + 0.25
    if uncertainty > float(tolerance):
        return fallback
    return {
        "status": "tuple_consensus_estimate",
        "source": "pcap_sysmon_exact_5tuple_consensus",
        "offset_seconds": offset,
        "uncertainty_seconds": uncertainty,
        "compensation_applied": bool(offset),
        "usable": True,
        "model": "tuple_consensus_constant",
        "sample_points": [],
        "drift_detected": False,
        "samples": len(best),
        "unique_connections": len(unique_connections),
        "raw_timestamps_modified": False,
    }


def _in_window(event, first, last, tolerance, clock):
    stamp = _timestamp(event.get("utc_time"))
    if stamp is None:
        return False
    if _range_intersects_unusable(first, last, clock):
        return False
    first = _pcap_time_on_windows(first, clock)
    last = _pcap_time_on_windows(last, clock)
    if first is None:
        return False
    if last is None:
        last = first
    return first - tolerance <= stamp <= last + tolerance


def _attribution(candidates, method):
    if not candidates:
        return {
            "status": "unmapped",
            "confidence": "none",
            "method": method,
            "pid": None,
            "process": "",
            "role": None,
            "tracked": False,
            "candidate_count": 0,
        }
    identities = {
        (item.get("pid"), item.get("process_guid") or "")
        for item in candidates
    }
    if len(identities) != 1:
        return {
            "status": "ambiguous",
            "confidence": "none",
            "method": method,
            "pid": None,
            "process": "",
            "role": None,
            "tracked": False,
            "candidate_count": len(identities),
            "candidates": candidates[:8],
        }
    item = candidates[0]
    return {
        "status": "mapped",
        "confidence": "high" if method in ("sysmon_eid3_exact", "sysmon_eid22_name_time") else "medium",
        "method": method,
        "pid": item.get("pid"),
        "process_guid": item.get("process_guid"),
        "process": item.get("process") or "",
        "role": item.get("role"),
        "tracked": bool(item.get("tracked")),
        "candidate_count": 1,
        "sysmon_record_id": item.get("record_id"),
    }


def correlate_capture(capture, network_events, lineage=None, tolerance=5.0, clock_sync=None):
    """Return a copied capture with per-flow/DNS attribution and a summary."""
    output = deepcopy(capture or {})
    lineage = lineage if isinstance(lineage, dict) else {}
    connects = [event for event in network_events or [] if int(event.get("event_id") or 0) == 3]
    dns_events = [event for event in network_events or [] if int(event.get("event_id") or 0) == 22]
    clock = _clock_context(clock_sync, tolerance)
    if not clock.get("usable") and clock.get("fallback_allowed", True):
        clock = _tuple_clock_context(output.get("flows"), connects, tolerance, clock)

    flow_counts = {"total": 0, "mapped": 0, "high": 0, "medium": 0, "ambiguous": 0, "unmapped": 0, "tracked": 0}
    by_pid = {}
    flow_attribution = {}
    for flow in output.get("flows") or []:
        flow_counts["total"] += 1
        key = _flow_tuple(flow)
        exact = []
        reverse = []
        segment_unusable = bool(
            clock.get("usable") and _range_intersects_unusable(
                flow.get("first_seen", flow.get("time")),
                flow.get("last_seen", flow.get("time")),
                clock,
            )
        )
        if clock.get("usable") and not segment_unusable:
            for event in connects:
                if not _in_window(
                    event,
                    flow.get("first_seen", flow.get("time")),
                    flow.get("last_seen", flow.get("time")),
                    tolerance,
                    clock,
                ):
                    continue
                event_key = _event_tuple(event)
                item = {**_process_meta(event, lineage), "record_id": event.get("record_id")}
                if event_key == key:
                    exact.append(item)
                elif event_key == (key[2], key[3], key[0], key[1], key[4]):
                    reverse.append(item)
        if segment_unusable:
            attr = _attribution([], "clock_segment_unusable")
            attr["reason"] = "flow_overlaps_clock_discontinuity_interval"
        elif not clock.get("usable"):
            attr = _attribution([], "clock_correlation_unusable")
            attr["reason"] = clock.get("status") or "clock_unavailable"
        elif exact:
            attr = _attribution(exact, "sysmon_eid3_exact")
        elif reverse:
            attr = _attribution(reverse, "sysmon_eid3_reverse")
        else:
            attr = _attribution([], "sysmon_eid3_exact")
        flow["attribution"] = attr
        flow_attribution[_flow_tuple(flow)] = attr
        status = attr["status"]
        flow_counts[status] += 1
        if status == "mapped":
            flow_counts[attr["confidence"]] += 1
            if attr.get("tracked"):
                flow_counts["tracked"] += 1
            pid_key = str(attr.get("pid"))
            by_pid[pid_key] = by_pid.get(pid_key, 0) + 1

    dns_counts = {
        "total": 0, "requests_total": 0, "responses_total": 0,
        "mapped": 0, "ambiguous": 0, "unmapped": 0, "tracked": 0,
    }
    attributed_queries = []
    for event in output.get("events") or []:
        event_key = (
            _ip(event.get("src_ip")),
            _port(event.get("src_port")),
            _ip(event.get("dst_ip")),
            _port(event.get("dst_port")),
            _protocol(event.get("protocol")),
        )
        if event.get("kind") != "DNS":
            if event_key in flow_attribution:
                event["attribution"] = deepcopy(flow_attribution[event_key])
            continue
        dns = event.get("dns") if isinstance(event.get("dns"), dict) else {}
        if dns.get("response"):
            dns_counts["responses_total"] += 1
            continue
        dns_counts["total"] += 1
        dns_counts["requests_total"] += 1
        query = str(dns.get("query") or event.get("host") or "").rstrip(".").lower()
        stamp = event.get("time")
        candidates = []
        segment_unusable = bool(
            clock.get("usable") and _range_intersects_unusable(stamp, stamp, clock)
        )
        if clock.get("usable") and not segment_unusable:
            for source in dns_events:
                source_name = str(source.get("query_name") or "").rstrip(".").lower()
                source_stamp = _timestamp(source.get("utc_time"))
                event_stamp = _pcap_time_on_windows(stamp, clock)
                if not query or query != source_name or source_stamp is None or event_stamp is None:
                    continue
                if abs(source_stamp - event_stamp) > tolerance:
                    continue
                candidates.append({**_process_meta(source, lineage), "record_id": source.get("record_id")})
        if segment_unusable:
            method = "clock_segment_unusable"
        elif clock.get("usable"):
            method = "sysmon_eid22_name_time"
        else:
            method = "clock_correlation_unusable"
        attr = _attribution(candidates, method)
        if segment_unusable:
            attr["reason"] = "dns_event_inside_clock_discontinuity_interval"
        elif not clock.get("usable"):
            attr["reason"] = clock.get("status") or "clock_unavailable"
        # EID22 identifies who requested the name; it does not prove that this
        # PID owned the UDP packet when Windows DNS Client performed it.
        attr["semantics"] = "dns_requester_not_wire_owner"
        event["attribution"] = attr
        attributed_queries.append((query, _timestamp(stamp), deepcopy(attr)))
        dns_counts[attr["status"]] += 1
        if attr.get("tracked"):
            dns_counts["tracked"] += 1

    # A DNS response has no independent requester. Pair it to the nearest raw
    # query occurrence for presentation, while keeping request accounting tied
    # exclusively to EID22-backed query events.
    for event in output.get("events") or []:
        if event.get("kind") != "DNS":
            continue
        dns = event.get("dns") if isinstance(event.get("dns"), dict) else {}
        if not dns.get("response"):
            continue
        query = str(dns.get("query") or event.get("host") or "").rstrip(".").lower()
        stamp = _timestamp(event.get("time"))
        candidates = [
            item for item in attributed_queries
            if query and item[0] == query and stamp is not None and item[1] is not None
            and abs(stamp - item[1]) <= max(2.0, float(tolerance) * 2.0)
        ]
        if candidates:
            _, _, attr = min(candidates, key=lambda item: abs(stamp - item[1]))
            attr["semantics"] = "dns_requester_via_paired_query"
            event["attribution"] = attr
        else:
            event["attribution"] = _attribution([], "dns_response_pair")

    # Give each protocol event its directional flow attribution when available,
    # then derive the compact rows only after all raw occurrences were handled.
    for event in output.get("events") or []:
        if isinstance(event.get("attribution"), dict):
            continue
        event_key = (
            _ip(event.get("src_ip")), _port(event.get("src_port")),
            _ip(event.get("dst_ip")), _port(event.get("dst_port")),
            _protocol(event.get("protocol")),
        )
        if event_key in flow_attribution:
            event["attribution"] = deepcopy(flow_attribution[event_key])
    output["display_events"] = CollapseEvents(output.get("events") or [])

    output["attribution"] = {
        "schema": "capesolo-network-attribution/1.3",
        "method": "pcap_plus_sysmon_eid3_eid22",
        "time_tolerance_seconds": float(tolerance),
        "clock_correlation": clock,
        "flows": flow_counts,
        "dns": dns_counts,
        "by_pid": by_pid,
        "sysmon_connect_events": len(connects),
        "sysmon_dns_events": len(dns_events),
        "raw_network_events_synthesized": False,
    }
    return output
