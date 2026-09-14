"""Offline SigmaHQ evaluator for P3 normalized Windows telemetry.

The bundled rule pack is parsed and compiled with pySigma at build time.  This
module evaluates only the constrained intermediate representation, never YAML,
and treats every Sigma-only ATT&CK hit as a candidate.  Native P3 state
machines remain the authority for ``observed`` mappings.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional
from CAPEsolo.capelib import native_semantics as ns


SCHEMA = "capesolo-sigma-runtime/1.0"
PACK_SCHEMA = "capesolo-sigma-pack/1.0"
MAX_EVENTS = 50000
MAX_MATCHES = 250
MAX_EVIDENCE_FIELDS = 16

FIELD_SCHEMAS = {
    "process_creation": {
        "EventID", "Image", "CommandLine", "CurrentDirectory", "ProcessId", "ParentProcessId",
        "ParentImage", "ParentCommandLine", "User", "Computer", "OriginalFileName",
        "Company", "Product", "Description",
    },
    "registry_set": {"EventID", "EventType", "Image", "ProcessId", "TargetObject", "Details", "User", "Computer"},
    "registry_add": {"EventID", "EventType", "Image", "ProcessId", "TargetObject", "Details", "User", "Computer"},
    "registry_delete": {"EventID", "EventType", "Image", "ProcessId", "TargetObject", "Details", "User", "Computer"},
    "registry_event": {"EventID", "EventType", "Image", "ProcessId", "TargetObject", "Details", "User", "Computer"},
    "file_event": {"EventID", "Image", "ProcessId", "TargetFilename", "SourceFilename", "User", "Computer"},
    "file_delete": {"EventID", "Image", "ProcessId", "TargetFilename", "User", "Computer"},
    "file_rename": {"EventID", "Image", "ProcessId", "TargetFilename", "SourceFilename", "User", "Computer"},
    "image_load": {"EventID", "Image", "ProcessId", "ImageLoaded", "User", "Computer"},
    "network_connection": {
        "EventID", "Image", "ProcessId", "User", "Computer", "Protocol", "Initiated", "SourceIp",
        "SourcePort", "DestinationIp", "DestinationHostname", "DestinationPort",
    },
    "dns_query": {"EventID", "Image", "ProcessId", "QueryName", "QueryResults"},
    "create_remote_thread": {
        "EventID", "SourceImage", "SourceProcessId", "TargetImage", "TargetProcessId", "StartAddress",
        "StartModule", "StartFunction",
    },
    "process_access": {
        "EventID", "SourceImage", "SourceProcessId", "TargetImage", "TargetProcessId", "GrantedAccess",
    },
    "pipe_created": {"EventID", "Image", "ProcessId", "PipeName", "Computer"},
    # P3 can parse EID 25 at collection time, but report.json currently does not
    # retain the raw event.  Keep the schema visible while declaring the sensor
    # unavailable until raw Sysmon evidence is exported.
    "process_tampering": {"EventID", "Image", "ProcessId", "Type", "Computer"},
}

BEHAVIOR_LOGSOURCES = {
    "process_creation", "registry_set", "registry_add", "registry_delete", "registry_event",
    "file_event", "file_delete", "file_rename", "image_load", "create_remote_thread",
    "process_access", "pipe_created",
}
NETWORK_LOGSOURCES = {"network_connection", "dns_query"}

for _category in ("file_event", "file_delete", "file_rename", "image_load", "registry_set", "registry_event", "network_connection"):
    FIELD_SCHEMAS[_category].update({"CommandLine", "ParentImage", "ParentCommandLine"})
FIELD_SCHEMAS["process_creation"].update({"Hashes", "FileVersion", "ParentUser"})
FIELD_SCHEMAS["process_access"].update({"SourceUser"})
FIELD_SCHEMAS["create_remote_thread"].update({"SourceCommandLine", "SourceParentImage"})


def _pack_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "sigma" / "sigmahq_windows_p3.json.gz"


def _load_pack(path: Optional[Path] = None) -> dict:
    selected = Path(path) if path else _pack_path()
    try:
        with gzip.open(selected, "rt", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) and value.get("schema") == PACK_SCHEMA else {}


def _args(call: dict) -> dict:
    value = call.get("arguments") or []
    if isinstance(value, dict):
        return value
    return {
        str(item.get("name")): item.get("value")
        for item in value if isinstance(item, dict) and item.get("name") is not None
    }


def _arg(arguments: dict, *names: str) -> Any:
    lowered = {str(key).casefold(): value for key, value in arguments.items()}
    for name in names:
        if name.casefold() in lowered:
            return lowered[name.casefold()]
    return None


def _completed(call: dict) -> bool:
    api = str(call.get("api") or "").casefold()
    if api == "isdebuggerpresent":
        return call.get("return") is not None or call.get("status") is not None
    return call.get("status") is not False and str(call.get("return") or "").casefold() not in {
        "0xffffffff", "-1", "false", "error",
    }


def _metadata(results: dict) -> tuple[dict[str, dict], dict[str, str]]:
    processes = [row for row in (results.get("behavior") or {}).get("processes") or [] if isinstance(row, dict)]
    by_pid = {str(row.get("process_id")): row for row in processes if row.get("process_id") is not None}
    paths = {pid: str(row.get("module_path") or row.get("process_name") or "") for pid, row in by_pid.items()}
    return by_pid, paths


def _version_info(results: dict) -> dict[str, str]:
    rows = ((results.get("target") or {}).get("pe") or {}).get("versioninfo") or []
    if isinstance(rows, dict):
        rows = [{"name": key, "value": value} for key, value in rows.items()]
    return {
        str(row.get("name") or "").casefold(): str(row.get("value") or "")
        for row in rows if isinstance(row, dict) and row.get("name")
    }


def _event(category: str, fields: dict, source: str, pid: Any = None, timestamp: Any = None, api: str = "") -> dict:
    clean = {str(key): value for key, value in fields.items() if value not in (None, "", [], {})}
    return {
        "category": category,
        "fields": clean,
        "evidence": {
            "source": source,
            "pid": pid,
            "timestamp": timestamp,
            "api": api,
        },
    }


def _iter_calls(results: dict, clean_rows: Optional[list[dict]]) -> Iterable[tuple[dict, dict]]:
    by_pid, _ = _metadata(results)
    if clean_rows is not None:
        for row in clean_rows:
            if not isinstance(row, dict) or not isinstance(row.get("call"), dict):
                continue
            if row.get("filter_from_clean_view") or row.get("provenance") in {"unknown", "framework_frida"}:
                continue
            process = by_pid.get(str(row.get("pid"))) or {
                "process_id": row.get("pid"), "process_name": row.get("process_name"), "module_path": row.get("process_path"),
            }
            call = dict(row["call"])
            if call.get("id") is None: call["id"] = row.get("call_id")
            if not call.get("timestamp"): call["timestamp"] = row.get("timestamp")
            yield process, call
        return
    for process in by_pid.values():
        for call in process.get("calls") or []:
            if not isinstance(call, dict) or call.get("filter_from_clean_view") is True:
                continue
            if call.get("provenance") == "framework_frida":
                continue
            yield process, call


def normalize_pipe_name(value: Any) -> str:
    """Remove a Windows pipe namespace, preserving meaningful inner components."""
    text = str(value)
    for prefix in ("\\??\\pipe\\", "\\\\.\\pipe\\", "\\\\?\\pipe\\", "\\Device\\NamedPipe\\"):
        if text.casefold().startswith(prefix.casefold()):
            return "\\" + text[len(prefix):]
    return text


def _pid_number(value: Any) -> Optional[int]:
    try:
        text = str(value).strip()
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except (ValueError, TypeError):
        return None


def normalize_events(results: dict, clean_rows: Optional[list[dict]] = None, analysis_path: Optional[Path] = None) -> tuple[list[dict], dict]:
    """Translate canonical P3 evidence into the Sigma default Windows fields."""
    events: list[dict] = []
    normalization = Counter()
    by_pid, paths = _metadata(results)
    version = _version_info(results)
    roots = [pid for pid, proc in by_pid.items() if str(proc.get("parent_id")) not in by_pid and proc.get("calls")]
    root_pid = roots[0] if len(roots) == 1 else None
    if analysis_path:
        try:
            runtime = json.loads((Path(analysis_path) / "frida_p3_runtime.json").read_text(encoding="utf-8"))
            explicit = str(runtime.get("target_pid") or "")
            if explicit in by_pid: root_pid = explicit
        except (OSError, ValueError, TypeError):
            pass
    target = results.get("target") or {}
    hashes = target.get("file") if isinstance(target.get("file"), dict) else target
    target_hashes = ",".join(f"{key.upper()}={hashes[key]}" for key in ("md5", "sha1", "sha256") if hashes.get(key))

    for pid, process in by_pid.items():
        environ = process.get("environ") or {}
        parent_pid = str(process.get("parent_id") or "")
        fields = {
            "EventID": 1,
            "Image": paths.get(pid),
            "CommandLine": environ.get("CommandLine"),
            "CurrentDirectory": environ.get("CurrentDirectory"),
            "ProcessId": process.get("process_id"),
            "ParentProcessId": process.get("parent_id"),
            "ParentImage": paths.get(parent_pid),
            "ParentCommandLine": ((by_pid.get(parent_pid) or {}).get("environ") or {}).get("CommandLine"),
            "ParentUser": ((by_pid.get(parent_pid) or {}).get("environ") or {}).get("UserName"),
            "User": environ.get("UserName"),
            "Computer": environ.get("ComputerName"),
        }
        if pid == root_pid:
            fields.update({
                "OriginalFileName": version.get("originalfilename"),
                "Company": version.get("companyname"),
                "Product": version.get("productname"),
                "Description": version.get("filedescription"),
                "FileVersion": version.get("fileversion"), "Hashes": target_hashes,
            })
        events.append(_event("process_creation", fields, "behavior_process", process.get("process_id"), process.get("first_seen")))

    for process, call in _iter_calls(results, clean_rows):
        if not _completed(call):
            continue
        api = str(call.get("api") or "")
        low = api.casefold()
        arguments = _args(call)
        pid = process.get("process_id")
        image = process.get("module_path") or process.get("process_name")
        environ = process.get("environ") or {}
        common = {"Image": image, "ProcessId": pid, "User": environ.get("UserName"), "Computer": environ.get("ComputerName")}
        common.update({"CommandLine": environ.get("CommandLine"),
                       "ParentImage": paths.get(str(process.get("parent_id"))),
                       "ParentCommandLine": ((by_pid.get(str(process.get("parent_id"))) or {}).get("environ") or {}).get("CommandLine")})
        when = call.get("timestamp")
        event_start = len(events)

        if low in {"createprocessw", "createprocessa", "ntcreateuserprocess"}:
            from CAPEsolo.capelib import native_semantics as ns
            child_pid = _pid_number(_arg(arguments, "ProcessId", "ProcessID"))
            # Explicit executable identity and child PID are required. A command
            # string alone can be ambiguous on Windows and is not enough here.
            child_image = _arg(arguments, "ApplicationName", "ImagePathName", "ImagePath")
            if ns.success(call) and child_image and child_pid and child_pid > 0 and child_pid != _pid_number(pid):
                fields = {"EventID": 1, "Image": child_image, "ProcessId": child_pid,
                          "CommandLine": _arg(arguments, "CommandLine"),
                          "ParentImage": image, "ParentProcessId": pid,
                          "ParentCommandLine": environ.get("CommandLine")}
                event = _event("process_creation", fields, "behavior_api", pid, when, api)
                event["evidence"]["target_pid"] = child_pid
                events.append(event)
                normalization["successful_process_creation_projected"] += 1

        if low.startswith("reg") or low.startswith("nt") and "key" in low:
            target = _arg(arguments, "FullName", "KeyName", "ObjectName", "TargetObject")
            value_name = _arg(arguments, "ValueName")
            if target and value_name and str(value_name).casefold() not in str(target).casefold():
                target = f"{target}\\{value_name}"
            details = _arg(arguments, "Buffer", "Data", "Value", "Details")
            category = None
            event_id = 13
            event_type = "SetValue"
            if low.startswith(("regsetvalue", "ntsetvaluekey")):
                category = "registry_set"
            elif low.startswith(("regdelete", "ntdeletekey", "ntdeletevaluekey")):
                category, event_id, event_type = "registry_delete", 12, "DeleteKey"
            elif low.startswith(("regcreatekey", "ntcreatekey")):
                disposition = str(_arg(arguments, "Disposition") or "").casefold()
                if disposition in {"1", "created", "reg_created_new_key"} or "created" in disposition:
                    category, event_id, event_type = "registry_add", 12, "CreateKey"
            if category and target:
                fields = dict(common, EventID=event_id, EventType=event_type, TargetObject=target, Details=details)
                events.append(_event(category, fields, "behavior_api", pid, when, api))
                events.append(_event("registry_event", fields, "behavior_api", pid, when, api))

        source_name = _arg(arguments, "ExistingFileName", "Source", "SourceFileName", "OldFileName")
        target_name = _arg(arguments, "FileName", "ObjectName", "HandleName", "TargetFilename", "NewFileName", "Destination")
        file_category = None
        event_id = 11
        if low.startswith(("deletefile", "ntdeletefile")):
            file_category, event_id = "file_delete", 23
        elif low.startswith(("movefile", "ntsetinformationfile")) and source_name and target_name:
            file_category = "file_rename"
        elif low.startswith(("copyfile", "writefile", "ntwritefile")):
            file_category = "file_event"
        elif low in {"ntcreatefile", "createfilea", "createfilew"}:
            from tools.frida_behavior_chains import _target_from_file_call
            if _target_from_file_call({"api": api, "call": call}): file_category = "file_event"
        if file_category and target_name:
            fields = dict(common, EventID=event_id, TargetFilename=target_name, SourceFilename=source_name)
            events.append(_event(file_category, fields, "behavior_api", pid, when, api))

        if low in {"ldrloaddll", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}:
            loaded = _arg(arguments, "FileName", "Module", "LibraryName")
            if loaded:
                events.append(_event("image_load", dict(common, EventID=7, ImageLoaded=loaded), "behavior_api", pid, when, api))

        if low in {"ntopenprocess", "openprocess"}:
            fields = {
                "EventID": 10, "SourceImage": image, "SourceProcessId": pid,
                "TargetImage": _arg(arguments, "ProcessName", "TargetImage"),
                "TargetProcessId": _arg(arguments, "ProcessIdentifier", "ProcessId", "TargetProcessId"),
                "GrantedAccess": _arg(arguments, "DesiredAccess", "Access", "GrantedAccess"),
                "SourceUser": environ.get("UserName"),
            }
            events.append(_event("process_access", fields, "behavior_api", pid, when, api))

        if low in {"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread"}:
            source_pid = _pid_number(pid)
            target_pid = _pid_number(_arg(arguments, "ProcessId", "TargetProcessId", "ProcessIdentifier"))
            handle = _pid_number(_arg(arguments, "ProcessHandle", "hProcess"))
            if handle in {-1, 0xffffffff, 0xffffffffffffffff} or (source_pid is not None and source_pid == target_pid):
                normalization["self_thread_skipped"] += 1
                continue
            if source_pid is None or target_pid is None or target_pid <= 0:
                normalization["thread_unknown_target_skipped"] += 1
                continue
            fields = {
                "EventID": 8, "SourceImage": image, "SourceProcessId": pid,
                "TargetImage": _arg(arguments, "ProcessName", "TargetImage"),
                "TargetProcessId": target_pid,
                "StartAddress": _arg(arguments, "StartAddress", "StartRoutine"),
                "StartModule": _arg(arguments, "StartModule"), "StartFunction": _arg(arguments, "StartFunction"),
                "SourceCommandLine": environ.get("CommandLine"), "SourceParentImage": paths.get(str(process.get("parent_id"))),
            }
            events.append(_event("create_remote_thread", fields, "behavior_api", pid, when, api))

        if low in {"createnamedpipea", "createnamedpipew", "ntcreateNamedpipefile".casefold()}:
            pipe = _arg(arguments, "PipeName", "FileName", "ObjectName")
            if pipe:
                normalized_pipe = normalize_pipe_name(pipe)
                normalization["pipe_namespace_normalized"] += int(normalized_pipe != pipe)
                event = _event("pipe_created", dict(common, EventID=17, PipeName=normalized_pipe), "behavior_api", pid, when, api)
                event["evidence"].update({"raw_pipe_name": pipe, "call_id": call.get("id")})
                events.append(event)

        for event in events[event_start:]:
            event["evidence"].update({"call_id": call.get("id"), "projection": "successful_clean_api"})
        if len(events) >= MAX_EVENTS:
            break

    network = results.get("network") or {}
    capture_status = str(((network.get("capture") or {}).get("runtime") or {}).get("status") or "").casefold()
    capture_complete = capture_status == "complete" or bool((network.get("capture") or {}).get("path"))
    if capture_complete:
        for protocol in ("tcp", "udp"):
            for row in network.get(protocol) or []:
                if not isinstance(row, dict) or row.get("signature_eligible") is not True:
                    continue
                attribution = row.get("attribution") or {}
                if attribution.get("tracked") is not True:
                    continue
                src, sport, dst, dport = row.get("src"), row.get("sport"), row.get("dst"), row.get("dport")
                # Sysmon records an outbound connection from the guest.  Reverse
                # server-to-client PCAP rows back to that requester orientation.
                initiated = True
                if attribution.get("method") == "sysmon_eid3_reverse":
                    src, sport, dst, dport = dst, dport, src, sport
                fields = {
                    "EventID": 3, "Image": attribution.get("process"), "ProcessId": attribution.get("pid"),
                    "Protocol": protocol, "Initiated": initiated, "SourceIp": src, "SourcePort": sport,
                    "DestinationIp": dst, "DestinationHostname": row.get("hostname"), "DestinationPort": dport,
                }
                events.append(_event("network_connection", fields, "network_attribution", attribution.get("pid"), row.get("time")))
        for row in network.get("dns") or []:
            if not isinstance(row, dict) or row.get("signature_eligible") is not True:
                continue
            candidates = row.get("requester_attributions") or [row.get("attribution") or {}]
            attribution = next((item for item in candidates if isinstance(item, dict) and item.get("tracked") is True), None)
            if not attribution:
                continue
            answers = ",".join(str(item.get("data")) for item in row.get("answers") or [] if isinstance(item, dict) and item.get("data"))
            fields = {
                "EventID": 22, "Image": attribution.get("process"), "ProcessId": attribution.get("pid"),
                "QueryName": row.get("request"), "QueryResults": answers,
            }
            events.append(_event("dns_query", fields, "network_attribution", attribution.get("pid"), row.get("first_seen")))

    available = set()
    if by_pid:
        available.update(BEHAVIOR_LOGSOURCES)
    if capture_complete:
        available.update(NETWORK_LOGSOURCES)
    counts = Counter(event["category"] for event in events)
    return events[:MAX_EVENTS], {
        "available_logsources": sorted(available),
        "event_counts": dict(sorted(counts.items())),
        "event_limit_reached": len(events) >= MAX_EVENTS,
        "normalization": dict(normalization),
        "logsource_semantics": "API projections use Sigma field names; synthetic EventID values do not prove that Sysmon event types were enabled.",
        "capture_complete": capture_complete,
        "raw_sysmon_eid25_exported": False,
    }


def _field(fields: dict, name: str) -> tuple[bool, Any]:
    lowered = {str(key).casefold(): value for key, value in fields.items()}
    key = name.casefold()
    return key in lowered, lowered.get(key)


def _scalar_match(spec: dict, candidate: Any, fields: dict) -> bool:
    kind = spec.get("kind")
    if kind == "null":
        return candidate is None
    if kind == "any":
        return any(_scalar_match(item, candidate, fields) for item in spec.get("values") or [])
    if kind == "fieldref":
        present, reference = _field(fields, str(spec.get("field") or ""))
        if not present:
            return False
        left, right = str(candidate or "").casefold(), str(reference or "").casefold()
        if spec.get("starts_with"):
            return left.startswith(right)
        if spec.get("ends_with"):
            return left.endswith(right)
        return left == right
    if kind == "number":
        try:
            return int(candidate) == int(spec.get("value"))
        except (TypeError, ValueError):
            return False
    if kind == "bool":
        if isinstance(candidate, str):
            value = candidate.casefold() in {"1", "true", "yes"}
        else:
            value = bool(candidate)
        return value is bool(spec.get("value"))
    if kind == "cidr":
        try:
            return ipaddress.ip_address(str(candidate)) in ipaddress.ip_network(str(spec.get("network")), strict=False)
        except ValueError:
            return False
    if kind == "regex":
        flags = re.IGNORECASE if spec.get("ignore_case") else 0
        try:
            return re.search(str(spec.get("pattern") or ""), str(candidate or ""), flags) is not None
        except re.error:
            return False
    return False


def _value_match(spec: dict, value: Any, fields: dict) -> bool:
    if isinstance(value, (list, tuple, set)):
        return any(_scalar_match(spec, item, fields) for item in value)
    return _scalar_match(spec, value, fields)


def _evaluate_known(node: dict, fields: dict, negated: bool = False):
    """Three-valued logic: missing sensor fields cannot satisfy an exclusion."""
    op = node.get("op")
    if op == "field":
        name = str(node.get("field") or "")
        present, value = _field(fields, name)
        spec = node.get("value") or {}
        if not present:
            return None, set(), {name}
        if spec.get("kind") == "fieldref" and not _field(fields, spec.get("field", ""))[0]:
            return None, set(), {spec.get("field", "")}
        matched = _value_match(spec, value, fields)
        positive = {name} if matched and not negated and spec.get("kind") != "null" else set()
        return matched, positive, set()
    if op == "not":
        value, _, missing = _evaluate_known(node.get("arg") or {}, fields, not negated)
        return (None if value is None else not value), set(), missing
    if op in {"and", "or"}:
        values = [_evaluate_known(item, fields, negated) for item in node.get("args") or []]
        if not values: return False, set(), set()
        if op == "and" and any(v[0] is False for v in values): return False, set(), set()
        if op == "or" and any(v[0] is True for v in values):
            return True, set().union(*(v[1] for v in values if v[0] is True)), set()
        missing = set().union(*(v[2] for v in values))
        if any(v[0] is None for v in values): return None, set(), missing
        return (op == "and"), set().union(*(v[1] for v in values)) if op == "and" else set(), set()
    return False, set(), set()


def _evaluate(node: dict, fields: dict, negated: bool = False) -> tuple[bool, set[str]]:
    matched, positive, _ = _evaluate_known(node, fields, negated)
    return matched is True, positive


def _confidence(rule: dict) -> str:
    status = str(rule.get("status") or "").casefold()
    level = str(rule.get("level") or "").casefold()
    if status in {"stable", "test"} and level in {"high", "critical"}:
        return "medium"
    return "low"


def evaluate_sigma(results: dict, analysis_path: Optional[Path] = None,
                   clean_rows: Optional[list[dict]] = None, pack_path: Optional[Path] = None) -> dict:
    pack = _load_pack(pack_path)
    if not pack:
        return {
            "schema": SCHEMA, "available": False, "reason": "sigma_pack_missing_or_invalid",
            "matches": [], "attack_candidates": [], "coverage": {},
        }

    events, telemetry = normalize_events(results, clean_rows, analysis_path)
    by_category: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        by_category[event["category"]].append(event)
    available = set(telemetry["available_logsources"])
    coverage = Counter()
    unsupported_sensor_categories = Counter()
    unsupported_fields = Counter()
    technique_coverage: dict[str, dict] = {}
    matches = []
    evaluations = []

    for rule in pack.get("rules") or []:
        coverage["pack_rules"] += 1
        category = str((rule.get("logsource") or {}).get("category") or "")
        evaluation = {"rule_id": rule.get("id"), "title": rule.get("title"), "category": category,
                      "attack_ids": rule.get("attack_ids") or [], "status": "no_events",
                      "missing_fields": [], "events": len(by_category.get(category) or [])}
        evaluations.append(evaluation)
        if category not in available:
            coverage["unsupported_by_sensor"] += 1
            unsupported_sensor_categories[category or "unspecified"] += 1
            evaluation["status"] = "unsupported_by_sensor"
            continue
        schema = FIELD_SCHEMAS.get(category) or set()
        missing_fields = set(rule.get("fields") or []) - schema
        if missing_fields:
            evaluation.update(status="unsupported_fields", missing_fields=sorted(missing_fields))
            coverage["unsupported_fields"] += 1
            for field in missing_fields:
                unsupported_fields[f"{category}.{field}"] += 1
            continue
        coverage["evaluated_rules"] += 1
        unknown_fields = set(); decided = 0
        for technique_id in rule.get("attack_ids") or []:
            row = technique_coverage.setdefault(technique_id, {"technique_id": technique_id, "eligible_rules": 0, "matched_rules": 0})
            row["eligible_rules"] += 1
        for event in by_category.get(category) or []:
            matched, positive_fields, unknown = _evaluate_known(rule.get("condition") or {}, event.get("fields") or {})
            if matched is None: unknown_fields.update(unknown)
            else: decided += 1
            # A rule satisfied only because exclusion fields were absent is not
            # evidence.  At least one positive, populated field must match.
            if not matched or not positive_fields:
                continue
            evidence_fields = {
                field: (event.get("fields") or {}).get(field)
                for field in sorted(positive_fields)[:MAX_EVIDENCE_FIELDS]
                if (event.get("fields") or {}).get(field) not in (None, "")
            }
            match = {
                "rule_id": rule.get("id"), "title": rule.get("title"),
                "status": rule.get("status"), "level": rule.get("level"),
                "confidence": _confidence(rule), "attack_ids": list(rule.get("attack_ids") or []),
                "authors": list(rule.get("authors") or []),
                "references": list(rule.get("references") or []),
                "logsource": rule.get("logsource"), "source_path": rule.get("source_path"),
                "source_sha256": rule.get("source_sha256"), "falsepositives": list(rule.get("falsepositives") or []),
                "matched_fields": evidence_fields, "evidence": event.get("evidence") or {},
            }
            matches.append(match)
            evaluation["status"] = "matched"
            coverage["matched_rules"] += 1
            for technique_id in rule.get("attack_ids") or []:
                technique_coverage[technique_id]["matched_rules"] += 1
            break
        if evaluation["status"] != "matched" and evaluation["events"]:
            evaluation.update(status="missing_event_fields" if unknown_fields else "evaluated_no_match",
                              missing_fields=sorted(unknown_fields), decided_events=decided)
        if len(matches) >= MAX_MATCHES:
            coverage["match_limit_reached"] = 1
            # Keep the complete denominator and coverage matrix; cap evidence only.
            MAX_RETAINED = MAX_MATCHES
            del matches[MAX_RETAINED:]

    candidates: dict[str, dict] = {}
    for match in matches:
        for technique_id in match.get("attack_ids") or []:
            row = candidates.setdefault(technique_id, {
                "technique_id": technique_id, "status": "candidate", "confidence": "low",
                "rule_ids": [], "matches": 0,
            })
            row["matches"] += 1
            if match.get("rule_id") not in row["rule_ids"]:
                row["rule_ids"].append(match.get("rule_id"))
            if match.get("confidence") == "medium":
                row["confidence"] = "medium"

    coverage_report = dict(sorted(coverage.items()))
    coverage_report["unsupported_by_sensor_categories"] = dict(sorted(unsupported_sensor_categories.items()))
    coverage_report["unsupported_fields_by_name"] = dict(sorted(unsupported_fields.items()))
    coverage_report["evaluation_statuses"] = dict(Counter(row["status"] for row in evaluations))
    coverage_report["matched_without_attack_tag"] = sum(not row["attack_ids"] for row in matches)
    return {
        "schema": SCHEMA, "available": True, "engine": "p3_sigma_ir/1.0",
        "policy": {
            "sigma_only_status": "candidate",
            "observed_requires": "native P3 semantic/state-machine corroboration",
            "score_sigma_only": False,
            "missing_sensor_semantics": "unsupported_by_sensor_not_absent",
        },
        "source": pack.get("source") or {}, "pack_summary": pack.get("summary") or {},
        "telemetry": telemetry, "coverage": coverage_report,
        "rule_evaluations": evaluations,
        "technique_coverage": sorted(technique_coverage.values(), key=lambda row: row["technique_id"]),
        "matches": matches,
        "attack_candidates": sorted(candidates.values(), key=lambda row: row["technique_id"]),
    }


__all__ = ["FIELD_SCHEMAS", "SCHEMA", "evaluate_sigma", "normalize_events"]
