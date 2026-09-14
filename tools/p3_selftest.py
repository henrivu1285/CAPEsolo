#!/usr/bin/env python3
"""Offline regression tests for CAPEsolo + Frida P3.2.3.16."""
from __future__ import annotations

import importlib.util
import gzip
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / "CAPEsolo"
PROJECT_ROOT = HERE.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_lifecycle_policy():
    m = load_module("lifecycle", ROOT / "lib" / "common" / "frida_lifecycle_policy.py")
    log = "\n".join([
        "x DEBUG: 9128: Hooked 671 out of 671 functions",
        "x DEBUG: 9128: Syscall hook installed, syscall logging level 1",
    ])
    assert m.detect_capemon_ready_signal(log, 9128) in {"hook_set_complete", "syscall_hook_installed"}
    assert m.detect_capemon_ready_signal(log, 7984) is None
    assert m.child_priority_decision(root_ready=True, root_alive=True, root_failed=False, elapsed=0, priority_window=.35) == "root_ready"
    assert m.child_priority_decision(root_ready=False, root_alive=False, root_failed=False, elapsed=.01, priority_window=.35) == "promote_root_unavailable"
    assert m.child_priority_decision(root_ready=False, root_alive=True, root_failed=False, elapsed=.36, priority_window=.35) == "promote_priority_window_elapsed"
    assert m.child_priority_decision(root_ready=False, root_alive=True, root_failed=False, elapsed=.10, priority_window=.35) == "wait"
    assert m.normalize_child_attach_policy("adaptive") == "adaptive"
    assert m.normalize_child_attach_policy("unsupported") == "adaptive"
    assert m.child_attach_decision(policy="adaptive", alive=True, elapsed=1.0, exclusive_window=1.5) == "wait_exclusive_window"
    assert m.child_attach_decision(policy="adaptive", alive=True, elapsed=1.5, exclusive_window=1.5) == "attach_now"
    assert m.child_attach_decision(policy="adaptive", alive=False, elapsed=.5, exclusive_window=1.5) == "target_exited_capemon_observed"
    assert m.child_attach_decision(policy="capemon_only", alive=True, elapsed=10, exclusive_window=1.5) == "capemon_only"
    active, stalled, was_stalled = m.advance_active_observation(
        active_elapsed=0.10, scheduler_gap_elapsed=0.0,
        delta=0.05, max_tick=0.25,
    )
    assert round(active, 2) == 0.15 and stalled == 0.0 and was_stalled is False
    active, stalled, was_stalled = m.advance_active_observation(
        active_elapsed=active, scheduler_gap_elapsed=stalled,
        delta=4.80, max_tick=0.25,
    )
    assert round(active, 2) == 0.15 and round(stalled, 2) == 4.80 and was_stalled is True
    assert m.child_prewarm_decision(
        require_prewarmed_arch=True, prewarm_enabled=True,
        target_arch="x86", requested_arches=["x86"], usable_arches=[],
    ) == "capemon_only_prewarm_unavailable"
    assert m.child_prewarm_decision(
        require_prewarmed_arch=True, prewarm_enabled=True,
        target_arch="x86", requested_arches=["x86"], usable_arches=["x86"],
    ) == "attach_allowed"


def test_exact_root_profile_resolution():
    m = load_module("resolver", ROOT / "lib" / "common" / "frida_profile_resolver.py")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        profiles = td / "profiles"
        samples = td / "samples"
        profiles.mkdir(); samples.mkdir()
        (profiles / "generic.json").write_text(json.dumps({"name": "generic"}), encoding="utf-8")
        (profiles / "family.json").write_text(json.dumps({
            "name": "family",
            "match": {"min_score": 80, "sha256": [] , "names": ["unrelated.bin"], "name_score": 100},
        }), encoding="utf-8")
        unrelated = samples / "unrelated.bin"
        root = samples / "actual.exe"
        unrelated.write_bytes(b"unrelated")
        root.write_bytes(b"actual")
        # A directory scan could see unrelated.bin, but exact-root mode must not.
        result = m.resolve_profile(profiles, samples, requested="auto", fallback="generic", target_path=root)
        assert result["selected"] == "generic", result
        assert Path(result["candidate"]) == root


def _call(pid, cid, ts, api, args, process_name="sample.exe"):
    return {
        "pid": pid,
        "process_name": process_name,
        "process_path": rf"C:\Lab\{process_name}",
        "call_id": cid,
        "timestamp": ts,
        "category": "process",
        "api": api,
        "provenance": "malware_candidate",
        "confidence": "candidate",
        "filter_from_clean_view": False,
        "possible_reasons": [],
        "call": {
            "timestamp": ts,
            "thread_id": "1",
            "caller": "0x401000",
            "parentcaller": "0x402000",
            "category": "process",
            "api": api,
            "status": True,
            "return": "0x0",
            "arguments": [{"name": k, "value": v} for k, v in args.items()],
            "id": cid,
        },
    }


def test_compaction_and_chains():
    compact = load_module("compact", HERE / "frida_behavior_compact.py")
    chains = load_module("chains", HERE / "frida_behavior_chains.py")
    recs = []
    for i in range(12):
        recs.append(_call(10, i, f"2026-08-21 19:00:48,{100+i:03d}", "NtClose", {"Handle": hex(0x100+i)}))
    for i in range(12, 24):
        recs.append(_call(10, i, f"2026-08-21 19:00:48,{200+i:03d}", "Process32NextW", {"ProcessName": f"p{i}.exe", "ProcessId": i}))
    out, summary = compact.compact_records(recs, {"by_api": {}})
    assert summary["expansion_invariant_ok"] is True
    assert summary["display_records_saved"] > 0
    assert summary["bursts_by_api"].get("NtClose") == 1
    assert summary["bursts_by_api"].get("Process32NextW") == 1
    assert sum(int(x.get("count") or 0) for x in out) == len(recs)

    behavior = [
        _call(10, 100, "2026-08-21 19:00:49,000", "CopyFileW", {"ExistingFileName": r"C:\Lab\sample.exe", "NewFileName": r"C:\Users\u\AppData\Local\stage.exe"}),
        _call(10, 101, "2026-08-21 19:00:49,100", "CreateProcessW", {"ApplicationName": r"C:\Users\u\AppData\Local\stage.exe", "ProcessId": 20}),
        _call(20, 102, "2026-08-21 19:00:49,200", "RegSetValueExW", {"FullName": r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater", "Buffer": r"C:\Users\u\AppData\Local\stage.exe"}, process_name="stage.exe"),
        _call(20, 103, "2026-08-21 19:00:49,300", "NtOpenProcess", {"ProcessHandle": "0x2bc", "DesiredAccess": "PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION", "ProcessIdentifier": 555, "ProcessName": r"C:\Windows\explorer.exe"}, process_name="stage.exe"),
        _call(10, 104, "2026-08-21 19:00:49,500", "NtTerminateProcess", {"ProcessHandle": "0xffffffff", "ExitCode": 0}),
    ]
    result = chains.extract_behavior_chains_from_records(behavior)
    assert result["summary"]["persistence_run_key"] == 1
    assert result["summary"]["injection_precursors"] == 1
    assert result["summary"]["confirmed_injection_sequences"] == 0
    assert result["summary"]["stage_handoffs"] == 1
    precursor = next(x for x in result["chains"] if x["chain_type"] == "injection_precursor")
    assert precursor["mitre_candidate"] is None

    without_copy = [record for record in behavior if record.get("api") != "CopyFileW"]
    incomplete = chains.extract_behavior_chains_from_records(without_copy)
    persistence = next(
        item for item in incomplete["chains"]
        if item["chain_type"] == "persistence_run_key"
    )
    assert persistence["confidence"] == "medium", persistence
    assert persistence["materialization_status"] == "not_observed", persistence
    assert persistence["preexisting_target_possible"] is True, persistence
    assert incomplete["summary"]["persistence_without_materialization"] == 1



def test_behavior_run_thread_scoping():
    provenance = load_module("provenance", HERE / "frida_behavior_provenance.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        runtime = {
            "run_id": "SCOPE-RUN",
            "lineage": {
                "10": {"role": "root", "create_time": 1.0, "exe": r"C:\Lab\root.exe"},
                "20": {"role": "child", "create_time": 2.0, "exe": r"C:\Lab\child.exe"},
            },
            "evidence": [],
        }
        # The same two calls are intentionally repeated under both process
        # containers. Thread ownership must keep each call only under its owner.
        c_root = _call(10, 1, "2026-08-21 19:00:10,100", "NtClose", {"Handle": "0x1"}, process_name="root.exe")["call"]
        c_root["thread_id"] = "100"
        c_child = _call(20, 2, "2026-08-21 19:00:10,200", "NtClose", {"Handle": "0x2"}, process_name="child.exe")["call"]
        c_child["thread_id"] = "200"
        stale = _call(10, 3, "2026-08-21 18:00:00,000", "NtClose", {"Handle": "0x3"}, process_name="root.exe")["call"]
        stale["thread_id"] = "100"
        report = {
            "target": {"sha256": "x", "pe": {"imagebase": "0x00400000"}},
            "behavior": {"processes": [
                {"process_id": 10, "process_name": "root.exe", "module_path": r"C:\Lab\root.exe", "threads": ["100"], "calls": [c_root, c_child, stale]},
                {"process_id": 20, "process_name": "child.exe", "module_path": r"C:\Lab\child.exe", "threads": ["200"], "calls": [c_root, c_child, stale]},
            ]},
        }
        (d / "report.json").write_text(json.dumps(report), encoding="utf-8")
        (d / "analysis.log").write_text(
            "2026-08-21 19:00:10,000 [x] INFO: start\n"
            "2026-08-21 19:00:11,000 [x] INFO: end\n",
            encoding="utf-8",
        )
        result = provenance.classify_behavior(d, output_dir=d, runtime=runtime, artifact_result={})
        scope = result["summary"]["run_scoping"]
        assert result["summary"]["calls_total"] == 2, result["summary"]
        assert scope["thread_mismatch_removed"] == 3, scope
        assert scope["outside_time_scope_removed"] == 1, scope


def test_behavior_pid_repair():
    repair = load_module("pid_repair", HERE / "frida_behavior_pid_repair.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        root_call = _call(10, 1, "2026-08-21 19:00:10,100", "NtClose", {"Handle": "0x1"})["call"]
        child_call = _call(20, 2, "2026-08-21 19:00:10,200", "NtClose", {"Handle": "0x2"})["call"]
        root_call["thread_id"] = "100"
        child_call["thread_id"] = "200"
        shared = [root_call, child_call]
        raw_report = {
            "behavior": {"processes": [
                {"process_id": 10, "process_name": "root.exe", "threads": [100], "calls": shared},
                {"process_id": 20, "process_name": "child.exe", "threads": [200], "calls": shared},
            ]},
        }
        raw_path = d / "report.json"
        raw_path.write_text(json.dumps(raw_report), encoding="utf-8")
        raw_before = raw_path.read_bytes()
        runtime = {
            "version": PRODUCT_VERSION,
            "lineage": {"10": {"role": "root"}, "20": {"role": "child"}},
        }
        result = repair.repair_behavior_pid_ownership(d, output_dir=d, runtime=runtime)
        fixed = json.loads((d / "report.behavior_fixed.json").read_text(encoding="utf-8"))
        processes = fixed["behavior"]["processes"]
        assert result["duplicate_call_containers_detected"] is True, result
        assert result["raw_call_occurrences"] == 4, result
        assert result["repaired_call_occurrences"] == 2, result
        assert result["thread_mismatch_removed"] == 2, result
        assert result["ownership_invariant_ok"] is True, result
        assert result["version"] == PRODUCT_VERSION, result
        assert [len(proc["calls"]) for proc in processes] == [1, 1], processes
        assert processes[0]["calls"][0]["thread_id"] == "100"
        assert processes[1]["calls"][0]["thread_id"] == "200"
        assert raw_path.read_bytes() == raw_before


def test_behavior_pid_validation_without_duplicate_report():
    repair = load_module("pid_repair_clean", HERE / "frida_behavior_pid_repair.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        root_call = _call(10, 1, "2026-08-21 19:00:10,100", "NtClose", {"Handle": "0x1"})["call"]
        child_call = _call(20, 2, "2026-08-21 19:00:10,200", "NtClose", {"Handle": "0x2"})["call"]
        root_call["thread_id"] = "100"
        child_call["thread_id"] = "200"
        report = {"behavior": {"processes": [
            {"process_id": 10, "threads": [100], "calls": [root_call]},
            {"process_id": 20, "threads": [200], "calls": [child_call]},
        ]}}
        (d / "report.json").write_text(json.dumps(report), encoding="utf-8")
        result = repair.repair_behavior_pid_ownership(d, output_dir=d, runtime={})
        assert result["changed"] is False
        assert result["fixed_report_created"] is False
        assert Path(result["output_report"]) == d / "report.json"
        assert not (d / "report.behavior_fixed.json").exists()

def test_attach_outcome_accounting():
    finalizer = load_module("finalizer_attach", HERE / "frida_p3_finalize.py")
    events = [
        {"kind": "frida_attach", "pid": 10, "attempt": 1, "status": "target_died", "monotonic": 1.0, "seq": 1},
        {"kind": "frida_attach", "pid": 20, "attempt": 1, "status": "success", "monotonic": 2.0, "seq": 2},
    ]
    noisy_log = "Frida attach attempt 1 failed\nCould not attach Frida to root\n"
    summary = finalizer._attach_outcome_summary(events, noisy_log)
    assert summary["attempts"] == 2, summary
    assert summary["success"] == 1, summary
    assert summary["target_died"] == 1, summary
    assert summary["hard_failures"] == 0, summary

    events = [
        {"kind": "frida_attach", "pid": 10, "attempt": 1, "status": "failed_exception", "monotonic": 1.0, "seq": 1},
    ]
    summary = finalizer._attach_outcome_summary(events, noisy_log)
    assert summary["failed_exception"] == 1, summary
    assert summary["hard_failures"] == 1, summary


def test_temporal_attach_provenance():
    artifact = load_module("artifact_p3235", HERE / "frida_artifact_filter.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        cape = d / "CAPE"
        cape.mkdir()
        sha = "a" * 64
        (cape / sha).write_bytes(b"not-a-pe-fragment")
        item = {
            "path": f"CAPE/{sha}",
            "pids": [10],
            "ppids": [1],
            "category": "CAPE",
            "metadata": "9;?C:\\Lab\\sample.exe;?C:\\Lab\\sample.exe;?0x05000000;?",
        }
        weak_log = "\n".join([
            '2026-08-22 11:00:00,000 [x] INFO: [FridaMuncher][pid=10] Attaching Frida (attempt 1/2, timeout=4.00s)...',
            '2026-08-22 11:00:01,000 [x] INFO: [P3Evidence] {"kind":"frida_attach","pid":10,"status":"target_died","attempt":1}',
            f'2026-08-22 11:00:00,500 [x] INFO: Uploading file X to CAPE/{sha}',
        ])
        temporal = artifact.parse_temporal_provenance_text(weak_log)
        c = artifact.classify_item(item, [], temporal, d, cape)
        assert c["instrumentation_possible"] is False, c
        assert c["annotations"], c
        assert c["annotations"][0]["kind"] == "frida_attach_attempt_temporal_proximity", c

        strong_log = "\n".join([
            '2026-08-22 11:00:00,000 [x] INFO: [FridaMuncher][pid=10] Attaching Frida (attempt 1/2, timeout=4.00s)...',
            '2026-08-22 11:00:00,800 [x] INFO: [P3Evidence] {"kind":"frida_helper_seen","pid":10,"helper_pid":99}',
            f'2026-08-22 11:00:01,000 [x] INFO: Uploading file X to CAPE/{sha}',
        ])
        temporal = artifact.parse_temporal_provenance_text(strong_log)
        c = artifact.classify_item(item, [], temporal, d, cape)
        assert c["instrumentation_possible"] is False, c
        assert c["instrumentation_possible_timing_only"] is True, c
        assert c["classification"] == "instrumentation_possible_timing_only", c
        assert c["annotations"][0]["strong_progress"] is True, c


def test_artifact_content_evidence():
    artifact = load_module("artifact_content_p3235", HERE / "frida_artifact_filter.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        cape = d / "CAPE"
        cape.mkdir()
        frida_sha = "b" * 64
        loader_sha = "c" * 64
        (cape / frida_sha).write_bytes("C:\\Temp\\frida-agent.dll".encode("utf-16le"))
        (cape / loader_sha).write_bytes(
            b"VirtualAlloc\x00VirtualProtect\x00LoadLibraryA\x00GetProcAddress\x00"
        )
        base_item = {
            "pids": [10], "ppids": [1], "category": "CAPE",
            "metadata": "9;?C:\\Lab\\sample.exe;?C:\\Lab\\sample.exe;?0x05000000;?",
        }
        frida_item = dict(base_item, path=f"CAPE/{frida_sha}")
        loader_item = dict(base_item, path=f"CAPE/{loader_sha}")
        frida_result = artifact.classify_item(frida_item, [], {"windows": {}, "artifact_times": {}}, d, cape)
        loader_result = artifact.classify_item(loader_item, [], {"windows": {}, "artifact_times": {}}, d, cape)
        assert frida_result["instrumentation"] is True, frida_result
        assert frida_result["classification"] == "instrumentation_confirmed", frida_result
        assert loader_result["instrumentation"] is False, loader_result
        # p32318: common API strings are context, not maliciousness evidence.
        assert loader_result["malware_candidate"] is False, loader_result
        assert loader_result["instrumentation_possible_timing_only"] is False, loader_result
        assert loader_result["classification"] == "unclassified", loader_result


def test_attach_defaults_present():
    generic = json.loads((ROOT / "data" / "frida_profiles" / "generic.json").read_text(encoding="utf-8"))
    blackenergy = json.loads((ROOT / "data" / "frida_profiles" / "blackenergy21.json").read_text(encoding="utf-8"))
    assert generic["frida_device_prewarm"] is True
    assert generic["early_agent_attach"] is True
    assert set(generic["early_agent_roles"]) >= {"root", "injected"}
    assert "child" not in set(generic["early_agent_roles"])
    assert generic["frida_injector_prewarm"] is True
    assert "x86" in generic["frida_injector_prewarm_arches"]
    assert 0.5 <= float(generic["attach_timeout"]) <= 10.0
    assert float(generic["child_attach_timeout"]) > float(generic["attach_timeout"])
    assert float(generic["attach_helper_extension"]) > 0
    assert float(generic["child_capemon_grace"]) >= 2.0
    assert generic["features"]["exception_diagnostics"] is False
    assert generic["features"]["child_exception_diagnostics"] is False
    assert generic["script_source_prewarm"] is True
    assert generic["child_fast_path"] is True
    assert generic["child_fast_only"] is True
    assert generic["child_attach_policy"] == "adaptive"
    assert float(generic["child_capemon_exclusive_window"]) >= 2.5
    assert 0.05 <= float(generic["child_observation_max_tick"]) <= 0.5
    assert generic["child_require_prewarmed_arch"] is True
    assert generic["child_fast_scripts"][0] == "process_injection_tracker.js"
    assert {3, 22}.issubset(set(generic["sysmon_event_ids"]))
    assert generic["pcap_capture"]["enabled"] is True
    assert generic["pcap_capture"]["agent_url"] == "http://192.168.56.2:54321"
    assert generic["pcap_capture"]["guest_ip"] == "auto"
    # Keep the sample-specific patched-entry profile on its validated path.
    assert blackenergy["early_agent_attach"] is False
    assert blackenergy["child_attach_policy"] == "immediate"
    assert blackenergy["child_fast_only"] is False
    assert blackenergy["features"]["exception_diagnostics"] is True
    assert {3, 22}.issubset(set(blackenergy["sysmon_event_ids"]))


def test_exception_diagnostics_opt_in_source():
    js = (ROOT / "data" / "frida_scripts" / "anti_evasion.js").read_text(encoding="utf-8")
    muncher = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    assert "enableExceptionDiagnostics: false" in js
    assert "Process.setExceptionHandler(function" not in js
    assert "function installExceptionDiagnostics()" in js
    assert js.index("Process.setExceptionHandler(handleProcessException)") > js.index("function installExceptionDiagnostics()")
    assert "message.enable_exception_diagnostics" in js
    assert '"enable_exception_diagnostics": exception_diagnostics' in muncher


def test_early_agent_deferred_hooks_source():
    source = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    mapping_start = source.index("self._start_early_agent_attach")
    ready_wait = source.index("return self._wait_for_capemon_ready_or_grace", mapping_start)
    instrument = source.index("def _instrument_process")
    claim = source.index("self._claim_early_agent_attach", instrument)
    script_load = source.index("scripts, preconfigured, script_failures = self._load_scripts", claim)
    assert mapping_start < ready_wait < instrument < claim < script_load
    assert 'phase="early_agent"' in source
    assert 'JS scripts remain deferred until CAPEMON-ready' in source


def test_child_fast_path_source():
    source = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    assert "start_priority = 100" in source
    assert "def _preload_script_sources" in source
    assert "def _ordered_script_paths" in source
    assert "frida_fast_hook_configured" in source
    assert "frida_hooks_partial_ready" in source
    assert "transport_closed_before_scripts" in source
    assert 'if ticket.get("claimed"):' in source
    assert "def _wait_for_child_attach_policy" in source
    assert 'self.child_attach_policy != "immediate"' in source
    assert "self.child_fast_only" in source


def test_attach_self_read_burst_filter():
    provenance = load_module("provenance_attach_p3237", HERE / "frida_behavior_provenance.py")
    from datetime import datetime

    base = datetime(2026, 8, 24, 0, 0, 0)
    runtime = {
        "evidence": [
            {
                "kind": "frida_attach_start", "pid": 20, "attempt": 1,
                "wall_time": base.timestamp(), "timeout": 2.0,
            },
            {
                "kind": "frida_attach", "pid": 20, "attempt": 1,
                "wall_time": base.timestamp() + .8, "status": "success",
            },
        ],
    }
    log = (
        "2026-08-24 00:00:00,000 [x] INFO: [P3Evidence] "
        + json.dumps(runtime["evidence"][0])
    )
    records = []
    anchor = _call(
        20, 1, "2026-08-24 00:00:00,050", "NtCreateFile",
        {"ObjectAttributes": r"\\??\\pipe\\frida-test"},
    )
    anchor.update({
        "provenance": "framework_frida", "confidence": "high",
        "filter_from_clean_view": True,
    })
    records.append(anchor)
    for i in range(64):
        record = _call(
            20, i + 2, f"2026-08-24 00:00:00,{100 + i:03d}",
            "NtReadVirtualMemory",
            {"ProcessHandle": "0xffffffff", "Size": "0x4"},
        )
        # Parent return sites legitimately vary during loader traversal.
        record["call"]["parentcaller"] = hex(0x70000000 + i)
        records.append(record)
    result = provenance.classify_frida_attach_self_read_bursts(
        records, runtime, [], log
    )
    assert result["classified_calls"] == 64, result
    assert result["bursts"] == 1, result
    assert all(r["filter_from_clean_view"] for r in records[1:])


def test_unhook_restore_burst_annotation():
    provenance = load_module("provenance_unhook_p32310", HERE / "frida_behavior_provenance.py")
    from datetime import datetime

    base = datetime(2026, 8, 24, 0, 0, 0)
    runtime = {
        "evidence": [
            {
                "kind": "frida_attach_start", "pid": 10, "attempt": 1,
                "wall_time": base.timestamp(), "timeout": 2.0,
            },
            {
                "kind": "frida_attach", "pid": 10, "attempt": 1,
                "wall_time": base.timestamp() + .5, "status": "success",
            },
        ],
    }
    log = (
        "2026-08-24 00:00:00,000 [x] INFO: [P3Evidence] "
        + json.dumps(runtime["evidence"][0])
    )
    functions = [
        "WriteProcessMemory", "VirtualProtectEx", "FindWindowA",
        "FindWindowW", "IsDebuggerPresent", "GetSystemInfo",
    ]
    records = []
    for index, function in enumerate(functions):
        record = _call(
            10, index + 1, "2026-08-24 00:00:00,700", "__anomaly__",
            {
                "Subcategory": "unhook",
                "FunctionName": function,
                "UnhookType": "restored",
            },
        )
        record["category"] = "__notification__"
        record["call"]["category"] = "__notification__"
        record["call"]["caller"] = "0x00000000"
        record["call"]["parentcaller"] = "0x00000000"
        record["call"]["thread_id"] = "8768"
        records.append(record)

    result = provenance.classify_unhook_restore_bursts(records, runtime, log)
    assert result["classified_calls"] == 6, result
    assert result["bursts"] == 1, result
    assert all(record["provenance"] == "framework_possible" for record in records)
    assert all(record["filter_from_clean_view"] is False for record in records)


def test_protected_range_deduplication():
    provenance = load_module("provenance_dedupe_p32310", HERE / "frida_behavior_provenance.py")
    item = {
        "base": 0x400000,
        "end": 0x410000,
        "path": r"C:\Lab\same.bin",
        "source": "artifact_provenance",
        "artifact_path": "CAPE/abc",
    }
    unique, removed = provenance._dedupe_ranges([dict(item), dict(item)])
    assert len(unique) == 1
    assert removed == 1


def test_werfault_attribution_without_child_attach():
    finalizer = load_module("finalizer_werfault_p32310", HERE / "frida_p3_finalize.py")
    events = [
        {
            "kind": "descendant_excluded", "pid": 30, "ppid": 20,
            "name": "werfault.exe", "exe": r"C:\Windows\SysWOW64\WerFault.exe",
        },
        {
            "kind": "frida_process_outcome", "pid": 20, "role": "child",
            "status": "capemon_only_policy",
        },
    ]
    lineage = {"20": {"role": "child", "exe": r"C:\Lab\stage.exe"}}
    process_summary = finalizer._process_instrumentation_summary(events, lineage)
    result = finalizer.build_werfault_diagnostics(events, lineage, process_summary)
    assert result["status"] == "werfault_without_parent_frida_attach", result
    assert result["direct_parent_frida_attach_observed"] is False, result
    assert result["direct_child_frida_cause_supported"] is False, result


def test_lifecycle_log_wording_source():
    source = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    assert "proceeding to lifecycle policy" in source
    assert "CAPEMON-ready signal=%s; proceeding to Frida attach" not in source


def test_shared_product_version_source():
    version_module = load_module(
        "shared_version_p32310", ROOT / "lib" / "common" / "frida_version.py"
    )
    assert version_module.PRODUCT_VERSION == PRODUCT_VERSION
    assert (ROOT / "version.txt").read_text(encoding="utf-8").strip() == version_module.PACKAGE_VERSION
    generic = json.loads(
        (ROOT / "data" / "frida_profiles" / "generic.json").read_text(encoding="utf-8")
    )
    assert generic["schema_version"] == "3.2.3.17"
    for filename in ("frida_artifact_filter.py", "frida_behavior_compact.py"):
        source = (HERE / filename).read_text(encoding="utf-8")
        assert '"version": "P3.2.3.5"' not in source
        assert "product_version_for_runtime(runtime)" in source


def test_registry_telemetry_continuity():
    finalizer = load_module("finalizer_continuity_p3237", HERE / "frida_p3_finalize.py")
    resolver = _call(
        20, 1, "2026-08-24 00:00:00,100", "LdrGetProcedureAddressForCaller",
        {"FunctionName": "RegCreateKeyExW"},
    )
    setter = _call(
        20, 2, "2026-08-24 00:00:00,200", "RegSetValueExW",
        {"Handle": "0x300", "FullName": r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"},
    )
    closer = _call(
        20, 3, "2026-08-24 00:00:00,201", "RegCloseKey",
        {"Handle": "0x300"},
    )
    missing = finalizer.detect_behavior_telemetry_gaps([resolver, setter, closer])
    assert missing["status"] == "suspected_gap", missing
    assert missing["high_confidence_gaps"] == 1, missing
    opener = _call(
        20, 2, "2026-08-24 00:00:00,150", "RegCreateKeyExW",
        {"Handle": "0x300", "FullName": r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    )
    complete = finalizer.detect_behavior_telemetry_gaps([resolver, opener, setter, closer])
    assert complete["status"] == "complete_observed", complete


def test_framework_only_rate_cap():
    compact = load_module("compact_coverage_p3235", HERE / "frida_behavior_compact.py")
    framework_calls = [
        {"api": "NtReadVirtualMemory", "filter_from_clean_view": True}
        for _ in range(4)
    ]
    log = "2026-08-23 [x] DEBUG: api-rate-cap: NtReadVirtualMemory hook disabled due to rate\n"
    coverage = compact._coverage_map(framework_calls, [], log)
    assert coverage["status"] == "expected_framework_rate_cap", coverage
    assert coverage["framework_only_rate_caps"] == ["NtReadVirtualMemory"], coverage
    mixed = framework_calls + [{"api": "NtReadVirtualMemory", "filter_from_clean_view": False}]
    coverage = compact._coverage_map(mixed, [mixed[-1]], log)
    assert coverage["status"] == "degraded", coverage


def test_injector_prewarm_source():
    source = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    assert "def _prewarm_frida_injector_arch" in source
    assert '"SysWOW64" / "cmd.exe"' in source
    assert "session.detach()" in source
    assert "proc.terminate()" in source
    assert '"usable_arches": usable' in source
    assert '"completed": True' in source
    assert "def _child_prewarm_gate" in source
    assert "capemon_only_prewarm_unavailable" in source


def test_helper_aware_child_attach_source():
    source = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    assert "def _attach_timeout_for_role" in source
    assert "def _extend_attach_for_helper" in source
    assert '"frida_attach_helper_extension"' in source
    assert "deadline, helper_extended = self._extend_attach_for_helper" in source


def test_review_export_profile():
    archive = load_module("result_archive", ROOT / "lib" / "core" / "result_archive.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "analysis.log").write_text("ok\n", encoding="utf-8")
        (d / "frida_p3_report.json").write_text("{}", encoding="utf-8")
        (d / "pcap_runtime.json").write_text("{}", encoding="utf-8")
        (d / "dump.pcapng").write_bytes(b"pcapng")
        (d / "raw.bin").write_bytes(b"raw")
        out, manifest = archive.build_result_archive(d, d.parent / "review.zip", "review")
        assert out.is_file()
        assert manifest["mode"] == "review"
        names = {item["path"] for item in manifest["files"]}
        assert names == {
            "analysis.log", "frida_p3_report.json", "pcap_runtime.json", "dump.pcapng"
        }
        assert manifest["version"] == PRODUCT_VERSION


def test_upstream_report_integration_source():
    source = (ROOT / "classes" / "json_report.py").read_text(encoding="utf-8")
    assert 'proc["calls"] = list(proc.get("calls", []))' in source
    assert "def WriteJsonFile(results, analysisDir=None)" in source
    assert 'Path(analysisDir).resolve() / "report.json"' in source


def test_auxiliary_config_and_monitor_option_filter_source():
    analyzer = (ROOT / "analyzer.py").read_text(encoding="utf-8")
    process = (ROOT / "lib" / "api" / "process.py").read_text(encoding="utf-8")
    assert 'configure = getattr(instance, "configure_from_data", None)' in analyzer
    assert "if not callable(configure):" in analyzer
    assert 'if optname.startswith(("frida_", "pcap_")) or optname == OPT_CURDIR:' in process


def test_process_instrumentation_summary():
    finalizer = load_module("finalizer_process_p3237", HERE / "frida_p3_finalize.py")
    lineage = {
        "10": {"role": "root"},
        "20": {"role": "child"},
    }
    events = [
        {"kind": "frida_attach", "pid": 10, "role": "root", "status": "success", "seq": 1},
        {"kind": "frida_hooks_ready", "pid": 10, "role": "root", "seq": 2},
        {"kind": "frida_attach", "pid": 20, "role": "child", "status": "success", "seq": 3},
        {
            "kind": "frida_script_setup_failed", "pid": 20, "role": "child",
            "status": "transport_closed_before_scripts", "error_type": "TransportError", "seq": 4,
        },
    ]
    summary = finalizer._process_instrumentation_summary(events, lineage)
    assert summary["by_pid"]["10"]["status"] == "hooks_ready", summary
    assert summary["by_pid"]["20"]["status"] == "transport_closed_before_scripts", summary
    assert summary["setup_failures"] == 1, summary
    assert finalizer._role_axis(summary, "child", [20]) == "transport_closed_before_scripts"
    observed = finalizer._process_instrumentation_summary([
        {
            "kind": "frida_process_outcome", "pid": 20, "role": "child",
            "status": "capemon_observed_short_lived", "seq": 1,
        },
    ], lineage)
    assert observed["incomplete"] == [], observed
    assert finalizer._role_axis(observed, "child", [20]) == "capemon_observed"
    interrupted = finalizer._process_instrumentation_summary([
        {
            "kind": "frida_process_outcome", "pid": 20, "role": "child",
            "status": "target_died_during_optional_attach",
            "attach_status": "target_died",
            "instrumentation_interference_possible": True,
            "seq": 1,
        },
    ], lineage)
    assert interrupted["incomplete"][0]["status"] == "target_died_during_optional_attach"
    assert finalizer._role_axis(interrupted, "child", [20]) == "target_died_during_optional_attach"


def test_sysmon_network_event_parsing():
    bridge = load_module("sysmon_network", ROOT / "lib" / "common" / "sysmon_bridge.py")

    def xml(event_id, fields):
        data = "".join(
            f'<Data Name="{name}">{value}</Data>' for name, value in fields.items()
        )
        return (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Sysmon"/>'
            f'<EventID>{event_id}</EventID><EventRecordID>42</EventRecordID>'
            '<TimeCreated SystemTime="2026-08-25T01:02:03.0000000Z"/>'
            '<Computer>WIN10</Computer></System>'
            f'<EventData>{data}</EventData></Event>'
        )

    connect = bridge.parse_sysmon_event_xml(xml(3, {
        "ProcessGuid": "{ABC-123}", "ProcessId": "812", "Image": r"C:\Lab\sample.exe",
        "Protocol": "tcp", "Initiated": "true", "SourceIp": "192.168.56.10",
        "SourcePort": "49152", "DestinationIp": "192.168.56.2", "DestinationPort": "80",
    }))
    assert connect["event_id"] == 3
    assert connect["process_guid"] == "ABC-123"
    assert connect["process_id"] == 812
    assert connect["initiated"] is True
    assert connect["destination_port"] == 80

    dns = bridge.parse_sysmon_event_xml(xml(22, {
        "ProcessGuid": "{ABC-123}", "ProcessId": "812", "Image": r"C:\Lab\sample.exe",
        "QueryName": "example.test", "QueryStatus": "0", "QueryResults": "192.168.56.2;",
    }))
    assert dns["event_id"] == 22
    assert dns["query_name"] == "example.test"
    assert dns["query_results"] == "192.168.56.2;"


def test_network_pid_correlation():
    network_pid = load_module("network_pid", ROOT / "capelib" / "network_pid.py")
    capture = {
        "flows": [
            {
                "flow_id": "tcp:a", "protocol": "tcp",
                "src_ip": "192.168.56.10", "src_port": 49152,
                "dst_ip": "192.168.56.2", "dst_port": 80,
                "first_seen": 100.0, "last_seen": 101.0,
            },
            {
                "flow_id": "tcp:b", "protocol": "tcp",
                "src_ip": "192.168.56.2", "src_port": 80,
                "dst_ip": "192.168.56.10", "dst_port": 49152,
                "first_seen": 100.1, "last_seen": 101.1,
            },
        ],
        "events": [
            {
                "kind": "HTTP", "protocol": "tcp",
                "src_ip": "192.168.56.10", "src_port": 49152,
                "dst_ip": "192.168.56.2", "dst_port": 80, "time": 100.2,
            },
            {
                "kind": "DNS", "host": "c2.example", "time": 100.0,
                "dns": {"query": "c2.example", "response": False},
            },
        ],
    }
    events = [
        {
            "event_id": 3, "record_id": 1, "utc_time": "1970-01-01T00:01:40Z",
            "process_guid": "ABC", "process_id": 10, "image": r"C:\Lab\sample.exe",
            "protocol": "tcp", "source_ip": "192.168.56.10", "source_port": 49152,
            "destination_ip": "192.168.56.2", "destination_port": 80,
        },
        {
            "event_id": 22, "record_id": 2, "utc_time": "1970-01-01T00:01:40Z",
            "process_guid": "ABC", "process_id": 10, "image": r"C:\Lab\sample.exe",
            "query_name": "C2.EXAMPLE.",
        },
    ]
    lineage = {"10": {"role": "root", "exe": r"C:\Lab\sample.exe", "sysmon_guid": "ABC"}}
    synchronized = {"status": "synchronized", "usable": True, "offset_ns": 0, "uncertainty_ns": 1_000_000}
    result = network_pid.correlate_capture(capture, events, lineage, clock_sync=synchronized)
    first, reverse = result["flows"]
    assert first["attribution"]["confidence"] == "high", first
    assert first["attribution"]["pid"] == 10
    assert first["attribution"]["tracked"] is True
    assert reverse["attribution"]["confidence"] == "medium", reverse
    assert result["events"][0]["attribution"]["pid"] == 10
    dns = result["events"][1]["attribution"]
    assert dns["pid"] == 10 and dns["semantics"] == "dns_requester_not_wire_owner"
    assert result["attribution"]["flows"]["mapped"] == 2
    assert result["attribution"]["flows"]["high"] == 1
    assert result["attribution"]["flows"]["medium"] == 1

    ambiguous_events = [events[0], {**events[0], "record_id": 3, "process_guid": "DEF", "process_id": 20}]
    ambiguous = network_pid.correlate_capture({"flows": [capture["flows"][0]], "events": []}, ambiguous_events, lineage, clock_sync=synchronized)
    assert ambiguous["flows"][0]["attribution"]["status"] == "ambiguous"

    reused = network_pid.correlate_capture(
        {"flows": [capture["flows"][0]], "events": []},
        [{**events[0], "process_guid": "REUSED"}],
        lineage,
        clock_sync=synchronized,
    )
    assert reused["flows"][0]["attribution"]["tracked"] is False


def test_network_clock_compensation():
    network_pid = load_module("network_pid_clock", ROOT / "capelib" / "network_pid.py")
    capture = {
        "flows": [{
            "protocol": "tcp",
            "src_ip": "192.168.56.10", "src_port": 50000,
            "dst_ip": "192.168.56.2", "dst_port": 80,
            # Ubuntu clock is 100 seconds behind the Windows guest.
            "first_seen": 100.0, "last_seen": 101.0,
        }],
        "events": [],
    }
    events = [{
        "event_id": 3, "record_id": 7,
        "utc_time": "1970-01-01T00:03:20Z",
        "process_guid": "CLOCK", "process_id": 10,
        "image": r"C:\Lab\sample.exe", "protocol": "tcp",
        "source_ip": "192.168.56.10", "source_port": 50000,
        "destination_ip": "192.168.56.2", "destination_port": 80,
    }]
    lineage = {"10": {"role": "root", "sysmon_guid": "CLOCK"}}
    clock = {
        "status": "offset_compensated",
        "source": "agent_response_midpoint",
        "offset_ns": -100 * 1_000_000_000,
        "uncertainty_ns": 5 * 1_000_000,
    }
    result = network_pid.correlate_capture(
        capture, events, lineage, clock_sync=clock
    )
    assert result["flows"][0]["attribution"]["pid"] == 10, result
    correlation = result["attribution"]["clock_correlation"]
    assert correlation["compensation_applied"] is True
    assert correlation["raw_timestamps_modified"] is False

    unreliable = {**clock, "status": "unreliable", "uncertainty_ns": 9_000_000_000}
    missed = network_pid.correlate_capture(
        capture, events, lineage, clock_sync=unreliable
    )
    assert missed["flows"][0]["attribution"]["status"] == "unmapped"
    assert missed["attribution"]["clock_correlation"]["usable"] is False

    second_flow = {
        "protocol": "tcp",
        "src_ip": "192.168.56.10", "src_port": 50001,
        "dst_ip": "192.168.56.2", "dst_port": 443,
        "first_seen": 102.0, "last_seen": 103.0,
    }
    second_event = {
        **events[0], "record_id": 8,
        "utc_time": "1970-01-01T00:03:22Z",
        "source_port": 50001, "destination_port": 443,
    }
    consensus = network_pid.correlate_capture(
        {"flows": [capture["flows"][0], second_flow], "events": []},
        [events[0], second_event],
        lineage,
        clock_sync=unreliable,
    )
    consensus_clock = consensus["attribution"]["clock_correlation"]
    assert consensus_clock["status"] == "tuple_consensus_estimate", consensus_clock
    assert consensus_clock["unique_connections"] == 2
    assert consensus["attribution"]["flows"]["mapped"] == 2


def test_pcap_client_clock_sample():
    client_module = load_module(
        "pcap_client_clock", ROOT / "lib" / "common" / "pcap_task_client.py"
    )
    client = client_module.PcapTaskClient("http://192.168.56.2:54321")
    client._record_clock_sample(
        {"server_time_ns": 900_010_000_000},
        1_000_000_000_000,
        1_000_020_000_000,
    )
    clock = client.runtime["clock_sync"]
    assert clock["status"] == "offset_compensated", clock
    assert clock["offset_ns"] == -100_000_000_000, clock
    assert clock["uncertainty_ns"] == 10_000_000, clock
    assert client.runtime["schema"] == "capesolo-pcap-runtime/1.4"
    assert client.runtime["clock_domains"]["capture_started_agent_utc"] == "ubuntu_agent"
    client._record_clock_sample(
        {"server_time_ns": 970_010_000_000},
        1_010_000_000_000,
        1_010_020_000_000,
        sample_kind="/v1/status",
    )
    clock = client.runtime["clock_sync"]
    assert clock["status"] == "clock_discontinuity", clock
    assert clock["usable"] is False and clock["fallback_allowed"] is False
    assert clock["discontinuity_intervals"][0]["step_ns"] == 60_000_000_000


def test_p32313_clock_samples_are_continuous_slew():
    from CAPEsolo.lib.common.clock_model import analyze_clock_samples
    from CAPEsolo.capelib import network_pid

    # Exact six offsets and server timestamps captured by the P3.2.3.13 run.
    points = [
        (1787941519180434544, 85725513944, 66839300),
        (1787941529232517398, 88048218598, 12943300),
        (1787941539255669534, 89646422234, 6944300),
        (1787941550033583528, 91171896828, 7142800),
        (1787941560479799549, 90999427349, 1868400),
        (1787941560607993448, 91047371498, 64871850),
    ]
    sample_points = [
        {
            "status": "offset_compensated", "server_time_ns": server,
            "offset_ns": offset, "uncertainty_ns": uncertainty,
        }
        for server, offset, uncertainty in points
    ]
    modeled = analyze_clock_samples(sample_points)
    assert modeled["status"] == "clock_slew_compensated", modeled
    assert modeled["usable"] is True and modeled["full_capture_usable"] is True
    assert modeled["slew_detected"] is True
    assert modeled["discontinuity_detected"] is False
    assert modeled["slew_intervals"][0]["reason"] == "same_direction_neighbor_continuation"

    # A stale P3.2.3.13 all-or-nothing verdict is recomputed from raw samples.
    context = network_pid._clock_context({
        "status": "clock_discontinuity", "usable": False,
        "discontinuity_detected": True, "sample_points": sample_points,
        "offset_ns": points[-1][1], "uncertainty_ns": points[-1][2],
    }, 5.0)
    assert context["status"] == "clock_slew_compensated", context
    assert context["usable"] is True and not context["unusable_intervals"]


def test_clock_step_is_segmented_not_globally_rejected():
    from CAPEsolo.capelib import network_pid

    clock = {
        "status": "offset_compensated", "usable": True,
        "offset_ns": 2_000_000_000, "uncertainty_ns": 1_000_000,
        "sample_points": [
            {"status": "offset_compensated", "server_time_ns": 100_000_000_000,
             "offset_ns": 2_000_000_000, "uncertainty_ns": 1_000_000},
            {"status": "offset_compensated", "server_time_ns": 150_000_000_000,
             "offset_ns": 2_100_000_000, "uncertainty_ns": 1_000_000},
            {"status": "offset_compensated", "server_time_ns": 200_000_000_000,
             "offset_ns": 64_000_000_000, "uncertainty_ns": 1_000_000},
            {"status": "offset_compensated", "server_time_ns": 250_000_000_000,
             "offset_ns": 64_100_000_000, "uncertainty_ns": 1_000_000},
        ],
    }
    flows = []
    events = []
    for index, (stamp, port, guest_stamp) in enumerate((
        (120.0, 50000, 117.96),
        (175.0, 50001, 0.0),
        (230.0, 50002, 165.94),
    ), 1):
        flows.append({
            "protocol": "tcp", "src_ip": "192.168.56.10", "src_port": port,
            "dst_ip": "192.168.56.2", "dst_port": 80,
            "first_seen": stamp, "last_seen": stamp + 0.1,
        })
        if guest_stamp:
            events.append({
                "event_id": 3, "record_id": index, "utc_time": guest_stamp,
                "process_guid": "CLOCK", "process_id": 10, "protocol": "tcp",
                "source_ip": "192.168.56.10", "source_port": port,
                "destination_ip": "192.168.56.2", "destination_port": 80,
            })
    result = network_pid.correlate_capture(
        {"flows": flows, "events": []}, events,
        {"10": {"role": "root", "sysmon_guid": "CLOCK"}},
        tolerance=1.0, clock_sync=clock,
    )
    context = result["attribution"]["clock_correlation"]
    assert context["status"] == "clock_segmented", context
    assert context["usable"] is True and context["full_capture_usable"] is False
    assert result["attribution"]["flows"]["mapped"] == 2, result
    assert result["flows"][1]["attribution"]["method"] == "clock_segment_unusable"
    assert result["flows"][1]["attribution"]["reason"] == "flow_overlaps_clock_discontinuity_interval"


def test_clock_dual_monotonic_sample_metadata():
    client_module = load_module(
        "pcap_client_monotonic", ROOT / "lib" / "common" / "pcap_task_client.py"
    )
    client = client_module.PcapTaskClient("http://192.168.56.2:54321")
    client._record_clock_sample(
        {"server_time_ns": 1_100_010_000_000, "server_monotonic_ns": 500_010_000_000},
        1_000_000_000_000, 1_000_020_000_000,
        client_send_monotonic_ns=400_000_000_000,
        client_receive_monotonic_ns=400_020_000_000,
    )
    point = client.runtime["clock_sync"]["sample_points"][0]
    assert point["client_midpoint_monotonic_ns"] == 400_010_000_000
    assert point["server_monotonic_ns"] == 500_010_000_000
    assert client.runtime["clock_sync"]["schema"] == "capesolo-clock-correlation/1.3"
    client._record_clock_sample(
        {"server_time_ns": 1_200_000_000_000, "server_monotonic_ns": 600_000_000_000},
        1_100_000_000_000, 1_101_000_000_000,
        client_send_monotonic_ns=500_000_000_000,
        client_receive_monotonic_ns=500_020_000_000,
    )
    jumped = client.runtime["clock_sync"]["sample_points"][-1]
    assert jumped["status"] == "unreliable", jumped
    assert jumped["client_request_wall_adjustment_ns"] == 980_000_000


def test_microsoft_telemetry_subdomain_is_environmental():
    from CAPEsolo.capelib.network_summary import NetworkSummary

    result = NetworkSummary(capture={
        "events": [{
            "kind": "TLS", "host": "self.events.data.microsoft.com",
            "src_ip": "192.168.56.101", "src_port": 50000,
            "dst_ip": "192.168.56.2", "dst_port": 443,
            "tls": {"hello": "client", "version": "TLS 1.2"},
        }],
        "flows": [], "hosts": {}, "counts": {"TLS": 1},
    })
    row = result["tls"][0]
    assert row["traffic_class"] == "os_background", row
    assert row["signature_eligible"] is False
    assert row["classification_reason"] == "known_microsoft_telemetry"


def test_pcap_periodic_clock_sampler_request():
    client_module = load_module(
        "pcap_client_sampler", ROOT / "lib" / "common" / "pcap_task_client.py"
    )
    client = client_module.PcapTaskClient("http://192.168.56.2:54321")
    client.runtime["run_id"] = "run id/with spaces"
    requested = []
    client._json_request = lambda method, path: requested.append((method, path)) or {"status": "capturing"}
    assert client._clock_sample_once() is True
    assert requested == [("GET", "/v1/status?run_id=run%20id%2Fwith%20spaces")]
    assert client.runtime["clock_sampler"]["periodic_requests"] == 1


def test_clock_drift_interpolation():
    network_pid = load_module("network_pid_drift", ROOT / "capelib" / "network_pid.py")
    capture = {
        "flows": [
            {
                "protocol": "tcp", "src_ip": "192.168.56.10", "src_port": 50000,
                "dst_ip": "192.168.56.2", "dst_port": 80,
                "first_seen": 100.0, "last_seen": 100.5,
            },
            {
                "protocol": "tcp", "src_ip": "192.168.56.10", "src_port": 50001,
                "dst_ip": "192.168.56.2", "dst_port": 443,
                "first_seen": 200.0, "last_seen": 200.5,
            },
        ],
        "events": [],
    }
    events = [
        {
            "event_id": 3, "record_id": 1, "utc_time": "1970-01-01T00:01:30Z",
            "process_guid": "CLOCK", "process_id": 10, "protocol": "tcp",
            "source_ip": "192.168.56.10", "source_port": 50000,
            "destination_ip": "192.168.56.2", "destination_port": 80,
        },
        {
            "event_id": 3, "record_id": 2, "utc_time": "1970-01-01T00:03:09Z",
            "process_guid": "CLOCK", "process_id": 10, "protocol": "tcp",
            "source_ip": "192.168.56.10", "source_port": 50001,
            "destination_ip": "192.168.56.2", "destination_port": 443,
        },
    ]
    clock = {
        "status": "offset_compensated", "offset_ns": 10_000_000_000,
        "uncertainty_ns": 1_000_000, "drift_detected": True,
        "offset_span_ns": 1_000_000_000,
        "sample_points": [
            {"status": "offset_compensated", "server_time_ns": 100_000_000_000,
             "offset_ns": 10_000_000_000, "uncertainty_ns": 1_000_000},
            {"status": "offset_compensated", "server_time_ns": 150_000_000_000,
             "offset_ns": 10_500_000_000, "uncertainty_ns": 1_000_000},
            {"status": "offset_compensated", "server_time_ns": 200_000_000_000,
             "offset_ns": 11_000_000_000, "uncertainty_ns": 1_000_000},
        ],
    }
    result = network_pid.correlate_capture(
        capture, events, {"10": {"role": "root", "sysmon_guid": "CLOCK"}},
        tolerance=1.0, clock_sync=clock,
    )
    assert result["attribution"]["flows"]["mapped"] == 2, result
    correlation = result["attribution"]["clock_correlation"]
    assert correlation["model"] == "piecewise_linear"
    assert correlation["drift_detected"] is True


def test_clock_discontinuity_rejects_pid_and_tuple_fallback():
    network_pid = load_module("network_pid_discontinuity", ROOT / "capelib" / "network_pid.py")
    flows = [
        {"protocol": "tcp", "src_ip": "192.168.56.10", "src_port": 50000,
         "dst_ip": "192.168.56.2", "dst_port": 80, "first_seen": 100.0, "last_seen": 101.0},
        {"protocol": "tcp", "src_ip": "192.168.56.10", "src_port": 50001,
         "dst_ip": "192.168.56.2", "dst_port": 443, "first_seen": 200.0, "last_seen": 201.0},
    ]
    events = [
        {"event_id": 3, "record_id": 1, "utc_time": "1970-01-01T00:01:38Z",
         "process_guid": "CLOCK", "process_id": 10, "protocol": "tcp",
         "source_ip": "192.168.56.10", "source_port": 50000,
         "destination_ip": "192.168.56.2", "destination_port": 80},
        {"event_id": 3, "record_id": 2, "utc_time": "1970-01-01T00:02:16Z",
         "process_guid": "CLOCK", "process_id": 10, "protocol": "tcp",
         "source_ip": "192.168.56.10", "source_port": 50001,
         "destination_ip": "192.168.56.2", "destination_port": 443},
    ]
    # This is deliberately shaped like a P3.2.3.12 runtime: the jump was not
    # labelled, so the correlator must infer it independently from sample points.
    clock = {
        "status": "offset_compensated", "usable": True, "uncertainty_ns": 1_000_000,
        "sample_points": [
            {"status": "offset_compensated", "server_time_ns": 100_000_000_000,
             "offset_ns": 2_000_000_000, "uncertainty_ns": 1_000_000},
            {"status": "offset_compensated", "server_time_ns": 200_000_000_000,
             "offset_ns": 64_000_000_000, "uncertainty_ns": 1_000_000},
        ],
    }
    result = network_pid.correlate_capture(
        {"flows": flows, "events": []}, events,
        {"10": {"role": "root", "sysmon_guid": "CLOCK"}},
        clock_sync=clock,
    )
    correlation = result["attribution"]["clock_correlation"]
    assert correlation["status"] == "clock_discontinuity", correlation
    assert correlation["usable"] is False and correlation["fallback_allowed"] is False
    assert result["attribution"]["flows"]["mapped"] == 0
    assert all(flow["attribution"]["method"] == "clock_correlation_unusable" for flow in result["flows"])


def test_raw_event_accounting_after_pid_correlation():
    from CAPEsolo.capelib import network_pid, network_summary
    request = {
        "kind": "HTTP", "protocol": "tcp", "src_ip": "192.168.56.10",
        "src_port": 50000, "dst_ip": "192.168.56.2", "dst_port": 80,
        "time": 1.0, "host": "example.test", "collapse": ("HTTP", "GET", "/"),
        "http": {"response": False, "method": "GET", "target": "/",
                 "version": "1.1", "host": "example.test", "headers": {}},
    }
    capture = network_pid.correlate_capture(
        {"flows": [], "events": [request, {**request, "time": 2.0}], "hosts": {}},
        [], {},
    )
    assert len(capture["events"]) == 2
    assert len(capture["display_events"]) == 1
    assert capture["display_events"][0]["repeats"] == 2
    summary = network_summary.NetworkSummary(capture=capture)
    assert len(summary["http"]) == 1
    assert summary["http"][0]["count"] == 2
    assert summary["capture"]["raw_event_occurrences"] == 2
    assert summary["capture"]["display_event_rows"] == 1
    assert summary["capture"]["protocol_occurrences"]["http_requests"] == 2


def test_http_plaintext_enriches_without_double_counting():
    from CAPEsolo.capelib import network_summary
    request = {
        "kind": "HTTP", "protocol": "tcp", "src_ip": "192.168.56.10",
        "src_port": 50000, "dst_ip": "192.168.56.2", "dst_port": 80,
        "time": 100.0, "host": "example.test",
        "http": {"response": False, "method": "GET", "target": "/a",
                 "version": "1.1", "host": "example.test", "headers": {}},
    }
    decrypted = {"http_ex": [{
        "src": "192.168.56.10", "sport": 50000, "dst": "192.168.56.2", "dport": 80,
        "method": "GET", "host": "example.test", "uri": "/a",
        "request": "GET /a HTTP/1.1\r\nHost: example.test", "first_seen": 100.0,
    }]}
    summary = network_summary.NetworkSummary(
        capture={"flows": [], "events": [request], "hosts": {}}, decrypted=decrypted,
    )
    assert len(summary["http"]) == 1, summary["http"]
    assert summary["http"][0]["count"] == 1
    assert set(summary["http"][0]["observation_sources"]) == {"capture", "decrypted"}
    assert summary["http"][0]["data"].startswith("GET /a")


def test_dns_request_response_occurrence_accounting():
    from CAPEsolo.capelib import network_pid, network_summary
    base = {
        "kind": "DNS", "protocol": "udp", "host": "c2.example",
        "src_ip": "192.168.56.10", "src_port": 50053,
        "dst_ip": "192.168.56.2", "dst_port": 53, "time": 100.0,
        "collapse": ("DNS", "c2.example", False),
        "dns": {"query": "c2.example", "query_type": "A", "response": False},
    }
    response = {
        **base, "src_ip": "192.168.56.2", "src_port": 53,
        "dst_ip": "192.168.56.10", "dst_port": 50053, "time": 100.1,
        "collapse": ("DNS", "c2.example", True),
        "dns": {"query": "c2.example", "query_type": "A", "response": True,
                "answers": [{"data": "192.168.56.2", "type": "A"}]},
    }
    evidence = [{
        "event_id": 22, "record_id": 4, "utc_time": "1970-01-01T00:01:40Z",
        "process_guid": "DNS", "process_id": 10, "query_name": "c2.example",
    }]
    capture = network_pid.correlate_capture(
        {"flows": [], "events": [base, response], "hosts": {}}, evidence,
        {"10": {"role": "root", "sysmon_guid": "DNS"}},
        clock_sync={"status": "synchronized", "usable": True, "offset_ns": 0, "uncertainty_ns": 1_000_000},
    )
    counts = capture["attribution"]["dns"]
    assert counts["requests_total"] == 1 and counts["responses_total"] == 1
    assert counts["mapped"] == 1 and counts["unmapped"] == 0
    summary = network_summary.NetworkSummary(capture=capture)
    assert summary["dns"][0]["count"] == 1
    assert summary["dns"][0]["response_count"] == 1


def test_tls_preflight_preserves_key_material_count():
    from CAPEsolo.capelib import network_decrypt
    old_unavailable = network_decrypt.Unavailable
    old_get_master = network_decrypt.GetTlsMaster
    try:
        network_decrypt.Unavailable = lambda: "httpreplay-ng deliberately unavailable"
        network_decrypt.GetTlsMaster = lambda _analysis: {b"client": b"secret"}
        result = network_decrypt.DecryptStreams(".", "missing.pcap")
    finally:
        network_decrypt.Unavailable = old_unavailable
        network_decrypt.GetTlsMaster = old_get_master
    assert result["available"] is False
    assert result["secrets"] == 1
    assert result["key_material"]["status"] == "available"
    assert result["engine"]["status"] == "unavailable"


def test_local_discovery_and_packet_loss_metadata():
    from CAPEsolo.capelib import network, network_summary
    traffic_class, eligible, reason = network_summary._TrafficClassification(
        {}, "", "udp", "192.168.56.10", 5353, "224.0.0.251", 5353
    )
    assert traffic_class == "local_service_discovery"
    assert eligible is False and reason == "mdns_multicast"
    flow_key = ("192.168.56.10", 50000, "192.168.56.2", 80, network.IP_TCP)
    connection_key = network._ConnectionKey(*flow_key)
    rows = network._FlowRows(
        {flow_key: {"bytes": 1, "packets": 1, "first": 1.0, "last": 1.0}},
        {"192.168.56.2": {"aaa-unrelated.test", "events.data.microsoft.com"}},
        {connection_key: {"events.data.microsoft.com"}},
    )
    assert rows[0]["host"] == "events.data.microsoft.com"
    assert network_summary._TrafficClassification({}, rows[0]["host"])[0] == "os_background"
    agent = load_module(
        "pcap_agent_loss", PROJECT_ROOT / "extras" / "ubuntu_pcap_agent" / "capesolo_pcap_agent.py"
    )
    assert agent.packet_loss_metadata(10, None)[0] == "unknown"
    assert agent.packet_loss_metadata(10, 0)[0] == "none_observed"
    assert agent.packet_loss_metadata(10, 2)[0] == "drops_observed"


def test_sysmon_final_drain_shutdown_order_source():
    source = (ROOT / "modules" / "auxiliary" / "frida_muncher.py").read_text(encoding="utf-8")
    stop_source = source[source.index("    def stop(self):"):]
    assert stop_source.index("self._stop_pcap_capture()") < stop_source.index("self.sysmon_bridge.drain(")
    assert stop_source.index("self.sysmon_bridge.drain(") < stop_source.index("self.sysmon_bridge.stop()")
    assert 'event_id not in (3, 5, 22)' in source


def test_http_response_separation_and_environment_gate():
    from CAPEsolo.capelib import network as network_module
    from CAPEsolo.capelib import network_summary as summary_module
    request = network_module.ParseHttp(
        b"GET /connecttest.txt HTTP/1.1\r\n"
        b"Host: www.msftconnecttest.com\r\n"
        b"User-Agent: Microsoft NCSI\r\n\r\n"
    )
    response = network_module.ParseHttp(
        b"HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\n\r\n"
    )
    assert request["message_type"] == "request" and request["method"] == "GET"
    assert response["message_type"] == "response" and response["status_code"] == "200"
    assert response["method"] == "" and response["target"] == ""

    capture = {
        "events": [
            {
                "kind": "HTTP", "src_ip": "192.168.56.10", "src_port": 50000,
                "dst_ip": "192.168.56.2", "dst_port": 80, "time": 1.0,
                "host": "www.msftconnecttest.com",
                "http": {**request, "host": "www.msftconnecttest.com"},
                "attribution": {"status": "mapped", "tracked": False, "process": r"C:\Windows\System32\svchost.exe"},
            },
            {
                "kind": "HTTP", "src_ip": "192.168.56.2", "src_port": 80,
                "dst_ip": "192.168.56.10", "dst_port": 50000, "time": 1.1,
                "http": {**response, "host": ""},
                "attribution": {"status": "mapped", "tracked": False, "process": r"C:\Windows\System32\svchost.exe"},
            },
        ],
        "flows": [],
        "hosts": {"192.168.56.2": ["www.msftconnecttest.com"]},
    }
    summary = summary_module.NetworkSummary(capture=capture)
    assert len(summary["http"]) == 1, summary["http"]
    assert len(summary["http_responses"]) == 1, summary["http_responses"]
    assert summary["http"][0]["signature_eligible"] is False
    assert summary["http"][0]["traffic_class"] == "os_background"
    assert summary["http_responses"][0]["status_code"] == "200"
    host = summary["hosts"][0]
    assert {"ip", "hostname", "country_name", "country_code", "asn"} <= set(host)


def test_optional_package_config_missing_is_quiet_source():
    source = (ROOT / "lib" / "common" / "abstracts.py").read_text(encoding="utf-8")
    assert "except ModuleNotFoundError as e:" in source
    assert "module_name.startswith(f\"{e.name}.\")" in source


def test_runtime_validator_network_summary():
    validator = load_module("runtime_validator_p32310", HERE / "p3_validate_runtime.py")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        (base / "pcap_runtime.json").write_text(json.dumps({
            "status": "complete", "fetched": True, "bytes": 100,
            "clock_sync": {
                "status": "synchronized", "source": "agent_response_midpoint",
                "offset_ns": 1000, "uncertainty_ns": 100,
            },
        }), encoding="utf-8")
        (base / "report.json").write_text(json.dumps({"network": {
            "attribution": {"flows": {"total": 1, "mapped": 1}, "dns": {}},
            "traffic_classification": {"counts": {"tracked_malware": 1}},
            "http": [{}], "http_responses": [{}], "tls": [],
        }}), encoding="utf-8")
        summary = validator.summarize_network(base)
        assert summary["capture_status"] == "complete"
        assert summary["clock_sync"]["status"] == "synchronized"
        assert summary["flows"]["mapped"] == 1
        assert summary["http_responses"] == 1


def test_environmental_http_signatures_are_gated():
    import types

    signature_module_name = "CAPEsolo.capelib.signatures"
    original = sys.modules.get(signature_module_name)
    stub = types.ModuleType(signature_module_name)

    class StubSignature:
        def __init__(self, results=None):
            self.results = results or {}
            self.data = []
            self.weight = 0

    stub.Signature = StubSignature
    sys.modules[signature_module_name] = stub
    try:
        cnc_module = load_module(
            "network_cnc_http_gate",
            ROOT / "signatures" / "community" / "network_cnc_http.py",
        )
        http_module = load_module(
            "network_http_gate",
            ROOT / "signatures" / "community" / "network_http.py",
        )
    finally:
        if original is None:
            sys.modules.pop(signature_module_name, None)
        else:
            sys.modules[signature_module_name] = original

    request = {
        "host": "www.msftconnecttest.com",
        "method": "GET",
        "uri": "http://www.msftconnecttest.com/connecttest.txt",
        "path": "/connecttest.txt",
        "version": "1.1",
        "data": "",
        "signature_eligible": False,
        "traffic_class": "os_background",
    }
    results = {"network": {"http": [request]}, "target": {}}
    assert http_module.NetworkHTTP(results).run() is False
    assert cnc_module.NetworkCnCHTTP(results).run() is False

    tracked = {**request, "host": "c2.example", "uri": "http://c2.example/a", "signature_eligible": True}
    tracked_results = {"network": {"http": [tracked]}, "target": {}}
    assert cnc_module.NetworkCnCHTTP(tracked_results).run() is True


def test_network_status_axes():
    finalizer = load_module("finalizer_network", HERE / "frida_p3_finalize.py")
    network_pid = load_module("network_pid_scope", ROOT / "capelib" / "network_pid.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "dump.pcapng").write_bytes(b"X" * 24)
        (d / "pcap_runtime.json").write_text(json.dumps({
            "configured": True, "required": False, "status": "complete", "fetched": True,
            "bytes": 24, "sha256": "a" * 64,
        }), encoding="utf-8")
        (d / "report.json").write_text(json.dumps({"network": {
            "sources": ["pcap"],
            "capture": {"counts": {"frames": 3, "packets": 2, "DNS": 1, "TLS": 1}, "sessions": {"total": 1, "with_keys": 0}},
            "attribution": {
                "flows": {"total": 2, "mapped": 1, "high": 1, "medium": 0, "ambiguous": 0, "unmapped": 1, "tracked": 1},
                "dns": {"mapped": 1, "ambiguous": 0, "unmapped": 0},
                "sysmon_connect_events": 1, "sysmon_dns_events": 1,
            },
            "dns": [{"request": "x"}], "http": [], "decrypted": {"counts": {"https_ex": 0}},
        }}), encoding="utf-8")
        observed = finalizer.build_network_observation(d, {})
        assert observed["capture_status"] == "complete", observed
        assert observed["pid_attribution_status"] == "partial", observed
        assert observed["tls_visibility"] == "metadata_only", observed
        assert observed["absence_interpretation"] == "tracked_network_observed"

        unsynced_report = json.loads((d / "report.json").read_text(encoding="utf-8"))
        unsynced_report["network"]["attribution"]["flows"].update(mapped=0, unmapped=2)
        unsynced_report["network"]["attribution"]["clock_correlation"] = {
            "status": "unreliable", "usable": False
        }
        (d / "report.json").write_text(json.dumps(unsynced_report), encoding="utf-8")
        unsynced = finalizer.build_network_observation(d, {})
        assert unsynced["pid_attribution_status"] == "clock_unsynchronized", unsynced

        discontinuous_report = json.loads((d / "report.json").read_text(encoding="utf-8"))
        discontinuous_report["network"]["attribution"]["clock_correlation"] = {
            "status": "clock_discontinuity", "usable": False, "discontinuity_detected": True,
        }
        (d / "report.json").write_text(json.dumps(discontinuous_report), encoding="utf-8")
        discontinuous = finalizer.build_network_observation(d, {})
        assert discontinuous["pid_attribution_status"] == "clock_discontinuity", discontinuous
        assert discontinuous["absence_interpretation"] == "network_attribution_inconclusive_clock_discontinuity"

        segmented_report = json.loads((d / "report.json").read_text(encoding="utf-8"))
        segmented_report["network"]["attribution"]["flows"].update(
            mapped=1, unmapped=1, tracked=0
        )
        segmented_report["network"]["attribution"]["clock_correlation"] = {
            "status": "clock_segmented", "usable": True,
            "discontinuity_detected": True,
            "unusable_intervals": [{"server_start_ns": 10, "server_end_ns": 20}],
        }
        (d / "report.json").write_text(json.dumps(segmented_report), encoding="utf-8")
        segmented = finalizer.build_network_observation(d, {})
        assert segmented["pid_attribution_status"] == "partial_clock_segments", segmented
        assert segmented["absence_interpretation"] == "network_attribution_partial_clock_segments"

        compensated_report = json.loads((d / "report.json").read_text(encoding="utf-8"))
        compensated_report["network"]["attribution"]["flows"].update(
            mapped=2, unmapped=0, tracked=0
        )
        compensated_report["network"]["attribution"]["clock_correlation"] = {
            "status": "clock_slew_compensated", "usable": True,
            "slew_detected": True,
        }
        (d / "report.json").write_text(json.dumps(compensated_report), encoding="utf-8")
        compensated = finalizer.build_network_observation(d, {})
        assert compensated["pid_attribution_status"] == "complete", compensated
        assert compensated["absence_interpretation"] == "tracked_network_not_observed_after_complete_attribution"

        # A file left by an older task must not become evidence when the current
        # capture failed or carries a different run id.
        (d / "frida_p3_runtime.json").write_text(
            json.dumps({"run_id": "CURRENT"}), encoding="utf-8"
        )
        (d / "pcap_runtime.json").write_text(json.dumps({
            "configured": True, "run_id": "OLD", "status": "complete", "fetched": True,
        }), encoding="utf-8")
        assert network_pid.discover_task_capture(d) is None
        failed = finalizer.build_network_observation(d, {
            "run_id": "CURRENT",
            "pcap": {"configured": True, "run_id": "CURRENT", "status": "start_failed", "errors": ["offline"]},
        })
        assert failed["capture_status"] == "failed", failed
        assert failed["absence_interpretation"] == "network_coverage_unavailable"


def test_finalizer_smoke():
    finalizer = load_module("finalizer", HERE / "frida_p3_finalize.py")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        runtime = {
            "schema": "capesolo-frida-p3-runtime/1",
            "version": PRODUCT_VERSION,
            "run_id": "TEST-RUN",
            "run_started_wall": 1.0,
            "run_stopped_wall": 2.0,
            "profile": {"request": "auto", "selected": "generic", "selection": {"source": "exact_root"}},
            "target_pid": 10,
            "gate_mode": "none",
            "lineage": {"10": {"role": "root", "create_time": 1.0, "exe": r"C:\Lab\sample.exe"}},
            "sysmon": {},
            "evidence": [
                {"kind": "frida_hooks_ready", "role": "root", "pid": 10, "run_id": "TEST-RUN"},
                {"kind": "root_instrumentation_ready", "pid": 10, "run_id": "TEST-RUN"},
            ],
        }
        (d / "frida_p3_runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
        (d / "p3_current_run.json").write_text(json.dumps({"run_id": "TEST-RUN"}), encoding="utf-8")
        (d / "files.json").write_text("[]", encoding="utf-8")
        (d / "analysis.log").write_text(
            "[P3Evidence] " + json.dumps({"kind": "controller_start", "run_id": "TEST-RUN"}) + "\n"
            "Run completed\nResultServer transfers complete=1 incomplete=0\n",
            encoding="utf-8",
        )
        report_json = {
            "target": {"sha256": "abc", "pe": {"imagebase": "0x00400000"}},
            "behavior": {"processes": []},
            "signatures": [],
        }
        (d / "report.json").write_text(json.dumps(report_json), encoding="utf-8")
        report = finalizer.build_report(d, output_dir=d)
        assert report["version"] == PRODUCT_VERSION
        assert report["processor_version"] == PRODUCT_VERSION
        assert report["instrumentation"]["gate_status"] == "not_applicable"
        assert report["instrumentation"]["frida_any_ready"] is True
        assert report["status"] == "complete", report["status"]
        assert "retained_pe_unique" in report["artifacts"]["summary"]
        assert report["behavior_pid_repair"]["available"] is True

        with (d / "analysis.log").open("a", encoding="utf-8") as handle:
            handle.write(
                "ResultServer thread still alive after 10.0s, but all 1 recorded "
                "transfer(s) are complete; shutdown state is uncertain\n"
            )
        warned = finalizer.build_report(d, output_dir=d)
        assert warned["status"] == "complete", warned["status"]
        assert warned["status_axes"]["resultserver"] == "complete_with_shutdown_warning"
        assert warned["integrity"]["resultserver"]["shutdown_warning_count"] == 1

        runtime["lineage"]["20"] = {
            "role": "child", "create_time": 1.5, "exe": r"C:\Lab\stage.exe"
        }
        runtime["evidence"].extend([
            {"kind": "frida_attach", "role": "child", "pid": 20, "status": "success", "attempt": 1, "run_id": "TEST-RUN", "seq": 3},
            {
                "kind": "frida_script_setup_failed", "role": "child", "pid": 20,
                "status": "transport_closed_before_scripts", "error_type": "TransportError",
                "run_id": "TEST-RUN", "seq": 4,
            },
        ])
        (d / "frida_p3_runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
        degraded = finalizer.build_report(d, output_dir=d)
        assert degraded["status"] == "degraded", degraded["status"]
        assert degraded["status_axes"]["frida_child"] == "transport_closed_before_scripts", degraded["status_axes"]
        assert degraded["instrumentation"]["frida_script_setup_failures"] == 1


def _attack_call(api, arguments, timestamp="2026-08-27 18:15:49,000", status=True):
    return {
        "timestamp": timestamp,
        "thread_id": "1",
        "category": "process",
        "api": api,
        "status": status,
        "return": "0x00000000",
        "arguments": [{"name": key, "value": value} for key, value in arguments.items()],
    }


def _attack_results(calls=None, process_name="sample.exe", module_path=r"C:\Lab\sample.exe", network=None, signatures=None):
    return {
        "target": {"name": process_name, "path": module_path, "category": "file"},
        "behavior": {
            "processes": [{
                "process_id": 10,
                "process_name": process_name,
                "module_path": module_path,
                "calls": calls or [],
            }],
            "summary": {},
            "processtree": [],
        },
        "network": network or {},
        "signatures": signatures or [],
        "payloads": [],
        "configs": [],
        "detections": [],
        "js_log": {},
    }


def _with_pe_identity(results, versioninfo, digital_signers=None, sha256="a" * 64):
    results["target"].update({
        "sha256": sha256,
        "pe": {
            "versioninfo": [
                {"name": name, "value": value}
                for name, value in versioninfo.items()
            ],
            "digital_signers": list(digital_signers or []),
        },
    })
    return results


def test_mitre_blackenergy21_pe_metadata_masquerading_replay():
    """Replay the identity evidence preserved by the supplied BE 2.1 run."""
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    results = _with_pe_identity(
        _attack_results(
            [_attack_call("GetSystemInfo", {"ProcessorArchitecture": 9})],
            process_name="rootkit.exe",
            module_path=r"C:\Users\tan\AppData\Local\Temp\rootkit.exe",
        ),
        {
            "FileDescription": "notepad",
            "LegalCopyright": "notepad",
            "FileVersion": "1.0.0.0",
            "ProductVersion": "1.0.0.0",
            "OriginalFilename": "notepad.exe",
            "Translation": "0x0409 0x0000",
        },
        sha256="3f771dc26345179db8ad4979eea3284c416c430022b0b990873b074a9e4fbc57",
    )
    # CAPEsolo stores the randomized submission path in target metadata while
    # the process sensor preserves the runtime identity used for correlation.
    results["target"]["name"] = "s_" + results["target"]["sha256"]
    results["target"]["path"] = rf"C:\Users\Public\CAPEsolo\analysis\{results['target']['name']}"
    results["signatures"] = [{
        "name": "Unpacker", "description": "Executable extraction",
        "confidence": 100, "severity": 1, "ttps": ["T1027", "T1140"],
    }]
    results["payloads"] = [{"artifact": {
        "sha256": "b" * 64, "size": 4096,
        "cape_type": "Unpacked PE Image", "pid": 10,
    }}]

    report = map_mitre_attack(results, write_artifact=False)
    mappings = {row["id"]: row for row in report["mappings"]}
    assert mappings["T1036"]["status"] == "observed", mappings
    assert mappings["T1036"]["confidence"] == "high", mappings["T1036"]
    assert "masquerading.pe_identity_mismatch" in mappings["T1036"]["rule_ids"]
    state = mappings["T1036"]["state_machines"][0]
    assert state["complete"] is True
    assert state["state_trace"] == [
        "runtime_identity", "coherent_pe_identity", "identity_mismatch", "trust_anomaly",
    ]
    evidence = mappings["T1036"]["evidence"][0]
    assert evidence["source"] == "pe_process_identity"
    assert evidence["details"]["original_filename"] == "notepad.exe"
    assert evidence["details"]["runtime_name"] == "rootkit.exe"

    # Internal PE metadata supports the parent technique strongly. It is only
    # a candidate for T1036.005 because the runtime name/path does not itself
    # match the claimed legitimate resource.
    matched_name = mappings["T1036.005"]
    assert (matched_name["status"], matched_name["confidence"]) == ("candidate", "medium")

    # Parent and sub-technique belong to one score family and therefore cannot
    # double-charge the risk score. Unverified unpacking adds no score; the
    # metadata-only result remains provisional.
    from CAPEsolo.capelib.threat_assessment import assess_threat
    results["mitre_attack"] = report
    assessment = assess_threat(results)
    masquerading_signals = [
        row for component in assessment["components"]
        if component["category"] == "mitre_attack"
        for row in component["signals"] if str(row.get("id") or "").startswith("T1036")
    ]
    assert len(masquerading_signals) == 1 and masquerading_signals[0]["points"] == 5
    assert assessment["score"] < 20 and assessment["provisional"] is True, assessment
    assert mappings["T1140"]["status"] == "candidate"

    if importlib.util.find_spec("markupsafe") is not None and importlib.util.find_spec("jinja2") is not None:
        from CAPEsolo.classes.html_report import ReportHTML
        with tempfile.TemporaryDirectory() as td:
            complete, error = ReportHTML().run(Path(td), ROOT, results)
            assert complete is True and error is None, error
            html = (Path(td) / "report.html").read_text(encoding="utf-8")
            assert "T1036" in html and "DET0127" in html and "AN0355" in html
            assert "pe_process_identity" in html


def test_mitre_masquerading_metadata_false_positive_gates():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    # A renamed, signed Windows binary may be an analyst upload artifact. The
    # mismatch alone must not claim malicious masquerading.
    signed = _with_pe_identity(
        _attack_results(process_name="renamed.exe", module_path=r"C:\Lab\renamed.exe"),
        {
            "CompanyName": "Microsoft Corporation",
            "FileDescription": "Notepad",
            "OriginalFilename": "NOTEPAD.EXE",
            "ProductName": "Microsoft Windows Operating System",
        },
        digital_signers=[{"subject": "Microsoft Windows", "verified": True}],
    )
    signed_ids = {row["id"] for row in map_mitre_attack(signed, write_artifact=False)["mappings"]}
    assert "T1036" not in signed_ids and "T1036.005" not in signed_ids

    # One descriptive string is not a coherent embedded identity and must not
    # be promoted through keyword matching.
    weak = _with_pe_identity(
        _attack_results(process_name="rootkit.exe", module_path=r"C:\Temp\rootkit.exe"),
        {"FileDescription": "notepad"},
    )
    weak_ids = {row["id"] for row in map_mitre_attack(weak, write_artifact=False)["mappings"]}
    assert "T1036" not in weak_ids and "T1036.005" not in weak_ids


def test_mitre_dyre_masquerading_regression():
    """Dyre keeps its existing name/location evidence without metadata overreach."""
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    root_path = r"C:\SandboxAgent\Malware\Dyre\Original\Document-772976_829712.scr.exe"
    child_path = r"C:\Users\tan\AppData\Local\googleupdaterr.exe"
    results = _with_pe_identity(
        _attack_results(
            [_attack_call("CopyFileW", {"ExistingFileName": root_path, "NewFileName": child_path})],
            process_name="Document-772976_829712.scr.exe",
            module_path=root_path,
        ),
        {
            "CompanyName": "Arcom",
            "FileDescription": "Arcoms Application",
            "InternalName": "Arcom",
            "OriginalFilename": "Arcoms.exe",
            "ProductName": "Arcoms Application",
        },
        sha256="523b9e8057ef0905e2c7d51b742d4be9374cf2eee5a810f05d987604847c549d",
    )
    report = map_mitre_attack(results, write_artifact=False)
    mappings = {row["id"]: row for row in report["mappings"]}
    assert "T1036" not in mappings, mappings
    assert mappings["T1036.005"]["status"] == "candidate"
    assert mappings["T1036.007"]["status"] == "candidate"


def test_mitre_evidence_first_dyre_mapping():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    root_path = r"C:\Lab\Document.pdf.exe"
    child_path = r"C:\Users\u\AppData\Local\googleupdaterr.exe"
    calls = [
        _attack_call("CopyFileW", {"ExistingFileName": root_path, "NewFileName": child_path}),
        _attack_call("RegSetValueExW", {"FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\GoogleUpdate", "Buffer": child_path}),
        _attack_call("DeleteFileW", {"FileName": root_path}),
        _attack_call("CreateToolhelp32Snapshot", {"Flags": "0x2"}),
        _attack_call("Process32NextW", {"ProcessName": "powershell.exe", "ProcessId": 99}),
        _attack_call("NtOpenProcess", {"ProcessHandle": "0x200", "ProcessIdentifier": 99, "ProcessName": r"C:\Windows\explorer.exe"}),
    ]
    network = {
        "capture": {"path": "dump.pcapng", "runtime": {"status": "complete", "packet_loss_status": "none_observed"}},
        "attribution": {"clock_correlation": {"usable": True, "drift_detected": False}, "flows": {"tracked": 0}},
        "http": [{
            "host": "www.msftconnecttest.com", "signature_eligible": False,
            "traffic_class": "os_background", "attribution": {"tracked": False},
        }],
    }
    report = map_mitre_attack(
        _attack_results(calls, "Document.pdf.exe", root_path, network, [{
            "name": "Unpacker", "description": "Executable extraction", "confidence": 100,
            "severity": 1, "ttps": ["T1027", "T1140"],
        }]),
        write_artifact=False,
    )
    observed = {item["id"] for item in report["mappings"] if item["status"] == "observed"}
    assert {"T1057", "T1070.004", "T1112", "T1547.001"}.issubset(observed), report
    assert "T1027.002" not in observed, report  # no corroborated unpacking artifact
    t1140 = next(item for item in report["mappings"] if item["id"] == "T1140")
    assert t1140["status"] == "candidate", t1140
    assert "T1055" not in {item["id"] for item in report["mappings"]}
    assert any(item["id"] == "T1055" for item in report["rejected_candidates"])
    assert "T1071.001" not in {item["id"] for item in report["mappings"]}
    # Merely enumerating powershell.exe must not claim PowerShell execution.
    assert "T1059.001" not in {item["id"] for item in report["mappings"]}


def test_mitre_confirmed_injection_requires_write_and_execute():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    calls = [
        _attack_call("NtOpenProcess", {"ProcessHandle": "0x200", "ProcessIdentifier": 99}),
        _attack_call("NtWriteVirtualMemory", {"ProcessHandle": "0x200", "Buffer": "MZ"}),
        _attack_call("NtCreateThreadEx", {"ProcessHandle": "0x200", "ProcessId": 99, "StartAddress": "0x401000"}),
    ]
    report = map_mitre_attack(_attack_results(calls), write_artifact=False)
    injection = next(item for item in report["mappings"] if item["id"] == "T1055")
    assert injection["status"] == "observed" and injection["confidence"] == "high", injection
    assert not any(item["id"] == "T1055" for item in report["rejected_candidates"]), report

    mismatched = [
        _attack_call("NtOpenProcess", {"ProcessHandle": "0x200", "ProcessIdentifier": 99}),
        _attack_call("NtWriteVirtualMemory", {"ProcessHandle": "0x200", "Buffer": "MZ"}),
        _attack_call("NtCreateThreadEx", {"ProcessHandle": "0x300", "ProcessId": 100, "StartAddress": "0x401000"}),
    ]
    report = map_mitre_attack(_attack_results(mismatched), write_artifact=False)
    assert "T1055" not in {item["id"] for item in report["mappings"]}, report
    assert any(item["id"] == "T1055" for item in report["rejected_candidates"]), report


def test_mitre_framework_injection_is_excluded():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    calls = [
        _attack_call("NtMapViewOfSection", {"ProcessHandle": "0xffffffff", "Module": "frida-agent.dll"}),
        _attack_call("NtCreateThreadEx", {"ProcessHandle": "0xffffffff", "ProcessId": 10, "Module": "frida-agent.dll"}),
    ]
    report = map_mitre_attack(_attack_results(calls), write_artifact=False)
    assert "T1055" not in {item["id"] for item in report["mappings"]}, report


def test_mitre_network_lineage_and_quality_gate():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    base_network = {
        "capture": {"path": "dump.pcapng", "runtime": {"status": "complete", "packet_loss_status": "none_observed"}},
        "attribution": {"clock_correlation": {"usable": True, "drift_detected": False}, "flows": {"mapped": 1, "tracked": 1}},
        "http": [{
            "host": "c2.example", "signature_eligible": True, "traffic_class": "tracked_malware",
            "src": "192.168.56.10", "sport": 50000, "dst": "192.168.56.2", "dport": 80,
            "attribution": {"tracked": True, "confidence": "high", "pid": 10, "process": r"C:\Lab\sample.exe", "role": "root"},
        }],
    }
    report = map_mitre_attack(_attack_results(network=base_network), write_artifact=False)
    http = next(item for item in report["mappings"] if item["id"] == "T1071.001")
    assert http["status"] == "observed" and http["confidence"] == "high", http

    drifted = json.loads(json.dumps(base_network))
    drifted["attribution"]["clock_correlation"]["drift_detected"] = True
    report = map_mitre_attack(_attack_results(network=drifted), write_artifact=False)
    http = next(item for item in report["mappings"] if item["id"] == "T1071.001")
    assert http["status"] == "candidate", http
    assert any(item["code"] == "network_clock_drift" for item in report["coverage_warnings"])

    discontinuous = json.loads(json.dumps(base_network))
    discontinuous["attribution"]["clock_correlation"].update({
        "status": "clock_discontinuity", "usable": False,
        "discontinuity_detected": True,
    })
    report = map_mitre_attack(_attack_results(network=discontinuous), write_artifact=False)
    assert "T1071.001" not in {item["id"] for item in report["mappings"]}
    assert any(item["code"] == "network_clock_discontinuity" for item in report["coverage_warnings"])

    slewed = json.loads(json.dumps(base_network))
    slewed["attribution"]["clock_correlation"].update({
        "status": "clock_slew_compensated", "usable": True,
        "slew_detected": True, "drift_detected": True,
    })
    report = map_mitre_attack(_attack_results(network=slewed), write_artifact=False)
    http = next(item for item in report["mappings"] if item["id"] == "T1071.001")
    assert http["status"] == "candidate", http
    assert any(item["code"] == "network_clock_slew" for item in report["coverage_warnings"])

    segmented = json.loads(json.dumps(base_network))
    segmented["attribution"]["clock_correlation"].update({
        "status": "clock_segmented", "usable": True,
        "discontinuity_detected": True, "drift_detected": True,
        "unusable_intervals": [{"server_start_ns": 10, "server_end_ns": 20}],
    })
    report = map_mitre_attack(_attack_results(network=segmented), write_artifact=False)
    assert "T1071.001" in {item["id"] for item in report["mappings"]}
    assert any(item["code"] == "network_clock_segmented" for item in report["coverage_warnings"])


def test_mitre_unpacker_requires_extracted_artifact_for_t1140():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    results = _attack_results(signatures=[{
        "name": "Unpacker", "description": "Executable extraction",
        "confidence": 100, "severity": 1, "ttps": ["T1027", "T1140"],
    }])
    no_artifact = map_mitre_attack(results, write_artifact=False)
    assert next(row for row in no_artifact["mappings"] if row["id"] == "T1140")["status"] == "candidate"
    results["payloads"] = [{"artifact": {
        "sha256": "a" * 64, "size": 4096, "cape_type": "Unpacked PE Image", "pid": 10,
    }}]
    with_artifact = map_mitre_attack(results, write_artifact=False)
    mapped = next(row for row in with_artifact["mappings"] if row["id"] == "T1140")
    assert mapped["status"] == "candidate" and mapped["confidence"] == "low", mapped
    assert mapped["evidence"][0]["details"]["eligible_payload_count"] == "0"
    assert "a" * 64 in mapped["evidence"][0]["details"]["artifact_decisions"]


def test_mitre_legacy_id_normalization():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    report = map_mitre_attack(_attack_results(signatures=[{
        "name": "injection_process_hollowing", "description": "Process hollowing",
        "confidence": 100, "severity": 3, "ttps": ["T1055", "T1093"],
    }]), write_artifact=False)
    hollow = next(item for item in report["mappings"] if item["id"] == "T1055.012")
    assert hollow["status"] == "observed" and hollow["normalized_from"] == ["T1093"], hollow
    migrated = map_mitre_attack(_attack_results(signatures=[{
        "name": "legacy-defense", "description": "Legacy v18 IDs", "confidence": 95,
        "severity": 2, "ttps": ["T1070.001", "T1562.001"],
    }]), write_artifact=False)
    assert {row["id"] for row in migrated["mappings"]} == {"T1685", "T1685.005"}
    assert all(row["normalized_from"] for row in migrated["mappings"])


def test_mitre_artifact_and_html_rendering():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    with tempfile.TemporaryDirectory() as td:
        analysis = Path(td)
        calls = [_attack_call("RegSetValueExW", {
            "FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad",
            "Buffer": "<script>alert(1)</script>",
        })]
        results = _attack_results(calls, process_name="<script>sample.exe</script>")
        (analysis / "frida_p3_runtime.json").write_text(json.dumps({"run_id":"html-fixture", "target_pid":10,
            "lineage":{"10":{"role":"root", "exe":r"C:\Lab\sample.exe"}}}), encoding="utf-8")
        results["mitre_attack"] = map_mitre_attack(results, analysis, write_artifact=True)
        assert (analysis / "mitre_attack.json").is_file()
        # The production CAPEsolo environment already requires Jinja2 and
        # MarkupSafe. Keep this offline self-test runnable on a minimal build
        # host while still exercising a full render whenever those deps exist.
        if importlib.util.find_spec("markupsafe") is None or importlib.util.find_spec("jinja2") is None:
            template = (ROOT / "capelib" / "html" / "sections" / "mitre.html").read_text(encoding="utf-8")
            html_source = (ROOT / "classes" / "html_report.py").read_text(encoding="utf-8")
            assert "Tactic coverage" in template and "Rejected or incomplete hypotheses" in template
            assert "autoescape=True" in html_source
            return
        from CAPEsolo.classes.html_report import ReportHTML
        completed, error = ReportHTML().run(analysis, ROOT, results)
        assert completed is True and error is None, error
        html = (analysis / "report.html").read_text(encoding="utf-8")
        assert "MITRE ATT&amp;CK" in html and "T1547.001" in html
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_mitre_full_offline_catalog_and_official_detection_metadata():
    from CAPEsolo.capelib.mitre_attack import load_catalog
    enterprise, meta = load_catalog("enterprise-attack")
    mobile, _ = load_catalog("mobile-attack")
    ics, _ = load_catalog("ics-attack")
    assert (len(enterprise), len(mobile), len(ics)) == (697, 124, 97), meta
    assert meta["source_tag"] == "v19.2" and meta["complete_catalog"] is True
    assert meta["validation"]["complete"] is True
    enterprise_counts = meta["domains"]["enterprise-attack"]
    assert enterprise_counts["linked_analytics"] == 1745
    assert enterprise_counts["active_analytics"] == 1758
    assert enterprise_counts["linked_data_components"] == 98
    assert enterprise_counts["active_data_components"] == 106
    run_key = enterprise["T1547.001"]
    strategy = next(row for row in run_key["strategies"] if row["id"] == "DET0365")
    analytic = next(row for row in strategy["analytics"] if row["id"] == "AN1032")
    assert {row["id"] for row in analytic["data_components"]} == {"DC0032", "DC0039", "DC0063"}
    masquerading = enterprise["T1036"]
    strategy = next(row for row in masquerading["strategies"] if row["id"] == "DET0127")
    analytic = next(row for row in strategy["analytics"] if row["id"] == "AN0355")
    assert "internal PE metadata" in analytic["description"]
    assert any(row["field"] == "OriginalFilenameMismatch" for row in analytic["mutable_elements"])


def test_mitre_state_machine_time_and_target_gates():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    late = [
        _attack_call("NtWriteVirtualMemory", {"ProcessHandle": "0x200", "ProcessId": 99}, "2026-08-27 18:15:00,000"),
        _attack_call("NtCreateThreadEx", {"ProcessHandle": "0x200", "ProcessId": 99}, "2026-08-27 18:17:01,000"),
    ]
    report = map_mitre_attack(_attack_results(late), write_artifact=False)
    assert "T1055" not in {row["id"] for row in report["mappings"]}
    rejected = next(row for row in report["rejected_candidates"] if row["id"] == "T1055")
    assert rejected["state_machine"]["missing_steps"] == ["remote_execute"]
    assert "same remote target" in rejected["state_machine"]["quality_gates"]


def test_mitre_lsass_state_machine_positive_and_negative():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    opened = [_attack_call("NtOpenProcess", {"ProcessHandle": "0x500", "ProcessIdentifier": 700, "ProcessName": r"C:\Windows\System32\lsass.exe"})]
    report = map_mitre_attack(_attack_results(opened), write_artifact=False)
    assert "T1003.001" not in {row["id"] for row in report["mappings"]}
    assert any(row["id"] == "T1003.001" for row in report["rejected_candidates"])
    complete = opened + [_attack_call("ReadProcessMemory", {"ProcessHandle": "0x500", "Size": 4096}, "2026-08-27 18:15:50,000")]
    report = map_mitre_attack(_attack_results(complete), write_artifact=False)
    mapped = next(row for row in report["mappings"] if row["id"] == "T1003.001")
    assert mapped["status"] == "observed"
    assert mapped["state_machines"][0]["state_trace"] == ["lsass_access", "lsass_read_or_dump"]


def test_mitre_environment_check_requires_compound_evidence():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    one = map_mitre_attack(_attack_results([_attack_call("GetSystemMetrics", {"Index": 0})]), write_artifact=False)
    assert "T1497.001" not in {row["id"] for row in one["mappings"]}
    assert any(row["id"] == "T1497.001" for row in one["rejected_candidates"])
    two = map_mitre_attack(_attack_results([
        _attack_call("GetSystemMetrics", {"Index": 0}),
        _attack_call("GlobalMemoryStatusEx", {"TotalPhys": 2147483648}, "2026-08-27 18:15:50,000"),
    ]), write_artifact=False)
    mapped = next(row for row in two["mappings"] if row["id"] == "T1497.001")
    assert mapped["status"] == "candidate"
    assert set(mapped["state_machines"][0]["state_trace"]) == {"display", "memory"}


def test_mitre_registry_query_and_debugger_state_machines():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    calls = [
        # CAPEMON records a negative IsDebuggerPresent result as status=False;
        # the probe still completed and is ATT&CK evidence.
        _attack_call("IsDebuggerPresent", {}, status=False),
        _attack_call("RegQueryValueExW", {
            "FullName": r"HKEY_CURRENT_USER\Software\Vendor\Product\InstallPath",
            "ValueName": "InstallPath",
        }, "2026-08-27 18:15:49,100"),
        _attack_call("NtQueryValueKey", {
            "FullName": r"HKEY_LOCAL_MACHINE\Software\Vendor\Product\Version",
            "ValueName": "Version",
        }, "2026-08-27 18:15:49,200"),
        # An unrelated information class must not be converted into T1622 by
        # finding a number in a free-form argument string.
        _attack_call("NtQueryInformationProcess", {"ProcessInformationClass": 0}, "2026-08-27 18:15:49,300"),
    ]
    report = map_mitre_attack(_attack_results(calls), write_artifact=False)
    mappings = {row["id"]: row for row in report["mappings"]}
    assert mappings["T1012"]["status"] == "observed", mappings["T1012"]
    assert mappings["T1012"]["state_machines"][0]["complete"] is True
    assert len(mappings["T1012"]["state_machines"][0]["state_trace"]) == 2
    assert mappings["T1622"]["status"] == "observed", mappings["T1622"]
    assert mappings["T1622"]["state_machines"][0]["state_trace"] == ["debugger_probe"]

    one = map_mitre_attack(_attack_results([calls[1]]), write_artifact=False)
    assert next(row for row in one["mappings"] if row["id"] == "T1012")["status"] == "candidate"
    failed = dict(calls[1]); failed["status"] = False; failed["return"] = "0x00000002"
    none = map_mitre_attack(_attack_results([failed]), write_artifact=False)
    assert "T1012" not in {row["id"] for row in none["mappings"]}


def test_mitre_keylogging_state_machine_uses_structured_global_hook():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    hook = _attack_call("SetWindowsHookExW", {
        "HookIdentifier": 2, "ProcedureAddress": "0x100013d0",
        "ModuleAddress": "0x10000000", "ThreadId": 0,
    })
    hook["return"] = "0x000703ad"
    report = map_mitre_attack(_attack_results([hook]), write_artifact=False)
    mapped = next(row for row in report["mappings"] if row["id"] == "T1056.001")
    assert (mapped["status"], mapped["confidence"]) == ("observed", "high"), mapped
    assert mapped["state_machines"][0]["state_trace"] == ["keyboard_hook"]

    message_hook = _attack_call("SetWindowsHookExW", {
        "HookIdentifier": 4, "ProcedureAddress": "0x100015a0",
        "ModuleAddress": "0x10000000", "ThreadId": 0,
    })
    message_hook["return"] = "0x000e032b"
    no_map = map_mitre_attack(_attack_results([message_hook]), write_artifact=False)
    assert "T1056.001" not in {row["id"] for row in no_map["mappings"]}

    local_hook = _attack_call("SetWindowsHookExA", {
        "HookIdentifier": 2, "ProcedureAddress": "0x401000",
        "ModuleAddress": "0x400000", "ThreadId": 8576,
    })
    local_hook["return"] = "0x1234"
    candidate = map_mitre_attack(_attack_results([local_hook]), write_artifact=False)
    local = next(row for row in candidate["mappings"] if row["id"] == "T1056.001")
    assert local["status"] == "candidate"


def test_mitre_screen_capture_artifact_state_machine():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    first = r"C:\Windows\Temp\shot_001.jpg"
    second = r"C:\Windows\Temp\shot_002.jpg"
    calls = [
        _attack_call("NtCreateFile", {"FileName": first, "DesiredAccess": "0x40100080", "CreateDisposition": 5}),
        _attack_call("NtWriteFile", {"HandleName": first, "Buffer": r"\xff\xd8\xff\xe0JFIF", "Length": 4096}, "2026-08-27 18:15:49,100"),
        _attack_call("NtCreateFile", {"FileName": second, "DesiredAccess": "0x40100080", "CreateDisposition": 5}, "2026-08-27 18:15:50,000"),
    ]
    # Preserve the raw magic field shape emitted by CAPEMON.
    calls[1]["arguments"][1]["raw_value"] = "ffd8ffe000104a464946"
    report = map_mitre_attack(_attack_results(calls), write_artifact=False)
    mapped = next(row for row in report["mappings"] if row["id"] == "T1113")
    assert (mapped["status"], mapped["confidence"]) == ("candidate", "medium"), mapped
    state = next(row for row in mapped["state_machines"] if row["rule_id"] == "sm.collection.screen_capture_artifacts")
    assert state["complete"] is False and state["state_trace"].count("image_artifact") == 2
    assert "screen capture source" in state["missing_steps"] and state["scoreable"] is False

    one = map_mitre_attack(_attack_results(calls[:2]), write_artifact=False)
    incomplete = next(row for row in one["mappings"] if row["id"] == "T1113")
    assert incomplete["status"] == "candidate"


def test_mitre_smtp_attempted_is_not_completed_c2():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    from CAPEsolo.capelib.threat_assessment import assess_threat

    failed = [
        _attack_call("connect", {"socket": 1228, "ip": "192.168.56.2", "port": 587}, status=False),
        _attack_call("send", {"socket": 1228, "buffer": "QUIT\r\n"}, "2026-08-27 18:15:50,000", status=False),
    ]
    attempted_report = map_mitre_attack(_attack_results(failed), write_artifact=False)
    attempted = next(row for row in attempted_report["mappings"] if row["id"] == "T1071.003")
    assert attempted["status"] == "attempted", attempted
    assert attempted_report["summary"]["attempted"] == 1
    state = attempted["state_machines"][0]
    assert state["outcome"] == "attempted" and state["scoreable"] is False
    attempted_results = _attack_results(failed)
    attempted_results["mitre_attack"] = attempted_report
    score = assess_threat(attempted_results)
    assert next(row for row in score["components"] if row["category"] == "validated_state_machines")["points"] == 0

    success = [
        _attack_call("connect", {"socket": 42, "ip": "192.0.2.25", "port": 587}),
        _attack_call("send", {"socket": 42, "buffer": "EHLO host.example\r\n"}, "2026-08-27 18:15:50,000"),
    ]
    completed_report = map_mitre_attack(_attack_results(success), write_artifact=False)
    completed = next(row for row in completed_report["mappings"] if row["id"] == "T1071.003")
    assert completed["status"] == "observed"


def test_mitre_system_location_requires_independent_signals():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack

    locale = _attack_call("GetUserDefaultLCID", {"SystemDefaultLangID": "0x00000409", "LanguageName": "English (United States)"})
    one = map_mitre_attack(_attack_results([locale]), write_artifact=False)
    mapped = next(row for row in one["mappings"] if row["id"] == "T1614")
    assert (mapped["status"], mapped["confidence"]) == ("candidate", "low")

    timezone = _attack_call("GetDynamicTimeZoneInformation", {"TimeZoneKeyName": "Pacific Standard Time"}, "2026-08-27 18:15:50,000")
    two = map_mitre_attack(_attack_results([locale, timezone]), write_artifact=False)
    mapped = next(row for row in two["mappings"] if row["id"] == "T1614")
    assert (mapped["status"], mapped["confidence"]) == ("observed", "medium")


def test_shareable_report_redacts_clipboard_but_preserves_raw_input():
    from copy import deepcopy
    from CAPEsolo.capelib.report_redaction import redact_report_in_place

    secret = "frida_pcap_agent_token=test-secret-value"
    call = _attack_call("GetClipboardData", {"Format": 13, "Data": secret})
    call["arguments"][1]["raw_value"] = secret.encode().hex()
    results = _attack_results([call])
    canonical = deepcopy(results)
    redact_report_in_place(results)
    argument = results["behavior"]["processes"][0]["calls"][0]["arguments"][1]
    assert argument["value"] == "<redacted clipboard data>" and argument["raw_value"] == "<redacted>"
    assert results["report_redaction"]["clipboard_fields_redacted"] == 1
    assert results["report_redaction"]["captured_bytes_redacted"] == len(secret)
    assert canonical["behavior"]["processes"][0]["calls"][0]["arguments"][1]["value"] == secret
    assert "test-secret-value" not in json.dumps(results)


def test_attempted_status_and_redaction_render_in_html():
    if importlib.util.find_spec("markupsafe") is None or importlib.util.find_spec("jinja2") is None:
        return
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    from CAPEsolo.capelib.threat_assessment import assess_threat
    from CAPEsolo.classes.html_report import ReportHTML

    secret = "frida_pcap_agent_token=must-not-appear"
    calls = [
        _attack_call("GetClipboardData", {"Format": 13, "Data": secret}),
        _attack_call("connect", {"socket": 7, "ip": "192.168.56.2", "port": 587}, "2026-08-27 18:15:50,000", status=False),
        _attack_call("send", {"socket": 7, "buffer": "QUIT\r\n"}, "2026-08-27 18:15:51,000", status=False),
    ]
    calls[0]["arguments"][1]["raw_value"] = secret.encode().hex()
    results = _attack_results(calls)
    results["mitre_attack"] = map_mitre_attack(results, write_artifact=False)
    results["threat_assessment"] = assess_threat(results)
    with tempfile.TemporaryDirectory() as td:
        complete, error = ReportHTML().run(Path(td), ROOT, results)
        assert complete is True and error is None, error
        html = (Path(td) / "report.html").read_text(encoding="utf-8")
        assert "Attempted" in html and "Mail Protocols" in html
        assert "Sensitive evidence protected" in html
        assert "must-not-appear" not in html


def test_threat_assessment_thresholds_caps_and_quality():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    from CAPEsolo.capelib.threat_assessment import assess_threat

    benign_results = _attack_results([_attack_call("LdrLoadDll", {"Module": "kernel32.dll"})])
    benign_results["mitre_attack"] = map_mitre_attack(benign_results, write_artifact=False)
    benign = assess_threat(benign_results)
    assert benign["score"] < 20 and benign["verdict"] == "benign", benign
    assert benign["provisional"] is True

    suspicious_results = _attack_results([_attack_call("RegSetValueExW", {
        "FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        "Buffer": r"C:\Users\u\AppData\Local\updater.exe",
    })])
    suspicious_results["mitre_attack"] = map_mitre_attack(suspicious_results, write_artifact=False)
    suspicious = assess_threat(suspicious_results)
    assert 20 <= suspicious["score"] < 60 and suspicious["verdict"] == "suspicious", suspicious

    malicious_calls = [
        _attack_call("CopyFileW", {"ExistingFileName": r"C:\Lab\sample.exe", "NewFileName": r"C:\Users\u\AppData\Local\googleupdaterr.exe"}),
        _attack_call("RegSetValueExW", {"FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\GoogleUpdate", "Buffer": r"C:\Users\u\AppData\Local\googleupdaterr.exe"}, "2026-08-27 18:15:49,100"),
        _attack_call("DeleteFileW", {"FileName": r"C:\Lab\sample.exe"}, "2026-08-27 18:15:49,200"),
        _attack_call("CreateToolhelp32Snapshot", {"Flags": "0x2"}, "2026-08-27 18:15:49,300"),
        _attack_call("IsDebuggerPresent", {}, "2026-08-27 18:15:49,400", status=False),
        _attack_call("RegQueryValueExW", {"FullName": r"HKCU\Software\Vendor\A", "ValueName": "A"}, "2026-08-27 18:15:49,500"),
        _attack_call("NtQueryValueKey", {"FullName": r"HKLM\Software\Vendor\B", "ValueName": "B"}, "2026-08-27 18:15:49,600"),
    ]
    malicious_results = _attack_results(malicious_calls, signatures=[{
        "name": "Unpacker", "description": "Executable extraction", "confidence": 100,
        "severity": 1, "ttps": ["T1027", "T1140"],
    }])
    malicious_results["payloads"] = [{"artifact": {"sha256": "a" * 64, "size": 4096, "cape_type": "Unpacked PE Image", "pid": 10}}]
    malicious_results["mitre_attack"] = map_mitre_attack(malicious_results, write_artifact=False)
    malicious = assess_threat(malicious_results)
    # Payload metadata without provenance no longer pushes this fixture over 60.
    assert 20 <= malicious["score"] < 60 and malicious["verdict"] == "suspicious", malicious
    assert not any(x.get("signal") in {"T1140", "T1027.002", "Unpacker"} for x in malicious["top_reasons"])
    assert sum(component["points"] for component in malicious["components"]) == malicious["score"]

    repeated = _attack_results([_attack_call("IsDebuggerPresent", {}, status=False) for _ in range(100)])
    repeated["mitre_attack"] = map_mitre_attack(repeated, write_artifact=False)
    repeated_score = assess_threat(repeated)
    assert repeated_score["score"] < 20, repeated_score
    assert next(row for row in repeated_score["components"] if row["category"] == "mitre_attack")["points"] <= 5

    reputation = _attack_results(signatures=[{
        "name": "antivirus_multiengine", "description": "Identified by 25 AntiVirus engines as malicious",
        "severity": 60, "confidence": 100, "ttps": [],
    }, {
        "name": "persistence_autorun", "description": "Installs itself for autorun", "severity": 3,
    }])
    reputation["mitre_attack"] = map_mitre_attack(reputation, write_artifact=False)
    reputation_score = assess_threat(reputation)
    assert reputation_score["score"] >= 60 and reputation_score["verdict"] == "malicious", reputation_score
    assert next(row for row in reputation_score["components"] if row["category"] == "external_reputation")["points"] == 60

    absent = _attack_results(); absent["behavior"]["processes"] = []
    absent["mitre_attack"] = map_mitre_attack(absent, write_artifact=False)
    inconclusive = assess_threat(absent)
    assert inconclusive["score"] == 0 and inconclusive["verdict"] == "inconclusive", inconclusive


def test_threat_assessment_html_and_pipeline_source():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    from CAPEsolo.capelib.threat_assessment import assess_threat

    results = _attack_results([_attack_call("IsDebuggerPresent", {}, status=False)])
    results["mitre_attack"] = map_mitre_attack(results, write_artifact=False)
    results["threat_assessment"] = assess_threat(results)
    template = (ROOT / "capelib" / "html" / "sections" / "threat_assessment.html").read_text(encoding="utf-8")
    report_template = (ROOT / "capelib" / "html" / "report.html").read_text(encoding="utf-8")
    pipeline = (ROOT / "classes" / "json_report.py").read_text(encoding="utf-8")
    assert "Evidence risk score" in template and "Benign 0–19" in template
    assert 'sections/threat_assessment.html' in report_template
    assert 'results["threat_assessment"] = assess_threat(results)' in pipeline
    if importlib.util.find_spec("jinja2") is None:
        return
    from CAPEsolo.classes.html_report import ReportHTML
    with tempfile.TemporaryDirectory() as td:
        complete, error = ReportHTML().run(Path(td), ROOT, results)
        assert complete is True and error is None, error
        html = (Path(td) / "report.html").read_text(encoding="utf-8")
        assert "Threat assessment" in html and "Evidence risk score" in html and "T1622" in html


def test_mitre_insufficient_evidence_is_not_sensor_unsupported():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    report = map_mitre_attack(
        _attack_results([_attack_call("GetSystemMetrics", {"Index": 0})]),
        write_artifact=False,
    )
    rejected = next(row for row in report["rejected_candidates"] if row["id"] == "T1497.001")
    assert rejected["status"] == "insufficient_evidence"
    assert report["summary"]["insufficient_evidence"] >= 1
    assert report["semantics"]["unsupported_by_sensor"] != report["semantics"]["insufficient_evidence"]
    assert report["coverage"]["detectors"]["domains"]["mobile-attack"]["unsupported_by_sensor"] == 124


def test_mitre_canonical_clean_view_excludes_framework_only_calls():
    from CAPEsolo.capelib.mitre_attack import AttackMapper
    with tempfile.TemporaryDirectory() as td:
        analysis = Path(td)
        clean = _call(10, 2, "2026-08-27 18:15:50,000", "RegSetValueExW", {
            "FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Good",
            "Buffer": r"C:\Lab\sample.exe",
        })
        (analysis / "behavior.filtered.jsonl").write_text(json.dumps(clean) + "\n", encoding="utf-8")
        raw = [_attack_call("GetSystemInfo", {"ProcessorArchitecture": 9}), clean["call"]]
        report = AttackMapper(_attack_results(raw), analysis).build()
        ids = {row["id"] for row in report["mappings"]}
        assert "T1547.001" in ids and "T1082" not in ids, report
        assert report["coverage"]["behavior"]["source"] == "behavior.filtered.jsonl"


def test_mitre_timestamped_chain_discovery():
    from CAPEsolo.capelib.mitre_attack import AttackMapper
    with tempfile.TemporaryDirectory() as td:
        analysis = Path(td)
        chain_report = {"behavior_chains": {"chains": [{
            "chain_type": "persistence_run_key", "confidence": "high", "mitre_candidate": "T1547.001",
            "interpretation": "Validated persistence chain", "steps": [{"evidence": {"pid": 10, "api": "RegSetValueExW"}}],
        }]}}
        (analysis / "frida_p3_report(20260828-055858).json").write_text(json.dumps(chain_report), encoding="utf-8")
        report = AttackMapper(_attack_results(), analysis).build()
        # CAR review: discovering an old chain does not establish current clean-call proof.
        assert "T1547.001" not in {row["id"] for row in report["mappings"]}
        assert report["coverage"]["behavior_chains"]["chains"] == 1


def test_mitre_report_time_preparation_builds_clean_view_and_chains():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    with tempfile.TemporaryDirectory() as td:
        analysis = Path(td)
        calls = [
            _attack_call("CopyFileW", {"ExistingFileName": r"C:\Lab\x.exe", "NewFileName": r"C:\Users\u\AppData\Local\x.exe"}),
            _attack_call("RegSetValueExW", {"FullName": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X", "Buffer": r"C:\Users\u\AppData\Local\x.exe"}, "2026-08-27 18:15:50,100"),
        ]
        for index, call in enumerate(calls, 1): call["id"] = index
        results = _attack_results(calls)
        results["behavior"]["processes"][0]["threads"] = ["1"]
        (analysis / "frida_p3_runtime.json").write_text(json.dumps({"run_id":"owned-fixture", "target_pid":10,
            "lineage":{"10":{"role":"root", "exe":r"C:\Lab\sample.exe"}}}), encoding="utf-8")
        report = map_mitre_attack(results, analysis, write_artifact=False)
        assert (analysis / "behavior.filtered.jsonl").is_file()
        assert (analysis / "frida_behavior_chains.json").is_file()
        assert report["coverage"]["behavior_chains"]["chains"] == 1
        persistence = next(row for row in report["mappings"] if row["id"] == "T1547.001")
        assert {"behavior_api", "behavior_chain"} <= set(persistence["sources"])
        assert "sigma_rule" in persistence["sources"]


def test_mitre_catalog_coverage_is_not_detection_coverage():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    report = map_mitre_attack(_attack_results(), write_artifact=False)
    coverage = report["coverage"]["detectors"]
    assert coverage["domains"]["enterprise-attack"]["catalog_techniques"] == 697
    assert coverage["domains"]["mobile-attack"] == {
        "catalog_techniques": 124, "supported": 0, "partially_supported": 0,
        "unsupported_by_sensor": 124, "not_applicable_to_platform": 0,
        "sensor_domain_enabled": False,
    }
    assert coverage["domains"]["ics-attack"]["unsupported_by_sensor"] == 97
    enterprise = coverage["domains"]["enterprise-attack"]
    assert enterprise["supported"] == 13
    assert len(enterprise["native_partial_ids"]) == 39
    assert enterprise["partially_supported"] > len(enterprise["native_partial_ids"])
    assert enterprise["sigma_partial_ids"]
    assert {"T1056.001", "T1113", "T1614"} <= set(enterprise["supported_ids"])
    assert "T1036" in enterprise["partial_ids"]
    assert "must not be interpreted as absent" in coverage["meaning"]


def test_mitre_double_extension_evidence_binding():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    report = map_mitre_attack(_attack_results([_attack_call("LdrLoadDll", {"Module": "kernel32.dll"})], process_name="invoice.pdf.exe"), write_artifact=False)
    mapped = next(row for row in report["mappings"] if row["id"] == "T1036.007")
    assert mapped["evidence"][0]["source"] == "target_metadata"
    assert "api" not in mapped["evidence"][0]


def test_mitre_html_catalog_state_and_unique_dom_ids():
    if importlib.util.find_spec("jinja2") is None: return
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    from CAPEsolo.classes.html_report import ReportHTML
    import re
    with tempfile.TemporaryDirectory() as td:
        analysis = Path(td)
        call = _attack_call("RegSetValueExW", {"FullName": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X", "Buffer": r"C:\Lab\x.exe"})
        results = _attack_results([call])
        results["behavior"]["processes"].append({"process_id": 20, "process_name": "child.exe", "module_path": r"C:\Lab\child.exe", "calls": [dict(call)]})
        results["mitre_attack"] = map_mitre_attack(results, write_artifact=False)
        complete, error = ReportHTML().run(analysis, ROOT, results)
        assert complete is True and error is None
        html = (analysis / "report.html").read_text(encoding="utf-8")
        assert "Catalog and executable detector coverage" in html and "Official ATT&amp;CK catalog graph" in html
        assert "SigmaHQ rule evaluation" in html and "Sigma-only match is always" in html
        assert "Pinned source rule" in html and "False-positive context" in html
        assert "Authors:" in html
        assert "Why rules were not evaluated" in html and "Missing normalized fields" in html
        assert "All active analytics" in html and "Insufficient evidence" in html
        assert "DET0365" in html and "AN1032" in html and "DC0063" in html
        ids = re.findall(r'\bid="([^"]+)"', html)
        duplicates = {value for value in ids if ids.count(value) > 1}
        assert not duplicates, sorted(duplicates)[:20]


def test_mitre_report_pipeline_source():
    source = (ROOT / "classes" / "json_report.py").read_text(encoding="utf-8")
    html_source = (ROOT / "classes" / "html_report.py").read_text(encoding="utf-8")
    assert 'results["mitre_attack"] = map_mitre_attack' in source
    assert 'path / "mitre_attack.json"' in (ROOT / "capelib" / "mitre_attack.py").read_text(encoding="utf-8")
    assert 'filepath = analysis_path / "report.html"' in html_source


def test_network_quality_html_and_agent_schema_source():
    template = (ROOT / "capelib" / "html" / "sections" / "network.html").read_text(encoding="utf-8")
    json_report = (ROOT / "classes" / "json_report.py").read_text(encoding="utf-8")
    agent = (PROJECT_ROOT / "extras" / "ubuntu_pcap_agent" / "capesolo_pcap_agent.py").read_text(encoding="utf-8")
    assert "Evidence quality" in template
    assert "absence_interpretation" in template
    assert "clock_slew_compensated" in template and "clock_segmented" in template
    assert "InterpretNetworkAbsence" in json_report
    assert 'SCHEMA = "capesolo-pcap-agent/1.3"' in agent
    assert 'payload.setdefault("server_monotonic_ns", time.monotonic_ns())' in agent


def _write_sigma_test_pack(path: Path) -> None:
    pack = {
        "schema": "capesolo-sigma-pack/1.0",
        "source": {"repository": "test", "commit": "test", "license": "test"},
        "summary": {"compiled_rules": 3},
        "rules": [
            {
                "id": "positive-run-key", "title": "Run key", "status": "test", "level": "high",
                "attack_ids": ["T1547.001"], "falsepositives": [], "source_path": "test/run.yml",
                "source_sha256": "0" * 64, "logsource": {"product": "windows", "category": "registry_set"},
                "fields": ["TargetObject"],
                "condition": {"op": "field", "field": "TargetObject", "value": {
                    "kind": "regex", "pattern": r"^.*\\CurrentVersion\\Run\\.*$", "ignore_case": True,
                }},
            },
            {
                "id": "negative-only", "title": "Negative only must not match", "status": "test", "level": "high",
                "attack_ids": ["T1059.003"], "falsepositives": [], "source_path": "test/negative.yml",
                "source_sha256": "1" * 64, "logsource": {"product": "windows", "category": "process_creation"},
                "fields": ["Image"],
                "condition": {"op": "not", "arg": {"op": "field", "field": "Image", "value": {
                    "kind": "regex", "pattern": r"^.*\\benign\\.exe$", "ignore_case": True,
                }}},
            },
            {
                "id": "network-only", "title": "Network sensor gate", "status": "test", "level": "high",
                "attack_ids": ["T1071.001"], "falsepositives": [], "source_path": "test/network.yml",
                "source_sha256": "2" * 64, "logsource": {"product": "windows", "category": "network_connection"},
                "fields": ["DestinationPort"],
                "condition": {"op": "field", "field": "DestinationPort", "value": {"kind": "number", "value": 80}},
            },
        ],
    }
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as handle:
            handle.write(json.dumps(pack, separators=(",", ":")).encode("utf-8"))


def test_sigma_pack_integrity_and_runtime_independence():
    pack_path = ROOT / "data" / "sigma" / "sigmahq_windows_p3.json.gz"
    with gzip.open(pack_path, "rt", encoding="utf-8") as handle:
        pack = json.load(handle)
    assert pack["schema"] == "capesolo-sigma-pack/1.0"
    assert pack["source"]["repository"] == "https://github.com/SigmaHQ/sigma"
    assert pack["source"]["commit"] == "272daf82bf77fb0bb97f1f0c4d82bc61154772e1"
    assert pack["source"]["license"] == "DRL-1.1"
    assert pack["source"]["builder"] == "pySigma" and pack["source"]["builder_version"] == "1.5.0"
    assert pack["summary"]["source_files"] == 2410
    assert pack["summary"]["compiled_rules"] == 1845
    assert len(pack["rules"]) == len({row["id"] for row in pack["rules"]}) == 1845
    assert all(len(row["source_sha256"]) == 64 for row in pack["rules"])
    assert all(row.get("authors") for row in pack["rules"])
    assert (ROOT / "data" / "sigma" / "SIGMAHQ_LICENSE").is_file()
    runtime_source = (ROOT / "capelib" / "sigma_runtime.py").read_text(encoding="utf-8")
    assert "from sigma" not in runtime_source and "import yaml" not in runtime_source


def test_sigma_ir_positive_near_miss_negative_only_and_sensor_gate():
    from CAPEsolo.capelib.sigma_runtime import evaluate_sigma
    with tempfile.TemporaryDirectory() as td:
        pack_path = Path(td) / "test-pack.json.gz"
        _write_sigma_test_pack(pack_path)
        positive = _attack_results([_attack_call("RegSetValueExW", {
            "FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            "Buffer": r"C:\Users\u\AppData\Local\updater.exe",
        })])
        matched = evaluate_sigma(positive, pack_path=pack_path)
        assert [row["rule_id"] for row in matched["matches"]] == ["positive-run-key"], matched["matches"]
        assert matched["attack_candidates"][0]["technique_id"] == "T1547.001"
        assert matched["coverage"]["unsupported_by_sensor"] == 1

        near_miss = _attack_results([_attack_call("RegSetValueExW", {
            "FullName": r"HKEY_CURRENT_USER\Software\Vendor\Preferences\Updater",
            "Buffer": "1",
        })])
        not_matched = evaluate_sigma(near_miss, pack_path=pack_path)
        assert not not_matched["matches"], not_matched["matches"]


def test_sigma_official_rule_native_corroboration():
    from CAPEsolo.capelib.mitre_attack import map_mitre_attack
    results = _attack_results([_attack_call("RegSetValueExW", {
        "FullName": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        "Buffer": r"C:\Users\u\AppData\Local\updater.exe",
    })])
    attack = map_mitre_attack(results, write_artifact=False)
    mapping = next(row for row in attack["mappings"] if row["id"] == "T1547.001")
    assert mapping["status"] == "observed"
    assert {"behavior_api", "sigma_rule"} <= set(mapping["sources"])
    assert attack["summary"]["sigma_rule_matches"] >= 1
    assert attack["sigma"]["matches"][0]["authors"]


def test_sigma_only_candidate_does_not_change_threat_score():
    from CAPEsolo.capelib.threat_assessment import assess_threat
    base = _attack_results()
    base["mitre_attack"] = {
        "mappings": [{
            "id": "T1059.001", "name": "PowerShell", "tactics": ["execution"],
            "status": "candidate", "confidence": "medium", "sources": ["sigma_rule"],
            "rule_ids": ["sigma.synthetic"],
        }],
        "state_machine_evaluations": [],
        "coverage": {"behavior": {"available": True, "clean_calls": 1, "source": "test"}, "signatures": {}},
        "coverage_warnings": [],
    }
    scored = assess_threat(base)
    attack_component = next(row for row in scored["components"] if row["category"] == "mitre_attack")
    assert scored["score"] == 0 and attack_component["points"] == 0 and not attack_component["signals"]


def test_sigma_replay_tool_policy_source():
    source = (HERE / "p32316_replay_sigma_reports.py").read_text(encoding="utf-8")
    assert "no_sigma_only_promotion" in source
    assert "sigma_only_score_neutral" in source
    assert "AttackMapper(results, report_path.parent).build()" in source


def main() -> int:
    tests = [
        test_lifecycle_policy,
        test_exact_root_profile_resolution,
        test_compaction_and_chains,
        test_behavior_run_thread_scoping,
        test_behavior_pid_repair,
        test_behavior_pid_validation_without_duplicate_report,
        test_attach_outcome_accounting,
        test_temporal_attach_provenance,
        test_artifact_content_evidence,
        test_attach_defaults_present,
        test_exception_diagnostics_opt_in_source,
        test_early_agent_deferred_hooks_source,
        test_child_fast_path_source,
        test_attach_self_read_burst_filter,
        test_unhook_restore_burst_annotation,
        test_protected_range_deduplication,
        test_werfault_attribution_without_child_attach,
        test_lifecycle_log_wording_source,
        test_shared_product_version_source,
        test_registry_telemetry_continuity,
        test_framework_only_rate_cap,
        test_injector_prewarm_source,
        test_helper_aware_child_attach_source,
        test_review_export_profile,
        test_upstream_report_integration_source,
        test_auxiliary_config_and_monitor_option_filter_source,
        test_process_instrumentation_summary,
        test_sysmon_network_event_parsing,
        test_network_pid_correlation,
        test_network_clock_compensation,
        test_pcap_client_clock_sample,
        test_p32313_clock_samples_are_continuous_slew,
        test_clock_step_is_segmented_not_globally_rejected,
        test_clock_dual_monotonic_sample_metadata,
        test_pcap_periodic_clock_sampler_request,
        test_clock_drift_interpolation,
        test_clock_discontinuity_rejects_pid_and_tuple_fallback,
        test_raw_event_accounting_after_pid_correlation,
        test_http_plaintext_enriches_without_double_counting,
        test_dns_request_response_occurrence_accounting,
        test_tls_preflight_preserves_key_material_count,
        test_local_discovery_and_packet_loss_metadata,
        test_microsoft_telemetry_subdomain_is_environmental,
        test_sysmon_final_drain_shutdown_order_source,
        test_http_response_separation_and_environment_gate,
        test_optional_package_config_missing_is_quiet_source,
        test_runtime_validator_network_summary,
        test_environmental_http_signatures_are_gated,
        test_network_status_axes,
        test_finalizer_smoke,
        test_mitre_blackenergy21_pe_metadata_masquerading_replay,
        test_mitre_masquerading_metadata_false_positive_gates,
        test_mitre_dyre_masquerading_regression,
        test_mitre_evidence_first_dyre_mapping,
        test_mitre_confirmed_injection_requires_write_and_execute,
        test_mitre_framework_injection_is_excluded,
        test_mitre_network_lineage_and_quality_gate,
        test_mitre_unpacker_requires_extracted_artifact_for_t1140,
        test_mitre_legacy_id_normalization,
        test_mitre_artifact_and_html_rendering,
        test_mitre_full_offline_catalog_and_official_detection_metadata,
        test_mitre_state_machine_time_and_target_gates,
        test_mitre_lsass_state_machine_positive_and_negative,
        test_mitre_environment_check_requires_compound_evidence,
        test_mitre_registry_query_and_debugger_state_machines,
        test_mitre_keylogging_state_machine_uses_structured_global_hook,
        test_mitre_screen_capture_artifact_state_machine,
        test_mitre_smtp_attempted_is_not_completed_c2,
        test_mitre_system_location_requires_independent_signals,
        test_shareable_report_redacts_clipboard_but_preserves_raw_input,
        test_attempted_status_and_redaction_render_in_html,
        test_threat_assessment_thresholds_caps_and_quality,
        test_threat_assessment_html_and_pipeline_source,
        test_mitre_insufficient_evidence_is_not_sensor_unsupported,
        test_mitre_canonical_clean_view_excludes_framework_only_calls,
        test_mitre_timestamped_chain_discovery,
        test_mitre_report_time_preparation_builds_clean_view_and_chains,
        test_mitre_catalog_coverage_is_not_detection_coverage,
        test_mitre_double_extension_evidence_binding,
        test_mitre_html_catalog_state_and_unique_dom_ids,
        test_mitre_report_pipeline_source,
        test_network_quality_html_and_agent_schema_source,
        test_sigma_pack_integrity_and_runtime_independence,
        test_sigma_ir_positive_near_miss_negative_only_and_sensor_gate,
        test_sigma_official_rule_native_corroboration,
        test_sigma_only_candidate_does_not_change_threat_score,
        test_sigma_replay_tool_policy_source,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS all={len(tests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
