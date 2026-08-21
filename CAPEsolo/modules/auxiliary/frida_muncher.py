import configparser
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path

import frida
import psutil

from lib.common.abstracts import Auxiliary

try:
    from lib.common.sysmon_bridge import SysmonRealtimeBridge
except Exception:
    SysmonRealtimeBridge = None

try:
    from lib.common.frida_profile_resolver import resolve_profile
except Exception:
    resolve_profile = None

log = logging.getLogger(__name__)


class FridaMuncher(Auxiliary):
    """
    CAPEsolo + Frida P3.2 reliability/provenance controller, built on the validated P2/P2.1 Hybrid core.

    P0 generalization changes:
      1. Safe gate default: gate_mode=none. No sample bytes are restored unless
         a profile or explicit CAPE option enables a patched-entry gate.
      2. No hard-coded rootkit.exe target. By default the controller discovers
         the new analysis process whose executable is located under CAPE's
         current analysis directory (the ``curdir`` option).
      3. Sample-specific behavior is moved to JSON profiles under
         data/frida_profiles/. The BlackEnergy2.1 profile contains the old
         rootkit.exe + EB FE gate settings; the generic profile does not.

    P1 generalization changes:
      1. Multi-process/child tracking: keep one Frida session per PID and follow
         descendants of the initial CAPE target.
      2. Runtime caller policy: JS may treat anonymous executable/private RX/RWX
         ranges as malware code, not only Process.mainModule.
      3. Anti-analysis hooks support observe/bypass modes. Generic defaults to
         observe; profiles may explicitly request bypass.
      4. x86/x64 diagnostics are architecture-aware in the JS agent.

    P2/P2.1 generalization changes:
      1. Event-driven enrollment of pre-existing processes. P2.1 prefers Sysmon
         Event ID 8 (CreateRemoteThread) as the system-wide high-confidence sensor.
      2. Frida injection hooks are fallback/enrichment only. A single Frida
         execution-transfer hint no longer enrolls a target by itself; multiple
         distinct indicators are correlated in a short window.
      3. Sysmon Event IDs 1/5 maintain process identity context and Event ID 25
         enriches tampering telemetry for processes already associated with the run.
      4. Benign crash-reporting descendants can be excluded from automatic child
         attachment without hiding explicit injection targets.
      5. Instrumentation provenance is emitted by the JS tracker so CAPE/Frida
         artifacts can be filtered later without deleting original evidence.

    Configuration precedence:
        explicit CAPE options > selected profile > safe built-in defaults

    P3/P3.1/P3.2 profile selection:
        frida_profile=auto      # conservative resolver; generic fallback
        frida_profile=generic   # explicit safe generic mode
        frida_profile=blackenergy21  # explicit compatibility profile
    """

    def __init__(self, options=None, config=None):
        super().__init__(options, config)

        # One analysis can now have multiple Frida sessions.  The initial
        # CAPE target is role=root; every descendant discovered later is role=child.
        self.sessions = {}
        self.scripts_by_pid = {}
        self.process_meta = {}
        self.process_events = {}
        self.lineage = {}
        self.pending_identities = set()
        self.session_lock = threading.RLock()

        self.target_pid = None
        self.worker = None
        self.child_threads = []
        self.enrollment_threads = []
        self.child_watcher = None
        self.stop_event = threading.Event()
        # P2.1 optimization: discover descendants immediately, but prioritize
        # root instrumentation so child Frida attaches cannot delay the root.
        self.root_ready = threading.Event()

        # P2 injection-correlation state.  Keys are (source_pid, target_pid,
        # target_create_time).  Evidence is deliberately kept in Python so a
        # single noisy API call does not automatically enroll an unrelated process.
        self.enrollment_evidence = {}

        # P2.1 hybrid Sysmon state. The existing CAPEsolo Sysmon auxiliary remains
        # responsible for normal capture/export; this bridge only subscribes to
        # the same Operational channel in real time for enrollment decisions.
        self.sysmon_bridge = None
        self.sysmon_bridge_active = False
        self.sysmon_ever_active = False
        self.sysmon_events_seen = 0
        self.sysmon_event_counts = {}

        self.started_wall = None
        self.baseline_targets = {}
        self.failed_identities = set()

        # Hotfix 1: remember descendants that were intentionally excluded so the
        # 100 ms watcher loop does not re-log/re-resolve the same benign child
        # for the rest of the analysis. The identity includes create_time to stay
        # safe across PID reuse.
        self.excluded_descendant_identities = {}

        # P3 production evidence ledger. This is deliberately bounded and
        # stores only structured control-plane evidence; high-volume API calls
        # remain in CAPEMON/BSON instead of being duplicated here.
        self.p3_evidence = []
        self.p3_evidence_seq = 0
        self.p3_evidence_dropped = 0
        self.p3_hook_counts = {}
        self.p3_evidence_lock = threading.RLock()
        self.p3_max_evidence = 5000
        self.p3_runtime_report_enabled = True
        self.p3_runtime_report_path = None
        self.profile_selection = {}

        # P3.2 logical attempt identity. CAPEsolo may append several attempts to
        # one analysis.log; every P3.2 controller instance carries a run_id so
        # finalizers can scope evidence to the current attempt without mutating
        # CAPEsolo raw storage.
        self.run_id = None
        self.stopped_wall = None
        self.p3_run_dir = None

        # ------------------------------------------------------------------
        # Profile + safe configuration
        # ------------------------------------------------------------------
        self.analysis_dir = str(
            self.options.get("curdir", "")
        ).strip()
        if self.analysis_dir:
            self.analysis_dir = os.path.normcase(
                os.path.abspath(self.analysis_dir)
            )

        self.profile_request = str(
            self.options.get("frida_profile", "auto")
        ).strip() or "auto"

        if self.profile_request.lower() in {"auto", ""} and resolve_profile is not None:
            try:
                self.profile_selection = resolve_profile(
                    profile_dir=Path.cwd() / "data" / "frida_profiles",
                    analysis_dir=self.analysis_dir,
                    requested=self.profile_request,
                    target_hint=str(self.options.get("frida_target", "") or ""),
                    fallback="generic",
                )
            except Exception:
                log.exception("[FridaMuncher] P3 auto profile resolution failed; using generic")
                self.profile_selection = {
                    "requested": self.profile_request,
                    "selected": "generic",
                    "source": "resolver_error",
                    "score": 0,
                    "candidate": None,
                    "reasons": ["resolver_exception"],
                }
        elif self.profile_request.lower() in {"auto", ""}:
            self.profile_selection = {
                "requested": self.profile_request,
                "selected": "generic",
                "source": "resolver_unavailable",
                "score": 0,
                "candidate": None,
                "reasons": ["resolver_unavailable"],
            }
        else:
            self.profile_selection = {
                "requested": self.profile_request,
                "selected": self.profile_request,
                "source": "explicit",
                "score": None,
                "candidate": None,
                "reasons": ["explicit_profile"],
            }

        self.profile_name = str(
            self.profile_selection.get("selected") or "generic"
        ).strip() or "generic"
        self.profile = self._load_profile(self.profile_name)

        target_cfg = dict(self.profile.get("target", {}) or {})
        gate_cfg = dict(self.profile.get("gate", {}) or {})
        features_cfg = dict(self.profile.get("features", {}) or {})

        # Optional explicit target name. Empty means: select the new process
        # launched from CAPE's curdir, instead of matching a hard-coded name.
        self.target_name = str(
            self.options.get(
                "frida_target",
                target_cfg.get("name", ""),
            )
        ).strip()

        # Exact target path is only derived when a target name is specified.
        # Generic mode instead accepts any new executable located under curdir.
        if self.analysis_dir and self.target_name:
            self.expected_path = os.path.normcase(
                os.path.abspath(
                    os.path.join(
                        self.analysis_dir,
                        self.target_name,
                    )
                )
            )
        else:
            self.expected_path = None

        self.gate_mode = str(
            self.options.get(
                "frida_gate_mode",
                gate_cfg.get("mode", "none"),
            )
        ).strip().lower() or "none"

        if self.gate_mode not in {"none", "patched_entry"}:
            log.warning(
                "[FridaMuncher] Unknown gate mode %r; forcing safe mode 'none'.",
                self.gate_mode,
            )
            self.gate_mode = "none"

        self.restore_hex = str(
            self.options.get(
                "frida_restore_hex",
                gate_cfg.get("restore_hex", ""),
            )
        ).replace(" ", "").strip().lower()

        self.expected_gate_hex = str(
            self.options.get(
                "frida_expected_gate_hex",
                gate_cfg.get("expected_hex", ""),
            )
        ).replace(" ", "").strip().lower()

        try:
            self.gate_delta = int(
                str(
                    self.options.get(
                        "frida_gate_delta",
                        gate_cfg.get("delta", 0),
                    )
                ),
                0,
            )
        except Exception:
            self.gate_delta = 0

        self.enable_legacy_int2a = self._as_bool(
            self.options.get(
                "frida_enable_legacy_int2a",
                features_cfg.get("legacy_int2a", False),
            )
        )

        self.follow_children = self._as_bool(
            self.options.get(
                "frida_follow_children",
                features_cfg.get("follow_children", True),
            )
        )

        self.private_exec_callers = self._as_bool(
            self.options.get(
                "frida_private_exec_callers",
                features_cfg.get("private_exec_callers", True),
            )
        )

        self.anti_analysis_mode = str(
            self.options.get(
                "frida_anti_analysis_mode",
                features_cfg.get("anti_analysis_mode", "observe"),
            )
        ).strip().lower() or "observe"

        if self.anti_analysis_mode not in {"observe", "bypass"}:
            log.warning(
                "[FridaMuncher] Unknown anti-analysis mode %r; forcing "
                "safe mode 'observe'.",
                self.anti_analysis_mode,
            )
            self.anti_analysis_mode = "observe"

        self.child_anti_analysis_mode = str(
            self.options.get(
                "frida_child_anti_analysis_mode",
                features_cfg.get("child_anti_analysis_mode", "observe"),
            )
        ).strip().lower() or "observe"
        if self.child_anti_analysis_mode not in {"observe", "bypass"}:
            self.child_anti_analysis_mode = "observe"

        # A patched-entry gate is never allowed to run with incomplete bytes.
        if self.gate_mode == "patched_entry":
            if not self.restore_hex or not self.expected_gate_hex:
                log.error(
                    "[FridaMuncher] Profile %s enables patched_entry but does "
                    "not define restore_hex/expected_hex; disabling the gate.",
                    self.profile_name,
                )
                self.gate_mode = "none"

        try:
            self.wait_timeout = float(
                self.options.get(
                    "frida_wait_timeout",
                    self.profile.get("wait_timeout", 120),
                )
            )
        except Exception:
            self.wait_timeout = 120.0

        try:
            self.capemon_detect_timeout = float(
                self.options.get(
                    "frida_capemon_detect_timeout",
                    self.profile.get("capemon_detect_timeout", 5),
                )
            )
        except Exception:
            self.capemon_detect_timeout = 5.0

        try:
            self.capemon_grace = float(
                self.options.get(
                    "frida_capemon_grace",
                    self.profile.get("capemon_grace", 1.5),
                )
            )
        except Exception:
            self.capemon_grace = 1.5

        try:
            self.capemon_fallback_delay = max(
                0.0,
                float(
                    self.options.get(
                        "frida_capemon_fallback_delay",
                        self.profile.get("capemon_fallback_delay", 2.0),
                    )
                ),
            )
        except Exception:
            self.capemon_fallback_delay = 2.0

        try:
            self.attach_retries = max(
                1,
                int(
                    self.options.get(
                        "frida_attach_retries",
                        self.profile.get("attach_retries", 2),
                    )
                ),
            )
        except Exception:
            self.attach_retries = 2


        try:
            self.child_capemon_detect_timeout = float(
                self.options.get(
                    "frida_child_capemon_detect_timeout",
                    self.profile.get("child_capemon_detect_timeout", 5),
                )
            )
        except Exception:
            self.child_capemon_detect_timeout = 5.0

        try:
            self.child_capemon_grace = float(
                self.options.get(
                    "frida_child_capemon_grace",
                    self.profile.get("child_capemon_grace", 0.5),
                )
            )
        except Exception:
            self.child_capemon_grace = 0.5

        self.child_wait_for_root_ready = self._as_bool(
            self.options.get(
                "frida_child_wait_for_root_ready",
                self.profile.get("child_wait_for_root_ready", True),
            )
        )
        try:
            self.child_root_ready_timeout = max(
                0.0,
                float(
                    self.options.get(
                        "frida_child_root_ready_timeout",
                        self.profile.get("child_root_ready_timeout", 10.0),
                    )
                ),
            )
        except Exception:
            self.child_root_ready_timeout = 10.0

        self.follow_injected_targets = self._as_bool(
            self.options.get(
                "frida_follow_injected_targets",
                features_cfg.get("follow_injected_targets", True),
            )
        )

        self.sysmon_bridge_enabled = self._as_bool(
            self.options.get(
                "frida_sysmon_bridge",
                features_cfg.get("sysmon_bridge", True),
            )
        )
        self.frida_injection_fallback = self._as_bool(
            self.options.get(
                "frida_injection_fallback",
                features_cfg.get("frida_injection_fallback", True),
            )
        )
        self.sysmon_channel = str(
            self.options.get(
                "frida_sysmon_channel",
                self.profile.get(
                    "sysmon_channel",
                    "Microsoft-Windows-Sysmon/Operational",
                ),
            )
        ).strip() or "Microsoft-Windows-Sysmon/Operational"
        self.sysmon_event_ids = self._as_int_tuple(
            self.options.get(
                "frida_sysmon_event_ids",
                self.profile.get("sysmon_event_ids", [1, 5, 8, 25]),
            ),
            default=(1, 5, 8, 25),
        )

        self.sysmon_injected_source_policy = str(
            self.options.get(
                "frida_sysmon_injected_source_policy",
                self.profile.get("sysmon_injected_source_policy", "correlate"),
            )
        ).strip().lower() or "correlate"
        if self.sysmon_injected_source_policy not in {"correlate", "direct", "telemetry"}:
            self.sysmon_injected_source_policy = "correlate"

        try:
            self.sysmon_tampering_init_window = max(
                0.0,
                float(
                    self.options.get(
                        "frida_sysmon_tampering_init_window",
                        self.profile.get("sysmon_tampering_init_window", 3.0),
                    )
                ),
            )
        except Exception:
            self.sysmon_tampering_init_window = 3.0

        # P3.1: for the root process, do not start the CAPEMON detect timeout
        # while CAPE still holds the process suspended.  We first wait for an
        # observable activation signal (CPU time advances) or for CAPEMON to
        # become mapped directly.  Child/injected processes skip this phase.
        try:
            self.capemon_activation_timeout = max(
                0.0,
                float(
                    self.options.get(
                        "frida_capemon_activation_timeout",
                        self.profile.get("capemon_activation_timeout", 20.0),
                    )
                ),
            )
        except Exception:
            self.capemon_activation_timeout = 20.0

        self.child_exclude_names = self._as_name_set(
            self.options.get(
                "frida_child_exclude_names",
                features_cfg.get(
                    "child_exclude_names",
                    ["werfault.exe", "wermgr.exe", "conhost.exe"],
                ),
            )
        )

        # Critical Windows processes are observed as injection targets but are not
        # Frida-attached by default. This keeps P2 useful without making the VM
        # fragile. Profiles/options may override the list explicitly.
        self.injected_exclude_names = self._as_name_set(
            self.options.get(
                "frida_injected_exclude_names",
                features_cfg.get(
                    "injected_exclude_names",
                    [
                        "system", "registry", "smss.exe", "csrss.exe",
                        "wininit.exe", "winlogon.exe", "services.exe",
                        "lsass.exe",
                    ],
                ),
            )
        )

        try:
            self.injection_min_signals = max(
                1,
                int(
                    self.options.get(
                        "frida_injection_min_signals",
                        self.profile.get("injection_min_signals", 2),
                    )
                ),
            )
        except Exception:
            self.injection_min_signals = 2

        try:
            self.injection_signal_window = max(
                0.5,
                float(
                    self.options.get(
                        "frida_injection_signal_window",
                        self.profile.get("injection_signal_window", 5.0),
                    )
                ),
            )
        except Exception:
            self.injection_signal_window = 5.0

        try:
            self.injection_capemon_detect_timeout = float(
                self.options.get(
                    "frida_injection_capemon_detect_timeout",
                    self.profile.get("injection_capemon_detect_timeout", 2.0),
                )
            )
        except Exception:
            self.injection_capemon_detect_timeout = 2.0

        try:
            self.injection_capemon_grace = float(
                self.options.get(
                    "frida_injection_capemon_grace",
                    self.profile.get("injection_capemon_grace", 0.25),
                )
            )
        except Exception:
            self.injection_capemon_grace = 0.25

        try:
            self.max_sessions = max(
                1,
                int(
                    self.options.get(
                        "frida_max_sessions",
                        self.profile.get("max_sessions", 16),
                    )
                ),
            )
        except Exception:
            self.max_sessions = 16

        self.p3_runtime_report_enabled = self._as_bool(
            self.options.get(
                "frida_p3_runtime_report",
                features_cfg.get("p3_runtime_report", True),
            )
        )
        try:
            self.p3_max_evidence = max(100, int(
                self.options.get(
                    "frida_p3_max_evidence",
                    self.profile.get("p3_max_evidence", 5000),
                )
            ))
        except Exception:
            self.p3_max_evidence = 5000

        default_results_dir = self._detect_capesolo_analysis_output_dir()
        self.p3_runtime_report_path = Path(str(
            self.options.get(
                "frida_p3_runtime_report_path",
                default_results_dir / "frida_p3_runtime.json",
            )
        ))

    @staticmethod
    def _detect_capesolo_analysis_output_dir():
        """Resolve CAPEsolo's configured analysis output directory when possible."""
        candidates = [Path.cwd() / "cfg.ini"]
        if os.name == "nt":
            candidates.append(
                Path(os.environ.get("PUBLIC", r"C:\Users\Public"))
                / "CAPEsolo" / "cfg.ini"
            )
        for cfg_path in candidates:
            try:
                if not cfg_path.is_file():
                    continue
                parser = configparser.ConfigParser()
                parser.read(cfg_path, encoding="utf-8")
                value = parser.get("analysis_directory", "analysis", fallback="").strip()
                if value:
                    return Path(value)
            except Exception:
                continue
        if os.name == "nt":
            return (
                Path(os.environ.get("PUBLIC", r"C:\Users\Public"))
                / "CAPEsolo" / "analysis"
            )
        return Path.cwd()

    @staticmethod
    def _p3_json_safe(value, depth=0):
        if depth > 6:
            return "<max-depth>"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value if len(value) <= 4096 else value[:4096] + "<truncated>"
        if isinstance(value, bytes):
            return value[:512].hex() + ("<truncated>" if len(value) > 512 else "")
        if isinstance(value, dict):
            return {
                str(k): FridaMuncher._p3_json_safe(v, depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [FridaMuncher._p3_json_safe(v, depth + 1) for v in value]
        return str(value)

    def _emit_evidence(self, kind, severity="info", **fields):
        event = {
            "schema": "capesolo-frida-p3-evidence/1",
            "kind": str(kind),
            "severity": str(severity),
            "wall_time": time.time(),
            "monotonic": time.monotonic(),
            "run_id": self.run_id,
        }
        event.update(self._p3_json_safe(fields))
        with self.p3_evidence_lock:
            self.p3_evidence_seq += 1
            event["seq"] = self.p3_evidence_seq
            if len(self.p3_evidence) < self.p3_max_evidence:
                self.p3_evidence.append(event)
            else:
                self.p3_evidence_dropped += 1
        # Keep the text log compact but machine-readable for recovery when the
        # runtime JSON file is unavailable.
        try:
            log.info("[P3Evidence] %s", json.dumps(event, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            log.debug("[P3Evidence] failed serializing event", exc_info=True)
        return event

    def _write_p3_runtime_report(self, session_count=0, excluded_summary=None):
        if not self.p3_runtime_report_enabled or self.p3_runtime_report_path is None:
            return None
        with self.session_lock:
            lineage = self._p3_json_safe(dict(self.lineage))
            failed = self._p3_json_safe(list(self.failed_identities))
        with self.p3_evidence_lock:
            events = list(self.p3_evidence)
            dropped = int(self.p3_evidence_dropped)
            hook_counts = dict(self.p3_hook_counts)
        report = {
            "schema": "capesolo-frida-p3-runtime/1",
            "version": "P3.2",
            "run_id": self.run_id,
            "run_started_wall": self.started_wall,
            "run_stopped_wall": self.stopped_wall,
            "profile": {
                "request": self.profile_request,
                "selected": self.profile_name,
                "selection": self._p3_json_safe(self.profile_selection),
            },
            "target_pid": self.target_pid,
            "sample_dir": self.analysis_dir,
            "results_dir": str(self.p3_runtime_report_path.parent) if self.p3_runtime_report_path else None,
            # P3.2 uses analysis_dir for CAPEsolo result storage; sample_dir is
            # the malware working directory.
            "analysis_dir": str(self.p3_runtime_report_path.parent) if self.p3_runtime_report_path else None,
            "gate_mode": self.gate_mode,
            "anti_analysis_mode": self.anti_analysis_mode,
            "follow_children": self.follow_children,
            "follow_injected_targets": self.follow_injected_targets,
            "sysmon": {
                "bridge_active_at_stop": bool(self.sysmon_bridge_active),
                "bridge_active_at_report": bool(self.sysmon_bridge_active),
                "bridge_ever_active": bool(self.sysmon_ever_active),
                "events_seen": self.sysmon_events_seen,
                "by_id": dict(sorted(self.sysmon_event_counts.items())),
            },
            "frida_sessions_at_stop": int(session_count),
            "excluded_descendants": excluded_summary or {},
            "lineage": lineage,
            "failed_identities": failed,
            "hook_counts": hook_counts,
            "evidence_dropped": dropped,
            "evidence": events,
        }
        try:
            path = self.p3_runtime_report_path
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))

            # Keep a per-attempt immutable-ish mirror in addition to the current
            # alias. This is P3-layer isolation only; raw CAPEsolo files remain
            # under the configured analysis directory.
            if self.run_id:
                run_dir = path.parent / "p3_runs" / str(self.run_id)
                run_dir.mkdir(parents=True, exist_ok=True)
                run_path = run_dir / "frida_p3_runtime.json"
                run_tmp = run_path.with_name(run_path.name + ".tmp")
                run_tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                os.replace(str(run_tmp), str(run_path))
                self.p3_run_dir = run_dir

            log.info("[FridaMuncher] P3 runtime report written: %s", path)
            return path
        except Exception:
            log.exception("[FridaMuncher] Failed writing P3 runtime report")
            return None


    def _write_p3_run_marker(self, status):
        """Write a small atomic pointer to the current P3.2 attempt."""
        if self.p3_runtime_report_path is None or not self.run_id:
            return
        try:
            base = self.p3_runtime_report_path.parent
            marker = base / "p3_current_run.json"
            payload = {
                "schema": "capesolo-frida-p3-run/1",
                "version": "P3.2",
                "run_id": self.run_id,
                "status": str(status),
                "started_wall": self.started_wall,
                "stopped_wall": self.stopped_wall,
                "profile": self.profile_name,
                "sample_dir": self.analysis_dir,
                "target_pid": self.target_pid,
            }
            marker.parent.mkdir(parents=True, exist_ok=True)
            tmp = marker.with_name(marker.name + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(marker))
        except Exception:
            log.debug("[FridaMuncher] Failed writing P3.2 run marker", exc_info=True)

    def _load_profile(self, name):
        """Load a profile from data/frida_profiles/<name>.json.

        Generic mode is fail-safe: if a requested profile is missing or
        malformed, no gate is enabled and no sample-specific bypass is used.
        """
        profile_dir = Path.cwd() / "data" / "frida_profiles"
        path = profile_dir / f"{name}.json"

        safe_default = {
            "name": "generic",
            "target": {"name": ""},
            "gate": {"mode": "none"},
            "features": {
                "legacy_int2a": False,
                "follow_children": True,
                "private_exec_callers": True,
                "anti_analysis_mode": "observe",
                "child_anti_analysis_mode": "observe",
                "follow_injected_targets": True,
                "sysmon_bridge": True,
                "frida_injection_fallback": True,
                "child_exclude_names": ["werfault.exe", "wermgr.exe", "conhost.exe"],
                "injected_exclude_names": [
                    "system", "registry", "smss.exe", "csrss.exe",
                    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
                ],
            },
            "capemon_activation_timeout": 20.0,
            "capemon_detect_timeout": 5,
            "capemon_grace": 1.5,
            "capemon_fallback_delay": 2.0,
            "child_capemon_detect_timeout": 5,
            "child_capemon_grace": 0.5,
            "child_wait_for_root_ready": True,
            "child_root_ready_timeout": 10.0,
            "injection_capemon_detect_timeout": 2.0,
            "injection_capemon_grace": 0.25,
            "injection_min_signals": 2,
            "injection_signal_window": 5.0,
            "sysmon_channel": "Microsoft-Windows-Sysmon/Operational",
            "sysmon_event_ids": [1, 5, 8, 25],
            "sysmon_injected_source_policy": "correlate",
            "sysmon_tampering_init_window": 3.0,
            "max_sessions": 16,
            "attach_retries": 2,
            "wait_timeout": 120,
        }

        if not path.exists():
            if name != "generic":
                log.warning(
                    "[FridaMuncher] Profile %s not found at %s; using safe "
                    "generic defaults.",
                    name,
                    path,
                )
            return safe_default

        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("profile root must be a JSON object")
            merged = dict(safe_default)
            merged.update(loaded)
            return merged
        except Exception:
            log.exception(
                "[FridaMuncher] Failed loading profile %s; using safe generic "
                "defaults.",
                path,
            )
            return safe_default

    @staticmethod
    def _as_bool(value):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {
            "1", "true", "yes", "on", "enabled"
        }

    @staticmethod
    def _as_name_set(value):
        """Normalize a profile list or comma-separated CAPE option to basenames."""
        if value is None:
            return set()
        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = str(value).replace(";", ",").split(",")
        return {
            os.path.basename(str(item).strip()).lower()
            for item in items
            if str(item).strip()
        }

    @staticmethod
    def _as_int_tuple(value, default=()):
        if value is None:
            return tuple(default)
        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = str(value).replace(";", ",").split(",")
        out = []
        for item in items:
            try:
                number = int(str(item).strip(), 0)
            except Exception:
                continue
            if number > 0 and number not in out:
                out.append(number)
        return tuple(out or default)

    @staticmethod
    def _path_is_under(path, directory):
        if not path or not directory:
            return False
        try:
            path = os.path.normcase(os.path.abspath(path))
            directory = os.path.normcase(os.path.abspath(directory))
            return os.path.commonpath([path, directory]) == directory
        except Exception:
            return False

    def _candidate_scope_matches(self, name, exe_path):
        """Return True only for a process belonging to this CAPE analysis.

        Selection priority:
          1. Exact profile/option target name + exact path under curdir.
          2. Generic mode: any NEW executable whose path is under curdir.
          3. If curdir is unavailable, an explicit frida_target is required.
        """
        if self.target_name:
            if not name or str(name).lower() != self.target_name.lower():
                return False

            if self.expected_path and exe_path:
                return exe_path == self.expected_path

            if self.analysis_dir and exe_path:
                return self._path_is_under(exe_path, self.analysis_dir)

            # Name-only fallback is allowed only when the user/profile
            # explicitly selected a target name.
            return True

        # Generic mode deliberately refuses name-only discovery. CAPE's curdir
        # gives us a safe boundary that excludes helper/system processes.
        if self.analysis_dir and exe_path:
            return self._path_is_under(exe_path, self.analysis_dir)

        return False

    def configure_from_data(self):
        return None

    # ------------------------------------------------------------------
    # Process discovery
    # ------------------------------------------------------------------

    def _matching_name(self, name):
        # Empty target_name means generic path-based discovery.
        if not self.target_name:
            return True
        if not name:
            return False
        return str(name).lower() == self.target_name.lower()

    def _get_identity(self, proc):
        try:
            create_time = float(
                proc.create_time()
            )
        except Exception:
            create_time = None

        try:
            exe_path = os.path.normcase(
                os.path.abspath(
                    proc.exe()
                )
            )
        except Exception:
            exe_path = None

        return (
            int(proc.pid),
            create_time,
            exe_path,
        )

    def _snapshot_existing_targets(self):
        snapshot = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid, ctime, exe_path = self._get_identity(proc)
                name = proc.info.get("name")

                if not self._candidate_scope_matches(name, exe_path):
                    continue

                snapshot[pid] = {
                    "create_time": ctime,
                    "exe": exe_path,
                }

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):
                continue

        return snapshot

    def _same_as_baseline_process(
        self,
        pid,
        create_time,
    ):
        old = self.baseline_targets.get(pid)

        if old is None:
            return False

        old_ctime = old.get("create_time")

        # If both timestamps are available, the same PID is safe to reuse
        # only when Windows reports a genuinely different process creation.
        if (
            old_ctime is not None
            and create_time is not None
        ):
            return (
                abs(
                    old_ctime
                    - create_time
                )
                < 0.5
            )

        # If creation time cannot be obtained, conservatively treat a
        # baseline PID as stale and ignore it.
        return True

    def _candidate_is_current_analysis(self, proc):
        try:
            name = proc.name()
        except Exception:
            return False

        pid, create_time, exe_path = self._get_identity(proc)

        if not self._candidate_scope_matches(name, exe_path):
            return False

        if self._same_as_baseline_process(pid, create_time):
            return False

        # CAPE starts auxiliary modules before the package process.
        if (
            create_time is not None
            and self.started_wall is not None
            and create_time < self.started_wall - 1.0
        ):
            return False

        identity_key = (
            pid,
            round(create_time or 0.0, 3),
        )

        if identity_key in self.failed_identities:
            return False

        return (
            pid,
            create_time,
            exe_path,
            identity_key,
        )

    def _wait_for_new_target(self, deadline):
        last_stale_log = 0.0

        while (
            not self.stop_event.is_set()
            and time.monotonic() < deadline
        ):
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    candidate = self._candidate_is_current_analysis(proc)

                    if candidate:
                        return candidate

                    # Only emit stale logs for processes that at least match the
                    # configured name/path scope; otherwise generic mode would
                    # spam one line per system process.
                    try:
                        pid, _, exe_path = self._get_identity(proc)
                        name = proc.info.get("name")
                        in_scope = self._candidate_scope_matches(name, exe_path)
                    except Exception:
                        in_scope = False
                        pid = -1

                    now = time.monotonic()
                    if in_scope and now - last_stale_log > 5.0:
                        log.info(
                            "[FridaMuncher] Ignoring pre-existing/stale "
                            "target pid=%d",
                            pid,
                        )
                        last_stale_log = now

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                ):
                    continue

            time.sleep(0.10)

        return None

    # ------------------------------------------------------------------
    # CAPEMON synchronization
    # ------------------------------------------------------------------

    def _identity_still_alive(
        self,
        pid,
        original_create_time,
    ):
        try:
            proc = psutil.Process(pid)

            if not proc.is_running():
                return False

            if original_create_time is not None:
                current_ctime = proc.create_time()

                if (
                    abs(
                        current_ctime
                        - original_create_time
                    )
                    >= 0.5
                ):
                    return False

            return True

        except Exception:
            return False

    def _wait_seconds_while_alive(
        self,
        pid,
        create_time,
        seconds,
    ):
        deadline = (
            time.monotonic()
            + seconds
        )

        while (
            not self.stop_event.is_set()
            and time.monotonic()
            < deadline
        ):
            if not self._identity_still_alive(
                pid,
                create_time,
            ):
                return False

            time.sleep(0.10)

        return not self.stop_event.is_set()

    def _wait_for_capemon(
        self,
        pid,
        create_time,
        grace=None,
        detect_timeout=None,
        fallback_floor=None,
    ):
        """Synchronize Frida after CAPEMON without consuming the detect timer
        while CAPE still holds the root process suspended.

        P3.1 uses two phases for the root process:
          1) activation phase: wait for CAPEMON to appear or for CPU time to
             advance, which is a conservative signal that the process resumed;
          2) detect phase: only now apply capemon_detect_timeout.

        Child and already-running injected targets keep the shorter P2.1 path.
        """
        if grace is None:
            grace = self.capemon_grace
        if detect_timeout is None:
            detect_timeout = self.capemon_detect_timeout
        if fallback_floor is None:
            fallback_floor = max(1.0, grace)

        cape_dll_dir = os.path.normcase(os.path.abspath(str(Path.cwd() / "dll")))
        memory_maps_supported = None

        with self.session_lock:
            role = str(self.lineage.get(pid, {}).get("role") or "")

        def find_capemon_mapping():
            nonlocal memory_maps_supported
            try:
                proc = psutil.Process(pid)
                maps = proc.memory_maps(grouped=False)
                memory_maps_supported = True
                for mapping in maps:
                    raw_path = getattr(mapping, "path", "") or ""
                    if not raw_path:
                        continue
                    mapped_path = os.path.normcase(os.path.abspath(raw_path))
                    if (
                        mapped_path.endswith(".dll")
                        and mapped_path.startswith(cape_dll_dir)
                        and "frida" not in mapped_path
                    ):
                        return mapped_path
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                raise
            except Exception:
                if memory_maps_supported is None:
                    memory_maps_supported = False
            return None

        def mark_capemon(mapped_path):
            now_mono = time.monotonic()
            with self.session_lock:
                meta = self.lineage.get(pid)
                if meta is not None:
                    meta["capemon_seen_monotonic"] = now_mono
                    meta["capemon_mapping"] = mapped_path
            log.info("[FridaMuncher][pid=%d] CAPEMON mapping detected: %s", pid, mapped_path)
            self._emit_evidence(
                "capemon_mapping", pid=pid, status="detected",
                path=mapped_path, grace=grace,
            )
            log.info(
                "[FridaMuncher][pid=%d] Waiting %.1fs CAPEMON grace period before Frida attach...",
                pid, grace,
            )
            return self._wait_seconds_while_alive(pid, create_time, grace)

        log.info("[FridaMuncher][pid=%d] Waiting for the current CAPEMON mapping...", pid)

        # Root-only activation phase. Existing children/injected targets may be
        # idle by design, so CPU advancement is not a useful prerequisite there.
        if role == "root" and self.capemon_activation_timeout > 0:
            try:
                proc = psutil.Process(pid)
                cpu0 = proc.cpu_times()
                baseline_cpu = float(cpu0.user) + float(cpu0.system)
            except Exception:
                baseline_cpu = None

            activation_deadline = time.monotonic() + self.capemon_activation_timeout
            activated = False
            while not self.stop_event.is_set() and time.monotonic() < activation_deadline:
                if not self._identity_still_alive(pid, create_time):
                    return False
                try:
                    mapped = find_capemon_mapping()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False
                if mapped:
                    return mark_capemon(mapped)

                try:
                    proc = psutil.Process(pid)
                    cpu = proc.cpu_times()
                    current_cpu = float(cpu.user) + float(cpu.system)
                    if baseline_cpu is None:
                        baseline_cpu = current_cpu
                    elif current_cpu > baseline_cpu + 0.005:
                        activated = True
                        now_mono = time.monotonic()
                        with self.session_lock:
                            meta = self.lineage.get(pid)
                            if meta is not None:
                                meta["process_activated_monotonic"] = now_mono
                        self._emit_evidence(
                            "process_activation", pid=pid, role=role,
                            signal="cpu_time_advanced", baseline_cpu=baseline_cpu,
                            current_cpu=current_cpu,
                        )
                        log.info(
                            "[FridaMuncher][pid=%d] Root activity detected; starting %.1fs CAPEMON detect window.",
                            pid, detect_timeout,
                        )
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False
                except Exception:
                    pass
                time.sleep(0.10)

            if not activated:
                self._emit_evidence(
                    "process_activation", severity="warning", pid=pid, role=role,
                    signal="activation_timeout", timeout=self.capemon_activation_timeout,
                )
                log.warning(
                    "[FridaMuncher][pid=%d] No explicit root activation signal within %.1fs; starting CAPEMON detect window conservatively.",
                    pid, self.capemon_activation_timeout,
                )

        detect_deadline = time.monotonic() + detect_timeout
        while not self.stop_event.is_set() and time.monotonic() < detect_deadline:
            if not self._identity_still_alive(pid, create_time):
                return False
            try:
                mapped = find_capemon_mapping()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
            if mapped:
                return mark_capemon(mapped)
            time.sleep(0.15)

        if not self._identity_still_alive(pid, create_time):
            return False

        fallback = max(grace, fallback_floor)
        log.warning(
            "[FridaMuncher][pid=%d] CAPEMON mapping was not positively identified in %.1fs after activation; using an additional %.1fs fallback delay.",
            pid, detect_timeout, fallback,
        )
        self._emit_evidence(
            "capemon_mapping", severity="warning", pid=pid, status="fallback",
            detect_timeout=detect_timeout, fallback=fallback,
            activation_timeout=self.capemon_activation_timeout if role == "root" else 0.0,
        )
        return self._wait_seconds_while_alive(pid, create_time, fallback)

    # ------------------------------------------------------------------
    # Frida / multi-process session management
    # ------------------------------------------------------------------

    def _new_process_events(self, pid):
        state = {
            "ready": threading.Event(),
            "gate": threading.Event(),
            "last_gate": None,
        }
        with self.session_lock:
            self.process_events[pid] = state
        return state

    def _on_message(self, pid, script_name, message, data):
        mtype = message.get("type")

        if mtype == "send":
            payload = message.get("payload")
            log.info(
                "[FridaMuncher][pid=%d][%s] %s",
                pid,
                script_name,
                payload,
            )

            if isinstance(payload, dict):
                hook = payload.get("hook")
                action = payload.get("action")
                if hook:
                    key = f"{hook}:{action or ''}"
                    with self.p3_evidence_lock:
                        self.p3_hook_counts[key] = self.p3_hook_counts.get(key, 0) + 1
                    if hook in {"EP_Gate", "InstrumentationModule", "InstrumentationRange"}:
                        self._emit_evidence(
                            "frida_hook_event", pid=pid, script=script_name,
                            hook=hook, action=action, payload=payload,
                        )
                    elif hook == "Exception" and action == "first":
                        self._emit_evidence(
                            "first_exception", severity="warning", pid=pid,
                            script=script_name, payload=payload,
                        )
                with self.session_lock:
                    state = self.process_events.get(pid)

                if state is not None:
                    if hook == "FridaHooks" and action == "ready":
                        state["ready"].set()
                    if hook == "EP_Gate" and action in (
                        "released",
                        "refused",
                        "exception",
                    ):
                        state["last_gate"] = payload
                        state["gate"].set()

                if hook == "ProcessEnrollment" and action == "hint":
                    self._handle_process_enrollment_hint(pid, payload)
            return

        if mtype == "error":
            log.error(
                "[FridaMuncher][pid=%d][%s] JS ERROR: %s\n%s",
                pid,
                script_name,
                message.get("description", "JavaScript error"),
                message.get("stack", ""),
            )
            return

        log.debug(
            "[FridaMuncher][pid=%d][%s] message=%r data=%r",
            pid,
            script_name,
            message,
            data,
        )

    def _on_session_detached(self, pid, reason, crash=None):
        with self.session_lock:
            self.sessions.pop(pid, None)
            self.scripts_by_pid.pop(pid, None)
            self.process_events.pop(pid, None)
            meta = self.process_meta.get(pid, {})

        log.info(
            "[FridaMuncher][pid=%d] Frida session detached: reason=%s role=%s",
            pid,
            reason,
            meta.get("role", "unknown"),
        )
        self._emit_evidence(
            "frida_detached", pid=pid, reason=reason, role=meta.get("role", "unknown"),
        )

    def _attach_with_retry(self, pid, create_time):
        device = frida.get_local_device()

        for attempt in range(1, self.attach_retries + 1):
            if not self._identity_still_alive(pid, create_time):
                return None

            log.info(
                "[FridaMuncher][pid=%d] Attaching Frida (attempt %d/%d)...",
                pid,
                attempt,
                self.attach_retries,
            )
            attach_started = time.monotonic()
            with self.session_lock:
                meta = self.lineage.get(pid)
                if meta is not None:
                    meta["frida_attach_started_monotonic"] = attach_started
                    meta["frida_attach_attempt"] = attempt

            try:
                session = device.attach(pid)
                attached_at = time.monotonic()
                with self.session_lock:
                    meta = self.lineage.get(pid)
                    if meta is not None:
                        meta["frida_attached_monotonic"] = attached_at
                self._emit_evidence(
                    "frida_attach", pid=pid, status="success", attempt=attempt,
                )
                return session
            except (frida.ProcessNotFoundError, frida.TransportError) as exc:
                self._emit_evidence(
                    "frida_attach", severity="warning", pid=pid, status="failed",
                    attempt=attempt, error=str(exc),
                )
                log.warning(
                    "[FridaMuncher][pid=%d] Frida attach attempt %d failed: %s",
                    pid,
                    attempt,
                    exc,
                )
                if attempt < self.attach_retries:
                    if not self._wait_seconds_while_alive(
                        pid, create_time, 1.0
                    ):
                        return None
        return None

    def _load_scripts(self, pid, session):
        script_dir = Path.cwd() / "data" / "frida_scripts"
        paths = sorted(script_dir.glob("*.js"))
        if not paths:
            raise RuntimeError(f"No Frida .js files found in {script_dir}")

        loaded = []
        for path in paths:
            source = path.read_text(encoding="utf-8")
            script = session.create_script(source)
            script.on(
                "message",
                lambda message, data, p=pid, n=path.name: self._on_message(
                    p, n, message, data
                ),
            )
            try:
                script.load()
            except Exception:
                log.exception(
                    "[FridaMuncher][pid=%d] Failed loading %s",
                    pid,
                    path.name,
                )
                continue

            loaded.append((path.name, script))
            self._emit_evidence("script_loaded", pid=pid, script=path.name)
            log.info(
                "[FridaMuncher][pid=%d] Loaded: %s",
                pid,
                path.name,
            )

        if not loaded:
            raise RuntimeError("Every Frida script failed to load")
        return loaded

    def _configure_scripts(self, pid, scripts, role):
        # Sample-specific gate/exception recovery belongs only to the initial
        # target. Child/injected processes receive the general anti-analysis
        # policy but never inherit an entry-gate patch automatically.
        gate_mode = self.gate_mode if role == "root" else "none"
        legacy_int2a = self.enable_legacy_int2a if role == "root" else False
        anti_mode = (
            self.anti_analysis_mode
            if role == "root"
            else self.child_anti_analysis_mode
        )

        bridge_active = bool(
            self.sysmon_bridge is not None and self.sysmon_bridge.active
        )
        self.sysmon_bridge_active = bridge_active
        if not self.follow_injected_targets:
            tracker_mode = "off"
        elif bridge_active:
            tracker_mode = "hybrid"
        elif self.frida_injection_fallback:
            tracker_mode = "frida_fallback"
        else:
            tracker_mode = "hybrid"

        payload = {
            "type": "profile_config",
            "profile": self.profile_name,
            "process_role": role,
            "enable_legacy_int2a": legacy_int2a,
            "gate_mode": gate_mode,
            "anti_analysis_mode": anti_mode,
            "private_exec_callers": self.private_exec_callers,
            "follow_injected_targets": self.follow_injected_targets,
            "injection_tracker_mode": tracker_mode,
            "sysmon_bridge_active": bridge_active,
        }

        delivered = 0
        for name, script in scripts:
            try:
                script.post(payload)
                delivered += 1
            except Exception:
                log.exception(
                    "[FridaMuncher][pid=%d] Failed posting profile_config to %s",
                    pid,
                    name,
                )

        log.info(
            "[FridaMuncher][pid=%d] Profile configuration sent to %d "
            "script(s): profile=%s role=%s anti_analysis=%s "
            "private_exec=%s legacy_int2a=%s gate_mode=%s tracker=%s sysmon=%s",
            pid,
            delivered,
            self.profile_name,
            role,
            anti_mode,
            self.private_exec_callers,
            legacy_int2a,
            gate_mode,
            tracker_mode,
            bridge_active,
        )
        self._emit_evidence(
            "profile_configured", pid=pid, role=role, profile=self.profile_name,
            anti_analysis=anti_mode, gate_mode=gate_mode, tracker_mode=tracker_mode,
            sysmon=bridge_active, delivered=delivered,
        )
        return delivered

    def _release_gate(self, pid, scripts):
        if self.gate_mode == "none":
            log.info(
                "[FridaMuncher][pid=%d] Gate disabled by profile/config; "
                "no sample bytes will be modified.",
                pid,
            )
            return 0

        if self.gate_mode != "patched_entry":
            log.warning(
                "[FridaMuncher][pid=%d] Unsupported gate_mode=%s; refusing "
                "to modify target memory.",
                pid,
                self.gate_mode,
            )
            return 0

        payload = {
            "type": "release_ep",
            "restore_hex": self.restore_hex,
            "expected_hex": self.expected_gate_hex,
            "gate_delta": self.gate_delta,
        }

        delivered = 0
        for name, script in scripts:
            try:
                script.post(payload)
                delivered += 1
            except Exception:
                log.exception(
                    "[FridaMuncher][pid=%d] Failed posting release_ep to %s",
                    pid,
                    name,
                )

        log.info(
            "[FridaMuncher][pid=%d] EP release request sent to %d script(s): "
            "profile=%s expected=%s restore=%s delta=0x%x",
            pid,
            delivered,
            self.profile_name,
            self.expected_gate_hex,
            self.restore_hex,
            self.gate_delta,
        )
        return delivered

    def _instrument_process(
        self,
        pid,
        create_time,
        exe_path,
        identity_key,
        role,
    ):
        """Attach/configure one PID. Safe to call from child worker threads."""
        if self.stop_event.is_set():
            return False

        if role == "root":
            grace = self.capemon_grace
            detect_timeout = self.capemon_detect_timeout
            fallback_floor = self.capemon_fallback_delay
        elif role == "injected":
            # A pre-existing injection target may never receive CAPEMON. Keep the
            # CAPEMON preference, but do not wait long before Frida enrollment.
            grace = self.injection_capemon_grace
            detect_timeout = self.injection_capemon_detect_timeout
            fallback_floor = 0.5
        else:
            grace = self.child_capemon_grace
            detect_timeout = self.child_capemon_detect_timeout
            fallback_floor = 1.0

        if not self._wait_for_capemon(
            pid,
            create_time,
            grace=grace,
            detect_timeout=detect_timeout,
            fallback_floor=fallback_floor,
        ):
            log.warning(
                "[FridaMuncher][pid=%d] %s disappeared before "
                "CAPEMON/Frida synchronization.",
                pid,
                role,
            )
            self.failed_identities.add(identity_key)
            return False

        session = self._attach_with_retry(pid, create_time)
        if session is None:
            log.warning(
                "[FridaMuncher][pid=%d] Could not attach Frida to %s.",
                pid,
                role,
            )
            self.failed_identities.add(identity_key)
            return False

        state = self._new_process_events(pid)
        with self.session_lock:
            self.sessions[pid] = session
            self.process_meta[pid] = {
                "create_time": create_time,
                "exe": exe_path,
                "identity": identity_key,
                "role": role,
            }

        try:
            try:
                session.on(
                    "detached",
                    lambda reason, crash=None, p=pid: self._on_session_detached(
                        p, reason, crash
                    ),
                )
            except Exception:
                # Session detach callbacks are useful but not required for
                # correctness; stop() still performs explicit cleanup.
                pass

            scripts = self._load_scripts(pid, session)
            with self.session_lock:
                self.scripts_by_pid[pid] = scripts

            log.info(
                "[FridaMuncher][pid=%d] All available scripts loaded for %s.",
                pid,
                role,
            )
            self._configure_scripts(pid, scripts, role)

            if not state["ready"].wait(timeout=5.0):
                log.error(
                    "[FridaMuncher][pid=%d] No FridaHooks-ready acknowledgement "
                    "for %s; no gate will be released.",
                    pid,
                    role,
                )
                raise RuntimeError("FridaHooks-ready timeout")

            log.info(
                "[FridaMuncher][pid=%d] JavaScript hooks confirmed ready for %s.",
                pid,
                role,
            )

            if role == "root":
                delivered = self._release_gate(pid, scripts)
                if self.gate_mode == "patched_entry" and delivered > 0:
                    if not state["gate"].wait(timeout=5.0):
                        log.error(
                            "[FridaMuncher][pid=%d] No EP_Gate result received "
                            "after release request.",
                            pid,
                        )
                    else:
                        log.info(
                            "[FridaMuncher][pid=%d] EP_Gate result: %s",
                            pid,
                            state["last_gate"],
                        )

            return True

        except Exception:
            log.exception(
                "[FridaMuncher][pid=%d] Script/setup failed for role=%s",
                pid,
                role,
            )
            self.failed_identities.add(identity_key)
            with self.session_lock:
                scripts = self.scripts_by_pid.pop(pid, [])
                self.sessions.pop(pid, None)
                self.process_events.pop(pid, None)
            for _, script in scripts:
                try:
                    script.unload()
                except Exception:
                    pass
            try:
                session.detach()
            except Exception:
                pass
            return False

    # ------------------------------------------------------------------
    # P2.1 hybrid Sysmon bridge
    # ------------------------------------------------------------------

    def _start_sysmon_bridge(self):
        if not self.follow_injected_targets or not self.sysmon_bridge_enabled:
            log.info(
                "[FridaMuncher] Sysmon bridge disabled by profile/config."
            )
            return False
        if SysmonRealtimeBridge is None:
            log.warning(
                "[FridaMuncher] Sysmon bridge helper unavailable; Frida "
                "correlation fallback remains enabled=%s.",
                self.frida_injection_fallback,
            )
            return False

        try:
            self.sysmon_bridge = SysmonRealtimeBridge(
                on_event=self._handle_sysmon_event,
                event_ids=self.sysmon_event_ids,
                channel=self.sysmon_channel,
                logger=log,
            )
            self.sysmon_bridge.start()
            # CAPEsolo may start its Sysmon auxiliary near the same time. The
            # bridge itself retries for a short period; wait briefly so root JS
            # can select the lower-hook hybrid mode when possible.
            self.sysmon_bridge.wait_until_active(timeout=2.0)
            self.sysmon_bridge_active = self.sysmon_bridge.active
            if self.sysmon_bridge_active:
                self.sysmon_ever_active = True
                log.info(
                    "[FridaMuncher] Sysmon realtime bridge active; Event ID 8 "
                    "is the primary remote-thread enrollment source."
                )
            else:
                log.warning(
                    "[FridaMuncher] Sysmon bridge not active yet; Frida tracker "
                    "will use fallback=%s for newly configured sessions.",
                    self.frida_injection_fallback,
                )
            return self.sysmon_bridge_active
        except Exception:
            log.exception("[FridaMuncher] Failed starting Sysmon bridge")
            self.sysmon_bridge = None
            self.sysmon_bridge_active = False
            return False

    def _handle_sysmon_event(self, event):
        if self.stop_event.is_set() or not isinstance(event, dict):
            return
        self.sysmon_events_seen += 1
        event_id = int(event.get("event_id") or 0)
        self.sysmon_event_counts[event_id] = self.sysmon_event_counts.get(event_id, 0) + 1

        if event_id == 1:
            self._handle_sysmon_process_create(event)
        elif event_id == 5:
            self._handle_sysmon_process_terminate(event)
        elif event_id == 8:
            self._handle_sysmon_remote_thread(event)
        elif event_id == 25:
            self._handle_sysmon_process_tampering(event)

    def _handle_sysmon_process_create(self, event):
        pid = int(event.get("process_id") or 0)
        if pid <= 0:
            return
        guid = str(event.get("process_guid") or "")
        with self.session_lock:
            meta = self.lineage.get(pid)
            if meta is not None:
                meta["sysmon_guid"] = guid or meta.get("sysmon_guid")
                meta["sysmon_image"] = event.get("image") or meta.get("exe")
                meta["sysmon_record_id"] = event.get("record_id")

    def _handle_sysmon_process_terminate(self, event):
        pid = int(event.get("process_id") or 0)
        if pid <= 0:
            return
        guid = str(event.get("process_guid") or "")
        with self.session_lock:
            meta = self.lineage.get(pid)
            if meta is None:
                return
            known_guid = str(meta.get("sysmon_guid") or "")
            if known_guid and guid and known_guid != guid:
                return
            meta["sysmon_terminated"] = True
            meta["sysmon_terminate_record_id"] = event.get("record_id")

    def _sysmon_source_is_tracked(self, source_pid, source_guid, source_image):
        with self.session_lock:
            meta = self.lineage.get(source_pid)
            if meta is None:
                return False
            known_guid = str(meta.get("sysmon_guid") or "")
            if known_guid and source_guid and known_guid != source_guid:
                return False

            # Learn the Sysmon ProcessGuid on the first matching event. If we do
            # not yet have a GUID, retain a conservative image consistency check.
            known_exe = os.path.normcase(str(meta.get("exe") or ""))
            event_exe = os.path.normcase(str(source_image or ""))
            if known_exe and event_exe:
                try:
                    if os.path.basename(known_exe).lower() != os.path.basename(event_exe).lower():
                        return False
                except Exception:
                    pass
            if source_guid and not known_guid:
                meta["sysmon_guid"] = source_guid
            return True

    def _handle_sysmon_remote_thread(self, event):
        if not self.follow_injected_targets:
            return
        source_pid = int(event.get("source_process_id") or 0)
        target_pid = int(event.get("target_process_id") or 0)
        source_guid = str(event.get("source_process_guid") or "")
        source_image = str(event.get("source_image") or "")
        if source_pid <= 0 or target_pid <= 0 or source_pid == target_pid:
            return

        if not self._sysmon_source_is_tracked(source_pid, source_guid, source_image):
            log.debug(
                "[FridaMuncher][Sysmon:EID8] telemetry only: untracked source "
                "source_pid=%d target_pid=%d source=%s target=%s",
                source_pid, target_pid, source_image, event.get("target_image"),
            )
            return

        with self.session_lock:
            source_role = str(self.lineage.get(source_pid, {}).get("role") or "")

        # A pre-existing injected host contains both benign host code and malware
        # code. Sysmon attributes EID8 to the process, not to the exact caller.
        # Therefore an injected host does not recursively enroll another process
        # from one Sysmon event by default. Correlate it with caller-filtered Frida
        # evidence unless a profile explicitly requests direct behavior.
        if source_role == "injected":
            if self.sysmon_injected_source_policy == "telemetry":
                log.info(
                    "[FridaMuncher][Sysmon:EID8] injected-source telemetry only: "
                    "source_pid=%d target_pid=%d", source_pid, target_pid,
                )
                return
            if self.sysmon_injected_source_policy == "correlate":
                self._handle_process_enrollment_hint(
                    source_pid,
                    {
                        "sensor": "sysmon",
                        "target_pid": target_pid,
                        "reason": "SysmonEID8:CreateRemoteThread",
                        "family": "sysmon_remote_thread",
                        "strength": "execution",
                    },
                )
                log.info(
                    "[FridaMuncher][Sysmon:EID8] injected-source event retained "
                    "for correlation: source_pid=%d target_pid=%d policy=correlate",
                    source_pid, target_pid,
                )
                return

        try:
            proc = psutil.Process(target_pid)
            if not proc.is_running():
                return
            target_create_time = float(proc.create_time())
            try:
                exe_path = os.path.normcase(os.path.abspath(proc.exe()))
            except Exception:
                exe_path = os.path.normcase(str(event.get("target_image") or "")) or None
            try:
                proc_name = str(proc.name() or "").lower()
            except Exception:
                proc_name = os.path.basename(exe_path or "").lower()
            try:
                actual_ppid = int(proc.ppid())
            except Exception:
                actual_ppid = None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        if proc_name in self.injected_exclude_names:
            log.warning(
                "[FridaMuncher][Sysmon:EID8] tracked source created remote thread "
                "in excluded critical target: source_pid=%d target_pid=%d name=%s "
                "start=%s module=%s function=%s; telemetry retained only",
                source_pid, target_pid, proc_name, event.get("start_address"),
                event.get("start_module"), event.get("start_function"),
            )
            return

        identity_key = (target_pid, round(target_create_time, 3))
        reason = "SysmonEID8:CreateRemoteThread"
        details = (
            f"start={event.get('start_address') or ''} "
            f"module={event.get('start_module') or ''} "
            f"function={event.get('start_function') or ''} "
            f"record={event.get('record_id')}"
        )
        log.warning(
            "[FridaMuncher][Sysmon:EID8] HIGH-confidence enrollment candidate: "
            "source_pid=%d target_pid=%d target=%s %s",
            source_pid, target_pid, exe_path, details,
        )
        self._emit_evidence(
            "sysmon_remote_thread", severity="warning", source_pid=source_pid,
            target_pid=target_pid, target=exe_path, details=details, confidence="high",
        )
        self._schedule_injected_target(
            source_pid=source_pid,
            target_pid=target_pid,
            target_create_time=target_create_time,
            exe_path=exe_path,
            identity_key=identity_key,
            actual_ppid=actual_ppid,
            reason=reason,
            evidence_count=1,
            strong=True,
            evidence_source="sysmon_eid8",
            confidence="high",
        )

    def _handle_sysmon_process_tampering(self, event):
        pid = int(event.get("process_id") or 0)
        if pid <= 0:
            return
        guid = str(event.get("process_guid") or "")
        now_mono = time.monotonic()
        with self.session_lock:
            meta = self.lineage.get(pid)
            if meta is None:
                log.debug(
                    "[FridaMuncher][Sysmon:EID25] telemetry only for untracked pid=%d image=%s type=%s",
                    pid, event.get("image"), event.get("tamper_type"),
                )
                return
            known_guid = str(meta.get("sysmon_guid") or "")
            if known_guid and guid and known_guid != guid:
                return
            if guid and not known_guid:
                meta["sysmon_guid"] = guid

            possible_sources = []
            capemon_seen = meta.get("capemon_seen_monotonic")
            if capemon_seen is not None or meta.get("capemon_mapping"):
                possible_sources.append("capemon")

            frida_started = meta.get("frida_attach_started_monotonic")
            frida_attached = meta.get("frida_attached_monotonic")
            if frida_attached is not None:
                possible_sources.append("frida")
            elif frida_started is not None:
                try:
                    if now_mono - float(frida_started) <= max(5.0, self.sysmon_tampering_init_window):
                        possible_sources.append("frida_attach")
                except Exception:
                    pass

            instrumentation_possible = bool(possible_sources)
            meta["sysmon_tampering"] = {
                "type": event.get("tamper_type"),
                "record_id": event.get("record_id"),
                "utc_time": event.get("utc_time"),
                "instrumentation_possible": instrumentation_possible,
                "possible_sources": possible_sources,
            }
        log.warning(
            "[FridaMuncher][Sysmon:EID25] tampering observed in tracked pid=%d role=%s image=%s type=%s instrumentation_possible=%s sources=%s",
            pid, meta.get("role"), event.get("image"), event.get("tamper_type"),
            instrumentation_possible, possible_sources,
        )
        self._emit_evidence(
            "sysmon_process_tampering", severity="warning", pid=pid,
            role=meta.get("role"), image=event.get("image"),
            tamper_type=event.get("tamper_type"),
            instrumentation_possible=instrumentation_possible,
            possible_sources=possible_sources,
        )

    # ------------------------------------------------------------------
    # P2.1 Frida fallback/enrichment target enrollment
    # ------------------------------------------------------------------

    def _handle_process_enrollment_hint(self, source_pid, payload):
        if not self.follow_injected_targets or self.stop_event.is_set():
            return

        try:
            target_pid = int(payload.get("target_pid") or 0)
        except Exception:
            return
        if target_pid <= 0 or target_pid == int(source_pid):
            return

        # Only accept hints originating from a process already associated with
        # this analysis. This prevents arbitrary Frida/system traffic from
        # enrolling unrelated processes.
        with self.session_lock:
            source_known = (
                source_pid in self.lineage or source_pid in self.sessions
            )
        if not source_known:
            return

        reason = str(payload.get("reason") or "unknown")
        strength = str(payload.get("strength") or "memory").lower()
        family = str(payload.get("family") or reason or "unknown").lower()
        sensor = str(payload.get("sensor") or "frida").lower()

        try:
            proc = psutil.Process(target_pid)
            if not proc.is_running():
                return
            target_create_time = float(proc.create_time())
            try:
                exe_path = os.path.normcase(os.path.abspath(proc.exe()))
            except Exception:
                exe_path = None
            try:
                proc_name = str(proc.name() or "").lower()
            except Exception:
                proc_name = os.path.basename(exe_path or "").lower()
            try:
                actual_ppid = int(proc.ppid())
            except Exception:
                actual_ppid = None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        if proc_name in self.injected_exclude_names:
            log.warning(
                "[FridaMuncher] Injection target observed but not attached: "
                "source_pid=%d target_pid=%d name=%s reason=%s "
                "policy=critical_process_excluded",
                source_pid, target_pid, proc_name, reason,
            )
            return

        identity_key = (target_pid, round(target_create_time, 3))
        evidence_key = (
            int(source_pid),
            target_pid,
            round(target_create_time, 3),
        )
        now = time.monotonic()

        with self.session_lock:
            evidence = self.enrollment_evidence.get(evidence_key)
            if (
                evidence is None
                or now - evidence.get("first_seen", now)
                > self.injection_signal_window
            ):
                evidence = {
                    "first_seen": now,
                    "last_seen": now,
                    "reasons": set(),
                    "families": set(),
                    "sensors": set(),
                }
                self.enrollment_evidence[evidence_key] = evidence

            evidence["last_seen"] = now
            evidence["reasons"].add(reason)
            evidence.setdefault("families", set()).add(family)
            evidence.setdefault("sensors", set()).add(sensor)
            evidence.setdefault("memory_families", set())
            evidence.setdefault("execution_families", set())
            if strength == "execution":
                evidence["execution_families"].add(family)
            else:
                evidence["memory_families"].add(family)

            # Correlate semantic families rather than raw API names. For example,
            # CreateRemoteThread -> NtCreateThreadEx is one remote_thread family,
            # and WriteProcessMemory -> NtWriteVirtualMemory is one remote_write
            # family. This avoids double-counting a single operation across Win32
            # and NT API layers.
            distinct_signals = len(evidence["families"])
            memory_count = len(evidence["memory_families"])
            execution_count = len(evidence["execution_families"])

            # P2.1 balanced policy: a single Frida execution API is evidence, not
            # proof. Enroll only after multiple distinct hints. This prevents a
            # legitimate one-off NtCreateThreadEx/CreateRemoteThread call from
            # immediately pulling an unrelated process into the analysis graph.
            should_enroll = (
                distinct_signals >= self.injection_min_signals
                and (memory_count > 0 or execution_count >= 2)
            )

        if not should_enroll:
            log.info(
                "[FridaMuncher] Injection hint retained: source_pid=%d "
                "target_pid=%d sensor=%s reason=%s family=%s strength=%s "
                "signals=%d/%d memory=%d execution=%d",
                source_pid, target_pid, sensor, reason, family, strength, distinct_signals,
                self.injection_min_signals, memory_count, execution_count,
            )
            self._emit_evidence(
                "injection_hint", source_pid=source_pid, target_pid=target_pid,
                sensor=sensor, reason=reason, family=family, strength=strength,
                distinct_signals=distinct_signals, minimum=self.injection_min_signals,
                memory_signals=memory_count, execution_signals=execution_count,
                decision="retained",
            )
            return

        sensors = set(evidence.get("sensors", set()))
        mixed_sensors = "sysmon" in sensors and "frida" in sensors
        self._schedule_injected_target(
            source_pid=source_pid,
            target_pid=target_pid,
            target_create_time=target_create_time,
            exe_path=exe_path,
            identity_key=identity_key,
            actual_ppid=actual_ppid,
            reason=reason,
            evidence_count=distinct_signals,
            strong=mixed_sensors,
            evidence_source="sysmon_frida_correlation" if mixed_sensors else f"{sensor}_correlation",
            confidence="high" if mixed_sensors else "medium",
        )

    def _schedule_injected_target(
        self,
        source_pid,
        target_pid,
        target_create_time,
        exe_path,
        identity_key,
        actual_ppid,
        reason,
        evidence_count,
        strong=False,
        evidence_source="frida_correlation",
        confidence="medium",
    ):
        with self.session_lock:
            existing = self.lineage.get(target_pid)
            if (
                existing is not None
                and abs(
                    (existing.get("create_time") or 0.0)
                    - target_create_time
                ) < 0.5
            ):
                return
            if identity_key in self.pending_identities:
                return
            if identity_key in self.failed_identities:
                return

            active_or_pending = (
                len(self.sessions) + len(self.pending_identities)
            )
            if active_or_pending >= self.max_sessions:
                log.warning(
                    "[FridaMuncher][pid=%d] Injection target discovered but "
                    "max_sessions=%d reached; not attaching.",
                    target_pid, self.max_sessions,
                )
                return

            # Event-driven enrollment intentionally does not require a PPID
            # relationship. The actual PPID is retained only as evidence.
            self.lineage[target_pid] = {
                "create_time": target_create_time,
                "ppid": actual_ppid,
                "exe": exe_path,
                "role": "injected",
                "source_pid": source_pid,
                "reason": reason,
                "evidence_source": evidence_source,
                "confidence": confidence,
                "enrolled_wall": time.time(),
            }
            self.pending_identities.add(identity_key)

        log.warning(
            "[FridaMuncher] INJECTION target enrolled: source_pid=%d "
            "target_pid=%d ppid=%s exe=%s reason=%s signals=%d strong=%s "
            "source=%s confidence=%s",
            source_pid, target_pid, actual_ppid, exe_path, reason,
            evidence_count, strong, evidence_source, confidence,
        )
        self._emit_evidence(
            "injection_enrolled", severity="warning", source_pid=source_pid,
            target_pid=target_pid, ppid=actual_ppid, exe=exe_path, reason=reason,
            evidence_count=evidence_count, strong=strong,
            evidence_source=evidence_source, confidence=confidence,
        )

        t = threading.Thread(
            target=self._instrument_injected_worker,
            args=(
                target_pid, target_create_time, exe_path, identity_key
            ),
            name=f"FridaMuncher-injected-{target_pid}",
            daemon=True,
        )
        with self.session_lock:
            self.enrollment_threads.append(t)
        t.start()

    def _instrument_injected_worker(
        self, pid, create_time, exe_path, identity_key
    ):
        try:
            self._instrument_process(
                pid, create_time, exe_path, identity_key, role="injected"
            )
        finally:
            with self.session_lock:
                self.pending_identities.discard(identity_key)

    # ------------------------------------------------------------------
    # Descendant tracking
    # ------------------------------------------------------------------

    def _lineage_contains_parent(self, ppid, child_create_time):
        with self.session_lock:
            parent = self.lineage.get(ppid)
        if parent is None:
            return False

        parent_ctime = parent.get("create_time")
        if (
            parent_ctime is not None
            and child_create_time is not None
            and child_create_time < parent_ctime - 1.0
        ):
            return False

        # A P2-injected host may have existed long before the analysis. Do not
        # retroactively enroll its already-existing children merely because the
        # host was just correlated as an injection target. Only children created
        # after enrollment are considered descendants of the malware activity.
        enrolled_wall = parent.get("enrolled_wall")
        if (
            parent.get("role") == "injected"
            and enrolled_wall is not None
            and child_create_time is not None
            and child_create_time < enrolled_wall - 1.0
        ):
            return False
        return True

    def _instrument_child_worker(
        self,
        pid,
        create_time,
        exe_path,
        identity_key,
    ):
        try:
            if self.child_wait_for_root_ready and not self.root_ready.is_set():
                log.debug(
                    "[FridaMuncher][pid=%d] Child attach queued until root "
                    "instrumentation is ready (timeout=%.1fs).",
                    pid, self.child_root_ready_timeout,
                )
                deadline = time.monotonic() + self.child_root_ready_timeout
                while (
                    not self.stop_event.is_set()
                    and not self.root_ready.is_set()
                    and time.monotonic() < deadline
                ):
                    if not self._identity_still_alive(pid, create_time):
                        log.debug(
                            "[FridaMuncher][pid=%d] Child exited while queued; "
                            "lineage retained without Frida attach.",
                            pid,
                        )
                        return
                    self.root_ready.wait(timeout=0.10)

                if not self.root_ready.is_set() and not self.stop_event.is_set():
                    log.warning(
                        "[FridaMuncher][pid=%d] Root was not ready after %.1fs; "
                        "proceeding with child attach to avoid indefinite delay.",
                        pid, self.child_root_ready_timeout,
                    )

            self._instrument_process(
                pid,
                create_time,
                exe_path,
                identity_key,
                role="child",
            )
        finally:
            with self.session_lock:
                self.pending_identities.discard(identity_key)

    def _watch_descendants(self):
        log.info(
            "[FridaMuncher] Child tracking enabled; max_sessions=%d.",
            self.max_sessions,
        )

        while not self.stop_event.is_set():
            for proc in psutil.process_iter(["pid", "ppid", "name"]):
                try:
                    pid = int(proc.info["pid"])
                    if pid == self.target_pid:
                        continue

                    ppid = int(proc.info.get("ppid") or 0)
                    create_time = float(proc.create_time())
                    identity_key = (pid, round(create_time, 3))

                    with self.session_lock:
                        already_known = (
                            pid in self.lineage
                            and abs(
                                (self.lineage[pid].get("create_time") or 0.0)
                                - create_time
                            ) < 0.5
                        )
                        pending = identity_key in self.pending_identities
                        excluded = identity_key in self.excluded_descendant_identities

                    if (
                        already_known
                        or pending
                        or excluded
                        or identity_key in self.failed_identities
                    ):
                        continue

                    if not self._lineage_contains_parent(ppid, create_time):
                        continue

                    try:
                        exe_path = os.path.normcase(os.path.abspath(proc.exe()))
                    except Exception:
                        exe_path = None

                    proc_name = str(
                        proc.info.get("name")
                        or os.path.basename(exe_path or "")
                        or ""
                    ).lower()
                    if proc_name in self.child_exclude_names:
                        with self.session_lock:
                            # Store once. Subsequent watcher passes hit the fast
                            # `excluded` check above and do not call proc.exe() or
                            # write another INFO line for the same process identity.
                            first_exclusion = (
                                identity_key
                                not in self.excluded_descendant_identities
                            )
                            if first_exclusion:
                                self.excluded_descendant_identities[identity_key] = {
                                    "pid": pid,
                                    "ppid": ppid,
                                    "create_time": create_time,
                                    "exe": exe_path,
                                    "name": proc_name,
                                    "reason": "excluded_child_name",
                                }

                        if first_exclusion:
                            log.info(
                                "[FridaMuncher] Excluded descendant registered: "
                                "pid=%d ppid=%d exe=%s "
                                "reason=excluded_child_name",
                                pid, ppid, exe_path,
                            )
                            self._emit_evidence(
                                "descendant_excluded", pid=pid, ppid=ppid, exe=exe_path,
                                name=proc_name, reason="excluded_child_name",
                            )
                        continue

                    # Add lineage immediately, before Frida attach. This lets a
                    # very short-lived child still contribute grandchildren.
                    with self.session_lock:
                        self.lineage[pid] = {
                            "create_time": create_time,
                            "ppid": ppid,
                            "exe": exe_path,
                            "role": "child",
                            "observed_monotonic": time.monotonic(),
                        }

                        active_or_pending = (
                            len(self.sessions) + len(self.pending_identities)
                        )
                        if active_or_pending >= self.max_sessions:
                            log.warning(
                                "[FridaMuncher][pid=%d] Descendant discovered "
                                "but max_sessions=%d reached; lineage retained "
                                "without Frida attach.",
                                pid,
                                self.max_sessions,
                            )
                            continue

                        self.pending_identities.add(identity_key)

                    log.info(
                        "[FridaMuncher] NEW descendant found: pid=%d ppid=%d "
                        "create_time=%s exe=%s",
                        pid,
                        ppid,
                        create_time,
                        exe_path,
                    )

                    t = threading.Thread(
                        target=self._instrument_child_worker,
                        args=(pid, create_time, exe_path, identity_key),
                        name=f"FridaMuncher-child-{pid}",
                        daemon=True,
                    )
                    with self.session_lock:
                        self.child_threads.append(t)
                    t.start()

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    log.debug(
                        "[FridaMuncher] Child discovery error for pid=%s",
                        getattr(proc, "pid", "?"),
                        exc_info=True,
                    )

            self.stop_event.wait(0.10)

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _run(self):
        overall_deadline = time.monotonic() + self.wait_timeout

        while (
            not self.stop_event.is_set()
            and time.monotonic() < overall_deadline
        ):
            candidate = self._wait_for_new_target(overall_deadline)
            if not candidate:
                break

            pid, create_time, exe_path, identity_key = candidate
            self.target_pid = pid

            log.info(
                "[FridaMuncher] NEW analysis target found: "
                "pid=%d create_time=%s exe=%s",
                pid,
                create_time,
                exe_path,
            )
            self._emit_evidence(
                "root_target", pid=pid, create_time=create_time, exe=exe_path,
                profile=self.profile_name,
            )

            self.root_ready.clear()
            with self.session_lock:
                self.lineage[pid] = {
                    "create_time": create_time,
                    "ppid": None,
                    "exe": exe_path,
                    "role": "root",
                    "observed_monotonic": time.monotonic(),
                }

            # Start descendant discovery as soon as the root PID is known.
            # Generic (ungated) malware may spawn short-lived children before
            # the root Frida attach has completed.
            if self.follow_children and (
                self.child_watcher is None
                or not self.child_watcher.is_alive()
            ):
                self.child_watcher = threading.Thread(
                    target=self._watch_descendants,
                    name="FridaMuncher-child-watcher",
                    daemon=True,
                )
                self.child_watcher.start()

            if not self._instrument_process(
                pid,
                create_time,
                exe_path,
                identity_key,
                role="root",
            ):
                continue

            self.root_ready.set()
            log.info(
                "[FridaMuncher][pid=%d] Root instrumentation ready; queued "
                "child attaches may proceed.",
                pid,
            )
            self._emit_evidence(
                "root_instrumentation_ready", pid=pid, profile=self.profile_name,
                gate_mode=self.gate_mode,
            )
            return

        log.warning(
            "[FridaMuncher] Worker finished without successfully "
            "instrumenting a new analysis target."
        )

    def start(self):
        self.stop_event.clear()
        self.root_ready.clear()
        self.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        self.started_wall = time.time()
        self.stopped_wall = None
        if self.p3_runtime_report_path is not None:
            self.p3_run_dir = self.p3_runtime_report_path.parent / "p3_runs" / self.run_id
        self._write_p3_run_marker("running")
        self.baseline_targets = self._snapshot_existing_targets()
        self._start_sysmon_bridge()

        log.info(
            "[FridaMuncher] P3.2 config: run_id=%s profile=%s target=%s "
            "analysis_dir=%s expected_path=%s gate_mode=%s restore=%s "
            "expected_gate=%s delta=0x%x legacy_int2a=%s "
            "anti_analysis=%s child_anti_analysis=%s private_exec=%s "
            "follow_children=%s follow_injected=%s max_sessions=%d "
            "capemon_activation=%.1fs capemon_detect=%.1fs capemon_grace=%.1fs capemon_fallback=%.1fs "
            "child_grace=%.1fs child_root_priority=%s child_root_timeout=%.1fs "
            "injection_grace=%.2fs injection_min_signals=%d "
            "sysmon_bridge=%s sysmon_active=%s "
            "sysmon_ids=%s frida_fallback=%s injected_source_policy=%s",
            self.run_id,
            self.profile_name,
            self.target_name or "<auto-from-curdir>",
            self.analysis_dir,
            self.expected_path,
            self.gate_mode,
            self.restore_hex or "<none>",
            self.expected_gate_hex or "<none>",
            self.gate_delta,
            self.enable_legacy_int2a,
            self.anti_analysis_mode,
            self.child_anti_analysis_mode,
            self.private_exec_callers,
            self.follow_children,
            self.follow_injected_targets,
            self.max_sessions,
            self.capemon_activation_timeout,
            self.capemon_detect_timeout,
            self.capemon_grace,
            self.capemon_fallback_delay,
            self.child_capemon_grace,
            self.child_wait_for_root_ready,
            self.child_root_ready_timeout,
            self.injection_capemon_grace,
            self.injection_min_signals,
            self.sysmon_bridge_enabled,
            self.sysmon_bridge_active,
            self.sysmon_event_ids,
            self.frida_injection_fallback,
            self.sysmon_injected_source_policy,
        )

        log.info(
            "[FridaMuncher] Baseline target PIDs to ignore: %s",
            self.baseline_targets,
        )
        log.info(
            "[FridaMuncher] P3/P3.1/P3.2 profile selection: requested=%s selected=%s source=%s score=%s candidate=%s reasons=%s",
            self.profile_request, self.profile_name,
            self.profile_selection.get("source"), self.profile_selection.get("score"),
            self.profile_selection.get("candidate"), self.profile_selection.get("reasons"),
        )
        self._emit_evidence(
            "controller_start", profile_request=self.profile_request,
            profile_selected=self.profile_name, profile_selection=self.profile_selection,
            sysmon_bridge_active=self.sysmon_bridge_active, baseline_targets=self.baseline_targets,
        )
        try:
            log.info(
                "[FridaMuncher] CAPE options received: %s",
                dict(self.options),
            )
        except Exception:
            log.info(
                "[FridaMuncher] CAPE options object: %r",
                self.options,
            )

        self.worker = threading.Thread(
            target=self._run,
            name="FridaMuncher-P3",
            daemon=True,
        )
        self.worker.start()
        log.info(
            "[FridaMuncher] P3.2 worker started; waiting for the NEW "
            "analysis target."
        )
        return True

    def stop(self):
        self.stop_event.set()

        if self.sysmon_bridge is not None:
            try:
                self.sysmon_bridge.stop()
            except Exception:
                log.debug("[FridaMuncher] Sysmon bridge stop failed", exc_info=True)
        self.sysmon_bridge_active = False

        with self.session_lock:
            scripts_by_pid = dict(self.scripts_by_pid)
            sessions = dict(self.sessions)
            self.scripts_by_pid.clear()
            self.sessions.clear()
            self.process_events.clear()

        for pid, scripts in scripts_by_pid.items():
            for _, script in scripts:
                try:
                    script.unload()
                except Exception:
                    pass

        for pid, session in sessions.items():
            try:
                session.detach()
            except Exception:
                pass

        with self.session_lock:
            excluded_summary = {}
            for meta in self.excluded_descendant_identities.values():
                name = str(meta.get("name") or "<unknown>")
                excluded_summary[name] = excluded_summary.get(name, 0) + 1

        log.info(
            "[FridaMuncher] Detached %d Frida session(s); Sysmon bridge events=%d "
            "by_id=%s; excluded_descendants=%s.",
            len(sessions),
            self.sysmon_events_seen,
            dict(sorted(self.sysmon_event_counts.items())),
            dict(sorted(excluded_summary.items())),
        )
        stop_event = self._emit_evidence(
            "controller_stop", sessions=len(sessions),
            sysmon_events=self.sysmon_events_seen,
            sysmon_by_id=dict(sorted(self.sysmon_event_counts.items())),
            excluded_descendants=dict(sorted(excluded_summary.items())),
        )
        self.stopped_wall = stop_event.get("wall_time") if isinstance(stop_event, dict) else time.time()
        self._write_p3_run_marker("stopped")
        self._write_p3_runtime_report(
            session_count=len(sessions),
            excluded_summary=dict(sorted(excluded_summary.items())),
        )
        return True
