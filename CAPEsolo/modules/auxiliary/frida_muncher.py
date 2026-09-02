import configparser
import json
import logging
import os
import struct
import subprocess
import threading
import time
import uuid
from pathlib import Path

import frida
import psutil

from lib.common.abstracts import Auxiliary
from lib.common.frida_version import PRODUCT_VERSION

try:
    from lib.common.sysmon_bridge import SysmonRealtimeBridge
except Exception:
    SysmonRealtimeBridge = None

try:
    from lib.common.pcap_task_client import PcapTaskClient
except Exception:
    PcapTaskClient = None

try:
    from lib.common.frida_profile_resolver import resolve_profile
except Exception:
    resolve_profile = None

try:
    from lib.common.frida_lifecycle_policy import (
        advance_active_observation,
        child_attach_decision,
        child_prewarm_decision,
        child_priority_decision,
        detect_capemon_ready_signal,
        normalize_child_attach_policy,
    )
except Exception:
    advance_active_observation = None
    child_attach_decision = None
    child_prewarm_decision = None
    child_priority_decision = None
    detect_capemon_ready_signal = None
    normalize_child_attach_policy = None

log = logging.getLogger(__name__)


class FridaMuncher(Auxiliary):
    """
    CAPEsolo + Frida P3.2.3.14 lifecycle/provenance controller, built on the validated P2/P2.1 Hybrid core.

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

    P3.2.3.14 profile selection:
        frida_profile=auto      # conservative resolver; generic fallback
        frida_profile=generic   # explicit safe generic mode
        frida_profile=blackenergy21  # explicit compatibility profile
    """

    # Run before other default-priority auxiliaries.  Besides warming Frida
    # earlier, this makes the ResultServer preflight observe only files left by
    # a previous analysis instead of files just created by DigiSig in this run.
    start_priority = 100

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
        # P3.2.3: root priority is bounded. Short-lived staging roots must not
        # block a viable child from reaching Frida instrumentation.
        self.root_instrumentation_failed = threading.Event()
        self.root_identity = None

        # P3.2.3.4: acquire the Frida local device before the malware root is
        # launched and keep attach RPCs bounded.  In P3.2.3 the first
        # get_local_device() on a child could consume several seconds, while a
        # blocking device.attach() could outlive a short-lived target.
        self.frida_device = None
        self.frida_device_error = None
        self.frida_device_acquire_ms = None
        self.frida_device_ready = threading.Event()
        self.frida_device_lock = threading.RLock()
        self.frida_device_thread = None
        self.attach_worker_threads = []

        # P3.2.3.4: split Frida agent injection from script installation.  The
        # agent may begin attaching as soon as CAPEMON is mapped, while all JS
        # hook scripts remain deferred until CAPEMON reports readiness.  This
        # preserves CAPEMON-first hook ownership but recovers the sub-second
        # window lost by waiting for hook_set_complete before device.attach().
        self.early_attach_lock = threading.RLock()
        self.early_attach_tickets = {}

        # P3.2.3.5 preloads JavaScript source before malware execution and can
        # configure the small injection tracker before the larger general
        # anti-evasion script in short-lived child/injected processes.
        self.script_source_cache = {}
        self.script_source_prewarm_result = {}

        # Optional injector-path prewarm uses a short-lived, controlled Windows
        # process owned by the sandbox itself.  It never targets the malware and
        # is completed before normal process enrollment.  This is useful for
        # warming Frida's cross-bitness helper on 64-bit Windows -> x86 targets.
        self.frida_injector_prewarm_thread = None
        self.frida_injector_prewarm_ready = threading.Event()
        self.frida_injector_prewarm_results = {}

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
        # EID3/EID22 are retained separately from the bounded P3 controller
        # ledger. They are wire-correlation evidence, not Frida hook events.
        self.sysmon_network_events = []
        self.sysmon_network_events_dropped = 0
        self.sysmon_network_event_limit = 20000
        self.sysmon_final_drain = {
            "status": "not_run",
            "timeout_seconds": 0.0,
            "quiet_period_seconds": 0.0,
            "events_added": 0,
        }

        # External capture is owned by the Ubuntu/INetSim VM. The client state
        # is embedded in the runtime report and also written to pcap_runtime.json.
        self.pcap_client = None
        self.pcap_runtime = {
            "schema": "capesolo-pcap-runtime/1.2",
            "configured": False,
            "status": "disabled",
            "errors": [],
        }

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
        self.result_storage_preflight = {}

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

        if self.profile_request.lower() in {"auto", ""}:
            # P3.2.3 never scans sibling samples before the actual root is
            # known. Start from the safe generic policy, then exact-root
            # revalidate while CAPE still owns the freshly launched target.
            self.profile_selection = {
                "requested": self.profile_request or "auto",
                "selected": "generic",
                "source": "safe_pre_root",
                "score": 0,
                "candidate": None,
                "reasons": ["awaiting_exact_root"],
            }
            self.profile_selection_provisional = dict(self.profile_selection)
        else:
            self.profile_selection = {
                "requested": self.profile_request,
                "selected": self.profile_request,
                "source": "explicit",
                "score": None,
                "candidate": None,
                "reasons": ["explicit_profile"],
            }
            self.profile_selection_provisional = dict(self.profile_selection)

        self.profile_name = str(
            self.profile_selection.get("selected") or "generic"
        ).strip() or "generic"
        self.profile = self._load_profile(self.profile_name)

        target_cfg = dict(self.profile.get("target", {}) or {})
        gate_cfg = dict(self.profile.get("gate", {}) or {})
        features_cfg = dict(self.profile.get("features", {}) or {})

        # Optional explicit target name. Empty means: select the new process
        # launched from CAPE's curdir, instead of matching a hard-coded name.
        explicit_target = str(self.options.get("frida_target", "") or "").strip()
        # P3.2.3: an auto-selected profile is provisional until the real root
        # executable is observed. Do not let a sibling file in the malware
        # directory constrain root discovery through that profile's target name.
        if self.profile_request.lower() in {"", "auto"}:
            self.target_name = explicit_target
        else:
            self.target_name = explicit_target or str(target_cfg.get("name", "") or "").strip()

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

        # P3.2.3.4: a process-wide Frida exception handler is a diagnostic
        # instrument, not a prerequisite for ordinary hooks. Keep it opt-in so
        # generic short-lived samples do not pay exception symbolization and
        # backtrace cost during an access-violation storm.
        self.exception_diagnostics = self._as_bool(
            self.options.get(
                "frida_exception_diagnostics",
                features_cfg.get("exception_diagnostics", False),
            )
        )
        self.child_exception_diagnostics = self._as_bool(
            self.options.get(
                "frida_child_exception_diagnostics",
                features_cfg.get("child_exception_diagnostics", False),
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
            self.attach_timeout = max(
                0.5,
                float(
                    self.options.get(
                        "frida_attach_timeout",
                        self.profile.get("attach_timeout", 4.0),
                    )
                ),
            )
        except Exception:
            self.attach_timeout = 4.0

        # A cross-bitness child attach may spend several seconds in Frida's
        # helper even after the helper process has appeared.  Keep the root
        # budget short, but give descendants a separate bounded budget and a
        # one-time extension when helper activity proves that the same RPC is
        # still making progress.  We never launch a concurrent attach RPC.
        try:
            self.child_attach_timeout = max(
                self.attach_timeout,
                float(
                    self.options.get(
                        "frida_child_attach_timeout",
                        self.profile.get("child_attach_timeout", 8.0),
                    )
                ),
            )
        except Exception:
            self.child_attach_timeout = max(self.attach_timeout, 8.0)

        try:
            self.attach_helper_extension = max(
                0.0,
                float(
                    self.options.get(
                        "frida_attach_helper_extension",
                        self.profile.get("attach_helper_extension", 4.0),
                    )
                ),
            )
        except Exception:
            self.attach_helper_extension = 4.0

        try:
            self.attach_poll_interval = min(
                0.25,
                max(
                    0.02,
                    float(
                        self.options.get(
                            "frida_attach_poll_interval",
                            self.profile.get("attach_poll_interval", 0.05),
                        )
                    ),
                ),
            )
        except Exception:
            self.attach_poll_interval = 0.05

        try:
            self.attach_retry_delay = max(
                0.0,
                float(
                    self.options.get(
                        "frida_attach_retry_delay",
                        self.profile.get("attach_retry_delay", 0.15),
                    )
                ),
            )
        except Exception:
            self.attach_retry_delay = 0.15

        try:
            self.frida_device_wait_timeout = max(
                0.1,
                float(
                    self.options.get(
                        "frida_device_wait_timeout",
                        self.profile.get("frida_device_wait_timeout", 1.0),
                    )
                ),
            )
        except Exception:
            self.frida_device_wait_timeout = 1.0

        self.frida_device_prewarm = self._as_bool(
            self.options.get(
                "frida_device_prewarm",
                self.profile.get("frida_device_prewarm", True),
            )
        )

        # P3.2.3.4 early-agent / deferred-hooks controls.  Default remains
        # conservative in code; the generic profile explicitly opts in.
        self.early_agent_attach = self._as_bool(
            self.options.get(
                "frida_early_agent_attach",
                self.profile.get("early_agent_attach", False),
            )
        )
        raw_roles = self.options.get(
            "frida_early_agent_roles",
            self.profile.get("early_agent_roles", ["root", "injected"]),
        )
        if isinstance(raw_roles, str):
            raw_roles = [x.strip() for x in raw_roles.replace(";", ",").split(",") if x.strip()]
        self.early_agent_roles = {str(x).strip().lower() for x in (raw_roles or []) if str(x).strip()}
        if not self.early_agent_roles:
            self.early_agent_roles = {"root", "injected"}

        # P3.2.3.5 child fast path.  Source is cached before malware launch and
        # the lightweight tracker is loaded/configured before the general
        # anti-evasion agent.  This does not move JS ahead of CAPEMON-ready.
        self.script_source_prewarm = self._as_bool(
            self.options.get(
                "frida_script_source_prewarm",
                self.profile.get("script_source_prewarm", True),
            )
        )
        self.child_fast_path = self._as_bool(
            self.options.get(
                "frida_child_fast_path",
                self.profile.get("child_fast_path", False),
            )
        )
        raw_fast_scripts = self.options.get(
            "frida_child_fast_scripts",
            self.profile.get("child_fast_scripts", ["process_injection_tracker.js"]),
        )
        self.child_fast_scripts = self._as_name_tuple(
            raw_fast_scripts,
            default=("process_injection_tracker.js",),
        )
        try:
            self.child_full_ready_timeout = min(5.0, max(
                0.1,
                float(self.options.get(
                    "frida_child_full_ready_timeout",
                    self.profile.get("child_full_ready_timeout", 0.75),
                )),
            ))
        except Exception:
            self.child_full_ready_timeout = 0.75

        # P3.2.3.7 keeps CAPEMON as the first and uninterrupted observer of a
        # newly-created child. The generic adaptive policy waits for a bounded
        # CAPEMON-exclusive *active-time* window before starting Frida's agent
        # attach. Scheduler/VM stalls are reported but do not consume this
        # window. A
        # short-lived child therefore completes without attach interference,
        # while a long-lived child still receives Frida instrumentation.  This
        # is intentionally family-agnostic: no image name, hash or sample path
        # is used in the decision.
        raw_child_policy = self.options.get(
            "frida_child_attach_policy",
            self.profile.get("child_attach_policy", "immediate"),
        )
        if normalize_child_attach_policy is not None:
            self.child_attach_policy = normalize_child_attach_policy(
                raw_child_policy, default="immediate"
            )
        else:
            candidate = str(raw_child_policy or "immediate").strip().lower()
            self.child_attach_policy = (
                candidate
                if candidate in {"adaptive", "immediate", "capemon_only"}
                else "immediate"
            )
        try:
            self.child_capemon_exclusive_window = min(10.0, max(
                0.0,
                float(self.options.get(
                    "frida_child_capemon_exclusive_window",
                    self.profile.get("child_capemon_exclusive_window", 3.0),
                )),
            ))
        except Exception:
            self.child_capemon_exclusive_window = 3.0
        try:
            self.child_observation_max_tick = min(2.0, max(
                0.05,
                float(self.options.get(
                    "frida_child_observation_max_tick",
                    self.profile.get("child_observation_max_tick", 0.25),
                )),
            ))
        except Exception:
            self.child_observation_max_tick = 0.25
        self.child_fast_only = self._as_bool(
            self.options.get(
                "frida_child_fast_only",
                self.profile.get("child_fast_only", False),
            )
        )

        self.frida_injector_prewarm = self._as_bool(
            self.options.get(
                "frida_injector_prewarm",
                self.profile.get("frida_injector_prewarm", False),
            )
        )
        self.child_require_prewarmed_arch = self._as_bool(
            self.options.get(
                "frida_child_require_prewarmed_arch",
                self.profile.get("child_require_prewarmed_arch", True),
            )
        )
        raw_arches = self.options.get(
            "frida_injector_prewarm_arches",
            self.profile.get("frida_injector_prewarm_arches", ["x86"]),
        )
        if isinstance(raw_arches, str):
            raw_arches = [x.strip() for x in raw_arches.replace(";", ",").split(",") if x.strip()]
        self.frida_injector_prewarm_arches = tuple(
            x for x in (str(a).strip().lower() for a in (raw_arches or []))
            if x in {"x86", "x64"}
        ) or ("x86",)
        try:
            self.frida_injector_prewarm_timeout = max(0.5, float(
                self.options.get(
                    "frida_injector_prewarm_timeout",
                    self.profile.get("frida_injector_prewarm_timeout", 3.0),
                )
            ))
        except Exception:
            self.frida_injector_prewarm_timeout = 3.0

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
                    self.profile.get("child_capemon_grace", 2.5),
                )
            )
        except Exception:
            self.child_capemon_grace = 2.5

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

        try:
            self.child_root_priority_window = max(
                0.0,
                float(
                    self.options.get(
                        "frida_child_root_priority_window",
                        self.profile.get("child_root_priority_window", 0.35),
                    )
                ),
            )
        except Exception:
            self.child_root_priority_window = 0.35

        try:
            self.capemon_ready_log_tail_bytes = max(
                32768,
                int(
                    self.options.get(
                        "frida_capemon_ready_log_tail_bytes",
                        self.profile.get("capemon_ready_log_tail_bytes", 262144),
                    )
                ),
            )
        except Exception:
            self.capemon_ready_log_tail_bytes = 262144

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
                self.profile.get("sysmon_event_ids", [1, 3, 5, 8, 22, 25]),
            ),
            default=(1, 3, 5, 8, 22, 25),
        )

        try:
            self.sysmon_network_event_limit = max(
                100,
                int(
                    self.options.get(
                        "pcap_sysmon_network_event_limit",
                        self.profile.get("sysmon_network_event_limit", 20000),
                    )
                ),
            )
        except Exception:
            self.sysmon_network_event_limit = 20000

        try:
            self.sysmon_final_drain_timeout = max(
                0.0,
                min(
                    10.0,
                    float(
                        self.options.get(
                            "frida_sysmon_final_drain_timeout",
                            self.profile.get("sysmon_final_drain_timeout", 2.0),
                        )
                    ),
                ),
            )
        except Exception:
            self.sysmon_final_drain_timeout = 2.0
        try:
            self.sysmon_final_drain_quiet_period = max(
                0.1,
                min(
                    self.sysmon_final_drain_timeout or 0.1,
                    float(
                        self.options.get(
                            "frida_sysmon_final_drain_quiet_period",
                            self.profile.get("sysmon_final_drain_quiet_period", 0.5),
                        )
                    ),
                ),
            )
        except Exception:
            self.sysmon_final_drain_quiet_period = 0.5

        pcap_cfg = dict(self.profile.get("pcap_capture", {}) or {})

        def pcap_option(name, default=None):
            for key in ("pcap_" + name, "frida_pcap_" + name):
                if key in self.options:
                    return self.options.get(key)
            return default

        self.pcap_capture_enabled = self._as_bool(
            pcap_option("capture_enabled", pcap_cfg.get("enabled", False))
        )
        self.pcap_agent_url = str(
            pcap_option("agent_url", pcap_cfg.get("agent_url", "http://192.168.56.2:54321"))
            or ""
        ).strip()
        self.pcap_agent_token = str(
            pcap_option("agent_token", pcap_cfg.get("agent_token", "")) or ""
        )
        self.pcap_guest_ip = str(
            pcap_option("guest_ip", pcap_cfg.get("guest_ip", "auto")) or "auto"
        ).strip()
        self.pcap_capture_fetch = self._as_bool(
            pcap_option("capture_fetch", pcap_cfg.get("fetch", True))
        )
        self.pcap_capture_required = self._as_bool(
            pcap_option("capture_required", pcap_cfg.get("required", False))
        )
        try:
            self.pcap_capture_duration = max(
                10,
                min(900, int(pcap_option("capture_duration", pcap_cfg.get("duration", 240)))),
            )
        except Exception:
            self.pcap_capture_duration = 240
        try:
            self.pcap_agent_timeout = max(
                0.5,
                min(30.0, float(pcap_option("agent_timeout", pcap_cfg.get("timeout", 5.0)))),
            )
        except Exception:
            self.pcap_agent_timeout = 5.0
        try:
            self.pcap_clock_sample_interval = max(
                5.0,
                min(
                    60.0,
                    float(
                        pcap_option(
                            "clock_sample_interval",
                            pcap_cfg.get("clock_sample_interval", 10.0),
                        )
                    ),
                ),
            )
        except Exception:
            self.pcap_clock_sample_interval = 10.0

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

    def _check_result_storage_preflight(self):
        """Detect known shared-output collisions without mutating CAPE evidence."""
        if self.p3_runtime_report_path is None:
            return {}
        base = self.p3_runtime_report_path.parent
        collision_paths = [
            "aux_/DigiSig.json",
            "evtx/evtx.zip",
            "tlsdump/tlsdump.log",
        ]
        existing = []
        for rel in collision_paths:
            try:
                if (base / rel).exists():
                    existing.append(rel)
            except OSError:
                pass
        result = {
            "analysis_dir": str(base),
            "collision_candidates_present": existing,
            "clean": not existing,
        }
        if existing:
            log.warning(
                "[FridaMuncher] Shared ResultServer paths already exist before this run: %s. "
                r"Use tools\p3_prepare_analysis.py --apply before the next analysis to avoid discarded uploads.",
                existing,
            )
            self._emit_evidence(
                "result_storage_preflight", severity="warning", **result
            )
        else:
            self._emit_evidence("result_storage_preflight", **result)
        self.result_storage_preflight = result
        return result

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
            "version": PRODUCT_VERSION,
            "run_id": self.run_id,
            "run_started_wall": self.started_wall,
            "run_stopped_wall": self.stopped_wall,
            "profile": {
                "request": self.profile_request,
                "selected": self.profile_name,
                "selection": self._p3_json_safe(self.profile_selection),
                "provisional_selection": self._p3_json_safe(self.profile_selection_provisional),
            },
            "target_pid": self.target_pid,
            "sample_dir": self.analysis_dir,
            "results_dir": str(self.p3_runtime_report_path.parent) if self.p3_runtime_report_path else None,
            # P3.2 uses analysis_dir for CAPEsolo result storage; sample_dir is
            # the malware working directory.
            "analysis_dir": str(self.p3_runtime_report_path.parent) if self.p3_runtime_report_path else None,
            "gate_mode": self.gate_mode,
            "anti_analysis_mode": self.anti_analysis_mode,
            "exception_diagnostics": self.exception_diagnostics,
            "child_exception_diagnostics": self.child_exception_diagnostics,
            "follow_children": self.follow_children,
            "follow_injected_targets": self.follow_injected_targets,
            "result_storage_preflight": self._p3_json_safe(self.result_storage_preflight),
            "lifecycle": {
                "root_ready": bool(self.root_ready.is_set()),
                "root_failed": bool(self.root_instrumentation_failed.is_set()),
                "root_identity": self._p3_json_safe(self.root_identity),
                "child_root_priority_window": self.child_root_priority_window,
                "capemon_ready_log_tail_bytes": self.capemon_ready_log_tail_bytes,
                "frida_device": {
                    "prewarm_enabled": bool(self.frida_device_prewarm),
                    "ready": bool(self.frida_device_ready.is_set() and self.frida_device is not None),
                    "acquire_ms": self.frida_device_acquire_ms,
                    "error": self.frida_device_error,
                },
                "early_agent": {
                    "enabled": bool(self.early_agent_attach),
                    "roles": sorted(self.early_agent_roles),
                    "tickets": self._p3_json_safe(self._early_attach_snapshot()),
                },
                "script_loading": {
                    "source_prewarm_enabled": bool(self.script_source_prewarm),
                    "source_prewarm": self._p3_json_safe(self.script_source_prewarm_result),
                    "child_fast_path": bool(self.child_fast_path),
                    "child_fast_scripts": list(self.child_fast_scripts),
                    "child_full_ready_timeout": self.child_full_ready_timeout,
                    "child_fast_only": bool(self.child_fast_only),
                },
                "child_attach": {
                    "policy": self.child_attach_policy,
                    "capemon_exclusive_window": self.child_capemon_exclusive_window,
                    "time_basis": "active_observation",
                    "observation_max_tick": self.child_observation_max_tick,
                    "require_prewarmed_arch": bool(self.child_require_prewarmed_arch),
                },
                "injector_prewarm": {
                    "enabled": bool(self.frida_injector_prewarm),
                    "arches": list(self.frida_injector_prewarm_arches),
                    "completed": bool(self.frida_injector_prewarm_ready.is_set()),
                    "ready": (
                        self.frida_injector_prewarm_results.get("status") == "ready"
                        if isinstance(self.frida_injector_prewarm_results, dict)
                        else False
                    ),
                    "usable_arches": list(self._injector_usable_arches()),
                    "results": self._p3_json_safe(self.frida_injector_prewarm_results),
                },
                "attach_timeout": self.attach_timeout,
                "child_attach_timeout": self.child_attach_timeout,
                "attach_helper_extension": self.attach_helper_extension,
                "attach_poll_interval": self.attach_poll_interval,
                "attach_retry_delay": self.attach_retry_delay,
            },
            "sysmon": {
                "bridge_active_at_stop": bool(self.sysmon_bridge_active),
                "bridge_active_at_report": bool(self.sysmon_bridge_active),
                "bridge_ever_active": bool(self.sysmon_ever_active),
                "events_seen": self.sysmon_events_seen,
                "by_id": dict(sorted(self.sysmon_event_counts.items())),
                "network_events": self._p3_json_safe(self.sysmon_network_events),
                "network_events_dropped": int(self.sysmon_network_events_dropped),
                "final_drain": self._p3_json_safe(self.sysmon_final_drain),
            },
            "pcap": self._p3_json_safe(self.pcap_runtime),
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
        """Write a small atomic pointer to the current analysis attempt."""
        if self.p3_runtime_report_path is None or not self.run_id:
            return
        try:
            base = self.p3_runtime_report_path.parent
            marker = base / "p3_current_run.json"
            payload = {
                "schema": "capesolo-frida-p3-run/1",
                "version": PRODUCT_VERSION,
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
            log.debug("[FridaMuncher] Failed writing %s run marker", PRODUCT_VERSION, exc_info=True)

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
                "exception_diagnostics": False,
                "child_exception_diagnostics": False,
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
            "child_root_priority_window": 0.35,
            "capemon_ready_log_tail_bytes": 262144,
            "injection_capemon_detect_timeout": 2.0,
            "injection_capemon_grace": 0.25,
            "injection_min_signals": 2,
            "injection_signal_window": 5.0,
            "sysmon_channel": "Microsoft-Windows-Sysmon/Operational",
            "sysmon_event_ids": [1, 3, 5, 8, 22, 25],
            "sysmon_network_event_limit": 20000,
            "sysmon_final_drain_timeout": 2.0,
            "sysmon_final_drain_quiet_period": 0.5,
            "pcap_capture": {
                "enabled": False,
                "agent_url": "http://192.168.56.2:54321",
                "agent_token": "",
                "guest_ip": "auto",
                "duration": 240,
                "fetch": True,
                "required": False,
                "timeout": 5.0,
                "clock_sample_interval": 10.0,
            },
            "sysmon_injected_source_policy": "correlate",
            "sysmon_tampering_init_window": 3.0,
            "max_sessions": 16,
            "attach_retries": 2,
            "attach_timeout": 4.0,
            "child_attach_timeout": 8.0,
            "attach_helper_extension": 4.0,
            "attach_poll_interval": 0.05,
            "attach_retry_delay": 0.15,
            "frida_device_prewarm": True,
            "frida_device_wait_timeout": 1.0,
            "early_agent_attach": False,
            "early_agent_roles": ["root", "injected"],
            "script_source_prewarm": True,
            "child_fast_path": False,
            "child_fast_scripts": ["process_injection_tracker.js"],
            "child_full_ready_timeout": 0.75,
            "child_attach_policy": "adaptive",
            "child_capemon_exclusive_window": 3.0,
            "child_observation_max_tick": 0.25,
            "child_fast_only": False,
            "frida_injector_prewarm": False,
            "child_require_prewarmed_arch": True,
            "frida_injector_prewarm_arches": ["x86"],
            "frida_injector_prewarm_timeout": 3.0,
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
    def _as_name_tuple(value, default=()):
        """Normalize an ordered profile list of script basenames."""
        if value is None:
            items = list(default)
        elif isinstance(value, (list, tuple)):
            items = value
        else:
            items = str(value).replace(";", ",").split(",")
        out = []
        for item in items:
            name = os.path.basename(str(item).strip()).lower()
            if name and name not in out:
                out.append(name)
        if out:
            return tuple(out)
        return tuple(
            os.path.basename(str(item).strip()).lower()
            for item in default
            if str(item).strip()
        )

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

    def _tail_analysis_log(self):
        """Read a bounded tail of analysis.log for CAPEMON readiness signals."""
        if self.p3_runtime_report_path is None:
            return ""
        path = self.p3_runtime_report_path.parent / "analysis.log"
        try:
            with path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                start = max(0, size - int(self.capemon_ready_log_tail_bytes))
                fh.seek(start, os.SEEK_SET)
                return fh.read().decode("utf-8", errors="replace")
        except OSError:
            return ""

    def _capemon_ready_signal(self, pid):
        if detect_capemon_ready_signal is None:
            return None
        try:
            return detect_capemon_ready_signal(self._tail_analysis_log(), int(pid))
        except Exception:
            return None

    def _wait_for_capemon_ready_or_grace(self, pid, create_time, grace, mapped_path):
        """Use CAPEMON log readiness to release early; grace remains a fallback cap."""
        grace = max(0.0, float(grace or 0.0))
        if grace <= 0:
            return True
        deadline = time.monotonic() + grace
        log.info(
            "[FridaMuncher][pid=%d] Waiting up to %.2fs for CAPEMON-ready; "
            "fixed grace is fallback-only.",
            pid, grace,
        )
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            if not self._identity_still_alive(pid, create_time):
                return False
            self._observe_early_attach_progress(pid)
            signal = self._capemon_ready_signal(pid)
            if signal:
                now_mono = time.monotonic()
                with self.session_lock:
                    meta = self.lineage.get(pid)
                    if meta is not None:
                        meta["capemon_ready_monotonic"] = now_mono
                        meta["capemon_ready_signal"] = signal
                self._emit_evidence(
                    "capemon_ready", pid=pid, status="detected", signal=signal,
                    mapping=mapped_path,
                )
                log.info(
                    "[FridaMuncher][pid=%d] CAPEMON-ready signal=%s; proceeding to lifecycle policy.",
                    pid, signal,
                )
                return True
            time.sleep(0.05)
        if self.stop_event.is_set():
            return False
        self._emit_evidence(
            "capemon_ready", pid=pid, status="grace_elapsed", signal=None,
            grace=grace, mapping=mapped_path,
        )
        return self._identity_still_alive(pid, create_time)

    def _root_is_alive(self):
        identity = self.root_identity
        if not identity:
            return False
        pid, create_time = identity
        return self._identity_still_alive(pid, create_time)

    def _wait_for_root_priority(self, pid, create_time):
        """Bound root priority without sacrificing short-lived child coverage."""
        if not self.child_wait_for_root_ready or self.root_ready.is_set():
            return True
        started = time.monotonic()
        while not self.stop_event.is_set():
            elapsed = time.monotonic() - started
            root_alive = self._root_is_alive()
            root_failed = self.root_instrumentation_failed.is_set()
            if child_priority_decision is not None:
                decision = child_priority_decision(
                    root_ready=self.root_ready.is_set(),
                    root_alive=root_alive,
                    root_failed=root_failed,
                    elapsed=elapsed,
                    priority_window=self.child_root_priority_window,
                )
            else:
                if self.root_ready.is_set():
                    decision = "root_ready"
                elif root_failed or not root_alive:
                    decision = "promote_root_unavailable"
                elif elapsed >= self.child_root_priority_window:
                    decision = "promote_priority_window_elapsed"
                else:
                    decision = "wait"

            if decision == "wait":
                if not self._identity_still_alive(pid, create_time):
                    return False
                self.root_ready.wait(timeout=0.05)
                continue

            if decision.startswith("promote_"):
                self._emit_evidence(
                    "child_promoted", pid=pid, reason=decision,
                    root_pid=(self.root_identity or (None, None))[0],
                    waited_ms=round(elapsed * 1000.0, 3),
                )
                log.info(
                    "[FridaMuncher][pid=%d] Child promoted to independent Frida attach: %s after %.0fms.",
                    pid, decision, elapsed * 1000.0,
                )
            return True
        return False

    def _wait_for_child_attach_policy(self, pid, create_time, exe_path=None):
        """Give CAPEMON an exclusive window before touching a child with Frida.

        Returns the terminal policy decision.  ``attach_now`` is the only
        result that permits an agent attach. Adaptive elapsed time advances
        only while the policy worker is being scheduled; long VM/Python stalls
        are accounted separately and never consume the CAPEMON-owned window.
        """
        policy = self.child_attach_policy
        window = self.child_capemon_exclusive_window
        entered = time.monotonic()
        wall_started = entered
        with self.session_lock:
            meta = self.lineage.get(pid)
            if isinstance(meta, dict):
                ready_at = meta.get("capemon_ready_monotonic")
                meta["child_attach_policy"] = policy
                meta["child_capemon_exclusive_window"] = window
                meta["child_attach_time_basis"] = "active_observation"
                meta["child_observation_max_tick"] = self.child_observation_max_tick
            else:
                ready_at = None
        if ready_at is not None:
            try:
                wall_started = min(entered, float(ready_at))
            except Exception:
                pass

        active_elapsed = 0.0
        scheduler_gap_elapsed = 0.0
        scheduler_gap_count = 0
        last_tick = entered
        pre_policy_delay = max(0.0, entered - wall_started)

        self._emit_evidence(
            "child_attach_policy", pid=pid, role="child", policy=policy,
            exclusive_window=window, status="started",
            time_basis="active_observation",
            observation_max_tick=self.child_observation_max_tick,
            pre_policy_delay_ms=round(pre_policy_delay * 1000.0, 3),
        )
        while not self.stop_event.is_set():
            now = time.monotonic()
            delta = max(0.0, now - last_tick)
            last_tick = now
            if advance_active_observation is not None:
                active_elapsed, scheduler_gap_elapsed, stalled = advance_active_observation(
                    active_elapsed=active_elapsed,
                    scheduler_gap_elapsed=scheduler_gap_elapsed,
                    delta=delta,
                    max_tick=self.child_observation_max_tick,
                )
            elif delta > self.child_observation_max_tick:
                scheduler_gap_elapsed += delta
                stalled = True
            else:
                active_elapsed += delta
                stalled = False
            if stalled:
                scheduler_gap_count += 1
                self._emit_evidence(
                    "child_attach_scheduler_gap", severity="warning",
                    pid=pid, role="child", gap_ms=round(delta * 1000.0, 3),
                    active_observed_ms=round(active_elapsed * 1000.0, 3),
                )

            alive = self._identity_still_alive(pid, create_time)
            wall_elapsed = max(0.0, now - wall_started)
            if child_attach_decision is not None:
                decision = child_attach_decision(
                    policy=policy,
                    alive=alive,
                    elapsed=active_elapsed,
                    exclusive_window=window,
                )
            elif not alive:
                decision = "target_exited_capemon_observed"
            elif policy == "capemon_only":
                decision = "capemon_only"
            elif policy == "immediate" or active_elapsed >= window:
                decision = "attach_now"
            else:
                decision = "wait_exclusive_window"

            if decision == "wait_exclusive_window":
                self.stop_event.wait(min(0.05, max(0.0, window - active_elapsed)))
                continue

            target_arch = self._pe_architecture(exe_path)
            usable_arches = self._injector_usable_arches()
            if decision == "attach_now" and policy == "adaptive":
                gate_decision, target_arch, usable_arches = self._child_prewarm_gate(exe_path)
                if gate_decision != "attach_allowed":
                    decision = gate_decision

            self._emit_evidence(
                "child_attach_policy", pid=pid, role="child", policy=policy,
                exclusive_window=window, status=decision,
                time_basis="active_observation",
                active_observed_ms=round(active_elapsed * 1000.0, 3),
                wall_observed_ms=round(wall_elapsed * 1000.0, 3),
                scheduler_gap_ms=round(scheduler_gap_elapsed * 1000.0, 3),
                scheduler_gap_count=scheduler_gap_count,
                pre_policy_delay_ms=round(pre_policy_delay * 1000.0, 3),
                target_arch=target_arch,
                usable_prewarm_arches=list(usable_arches),
            )
            with self.session_lock:
                meta = self.lineage.get(pid)
                if isinstance(meta, dict):
                    meta["child_active_observed_ms"] = round(active_elapsed * 1000.0, 3)
                    meta["child_wall_observed_ms"] = round(wall_elapsed * 1000.0, 3)
                    meta["child_scheduler_gap_ms"] = round(scheduler_gap_elapsed * 1000.0, 3)
                    meta["child_scheduler_gap_count"] = scheduler_gap_count
                    meta["child_pre_policy_delay_ms"] = round(pre_policy_delay * 1000.0, 3)
                    meta["target_arch"] = target_arch
                    meta["child_attach_policy_decision"] = decision
            if decision == "attach_now":
                log.info(
                    "[FridaMuncher][pid=%d] Child survived %.0fms active CAPEMON-exclusive window (wall=%.0fms, scheduler_gap=%.0fms); Frida attach may proceed.",
                    pid, active_elapsed * 1000.0, wall_elapsed * 1000.0,
                    scheduler_gap_elapsed * 1000.0,
                )
            elif decision == "capemon_only":
                log.info(
                    "[FridaMuncher][pid=%d] Child retained as CAPEMON/Sysmon-only by policy.",
                    pid,
                )
            elif decision == "capemon_only_prewarm_unavailable":
                log.warning(
                    "[FridaMuncher][pid=%d] Child retained as CAPEMON/Sysmon-only: target_arch=%s has no usable injector prewarm.",
                    pid, target_arch or "unknown",
                )
            else:
                log.info(
                    "[FridaMuncher][pid=%d] Short-lived child exited during CAPEMON-exclusive window; Frida attach intentionally skipped.",
                    pid,
                )
            return decision
        return "stop_requested"

    def _option_is_explicit(self, key):
        try:
            return key in self.options and str(self.options.get(key, "")).strip() != ""
        except Exception:
            return False

    def _reselect_profile_for_root(self, exe_path):
        """Revalidate auto profile selection against the actual root executable."""
        if self.profile_request.lower() not in {"", "auto"} or resolve_profile is None or not exe_path:
            return False
        try:
            selection = resolve_profile(
                profile_dir=Path.cwd() / "data" / "frida_profiles",
                analysis_dir=self.analysis_dir,
                requested="auto",
                target_hint=os.path.basename(exe_path),
                fallback="generic",
                target_path=exe_path,
            )
        except Exception:
            log.exception("[FridaMuncher] Exact-root profile revalidation failed; retaining current profile")
            return False

        previous = self.profile_name
        self.profile_selection = selection
        selected = str(selection.get("selected") or "generic").strip() or "generic"
        self.profile_name = selected
        self.profile = self._load_profile(selected)
        gate_cfg = dict(self.profile.get("gate", {}) or {})
        features_cfg = dict(self.profile.get("features", {}) or {})

        if not self._option_is_explicit("frida_gate_mode"):
            self.gate_mode = str(gate_cfg.get("mode", "none") or "none").strip().lower()
        if self.gate_mode not in {"none", "patched_entry"}:
            self.gate_mode = "none"
        if not self._option_is_explicit("frida_restore_hex"):
            self.restore_hex = str(gate_cfg.get("restore_hex", "") or "").replace(" ", "").strip().lower()
        if not self._option_is_explicit("frida_expected_gate_hex"):
            self.expected_gate_hex = str(gate_cfg.get("expected_hex", "") or "").replace(" ", "").strip().lower()
        if not self._option_is_explicit("frida_gate_delta"):
            try:
                self.gate_delta = int(str(gate_cfg.get("delta", 0)), 0)
            except Exception:
                self.gate_delta = 0
        if not self._option_is_explicit("frida_enable_legacy_int2a"):
            self.enable_legacy_int2a = self._as_bool(features_cfg.get("legacy_int2a", False))
        if not self._option_is_explicit("frida_exception_diagnostics"):
            self.exception_diagnostics = self._as_bool(features_cfg.get("exception_diagnostics", False))
        if not self._option_is_explicit("frida_child_exception_diagnostics"):
            self.child_exception_diagnostics = self._as_bool(features_cfg.get("child_exception_diagnostics", False))
        if not self._option_is_explicit("frida_follow_children"):
            self.follow_children = self._as_bool(features_cfg.get("follow_children", True))
        if not self._option_is_explicit("frida_private_exec_callers"):
            self.private_exec_callers = self._as_bool(features_cfg.get("private_exec_callers", True))
        if not self._option_is_explicit("frida_anti_analysis_mode"):
            self.anti_analysis_mode = str(features_cfg.get("anti_analysis_mode", "observe") or "observe").strip().lower()
        if self.anti_analysis_mode not in {"observe", "bypass"}:
            self.anti_analysis_mode = "observe"
        if not self._option_is_explicit("frida_child_anti_analysis_mode"):
            self.child_anti_analysis_mode = str(features_cfg.get("child_anti_analysis_mode", "observe") or "observe").strip().lower()
        if self.child_anti_analysis_mode not in {"observe", "bypass"}:
            self.child_anti_analysis_mode = "observe"
        if not self._option_is_explicit("frida_follow_injected_targets"):
            self.follow_injected_targets = self._as_bool(features_cfg.get("follow_injected_targets", True))
        if not self._option_is_explicit("frida_child_wait_for_root_ready"):
            self.child_wait_for_root_ready = self._as_bool(self.profile.get("child_wait_for_root_ready", True))
        if not self._option_is_explicit("frida_child_exclude_names"):
            self.child_exclude_names = self._as_name_set(features_cfg.get("child_exclude_names", []))
        if not self._option_is_explicit("frida_injected_exclude_names"):
            self.injected_exclude_names = self._as_name_set(features_cfg.get("injected_exclude_names", []))

        for option_key, attr, profile_key, default in (
            ("frida_capemon_grace", "capemon_grace", "capemon_grace", 1.5),
            ("frida_child_capemon_grace", "child_capemon_grace", "child_capemon_grace", 2.5),
            ("frida_capemon_detect_timeout", "capemon_detect_timeout", "capemon_detect_timeout", 5.0),
            ("frida_child_capemon_detect_timeout", "child_capemon_detect_timeout", "child_capemon_detect_timeout", 5.0),
            ("frida_capemon_activation_timeout", "capemon_activation_timeout", "capemon_activation_timeout", 20.0),
            ("frida_capemon_fallback_delay", "capemon_fallback_delay", "capemon_fallback_delay", 2.0),
            ("frida_child_root_ready_timeout", "child_root_ready_timeout", "child_root_ready_timeout", 10.0),
            ("frida_child_root_priority_window", "child_root_priority_window", "child_root_priority_window", 0.35),
            ("frida_attach_timeout", "attach_timeout", "attach_timeout", 4.0),
            ("frida_child_attach_timeout", "child_attach_timeout", "child_attach_timeout", 8.0),
            ("frida_attach_helper_extension", "attach_helper_extension", "attach_helper_extension", 4.0),
            ("frida_attach_poll_interval", "attach_poll_interval", "attach_poll_interval", 0.05),
            ("frida_attach_retry_delay", "attach_retry_delay", "attach_retry_delay", 0.15),
            ("frida_device_wait_timeout", "frida_device_wait_timeout", "frida_device_wait_timeout", 1.0),
            ("frida_injection_capemon_detect_timeout", "injection_capemon_detect_timeout", "injection_capemon_detect_timeout", 2.0),
            ("frida_injection_capemon_grace", "injection_capemon_grace", "injection_capemon_grace", 0.25),
        ):
            if self._option_is_explicit(option_key):
                continue
            try:
                setattr(self, attr, max(0.0, float(self.profile.get(profile_key, default))))
            except Exception:
                setattr(self, attr, default)

        # Re-apply safety bounds after exact-root profile selection.
        self.attach_timeout = max(0.5, float(self.attach_timeout))
        self.child_attach_timeout = max(self.attach_timeout, float(self.child_attach_timeout))
        self.attach_helper_extension = max(0.0, float(self.attach_helper_extension))
        self.attach_poll_interval = min(0.25, max(0.02, float(self.attach_poll_interval)))
        self.attach_retry_delay = max(0.0, float(self.attach_retry_delay))
        self.frida_device_wait_timeout = max(0.1, float(self.frida_device_wait_timeout))

        if not self._option_is_explicit("frida_device_prewarm"):
            self.frida_device_prewarm = self._as_bool(self.profile.get("frida_device_prewarm", True))
        if not self._option_is_explicit("frida_early_agent_attach"):
            self.early_agent_attach = self._as_bool(self.profile.get("early_agent_attach", False))
        if not self._option_is_explicit("frida_early_agent_roles"):
            roles = self.profile.get("early_agent_roles", ["root", "injected"])
            if isinstance(roles, str):
                roles = [x.strip() for x in roles.replace(";", ",").split(",") if x.strip()]
            self.early_agent_roles = {str(x).strip().lower() for x in (roles or []) if str(x).strip()} or {"root", "injected"}
        if not self._option_is_explicit("frida_script_source_prewarm"):
            self.script_source_prewarm = self._as_bool(self.profile.get("script_source_prewarm", True))
        if not self._option_is_explicit("frida_child_fast_path"):
            self.child_fast_path = self._as_bool(self.profile.get("child_fast_path", False))
        if not self._option_is_explicit("frida_child_fast_scripts"):
            self.child_fast_scripts = self._as_name_tuple(
                self.profile.get("child_fast_scripts", ["process_injection_tracker.js"]),
                default=("process_injection_tracker.js",),
            )
        if not self._option_is_explicit("frida_child_fast_only"):
            self.child_fast_only = self._as_bool(self.profile.get("child_fast_only", False))
        if not self._option_is_explicit("frida_child_attach_policy"):
            raw_policy = self.profile.get("child_attach_policy", "adaptive")
            if normalize_child_attach_policy is not None:
                self.child_attach_policy = normalize_child_attach_policy(raw_policy)
            else:
                candidate = str(raw_policy or "adaptive").strip().lower()
                self.child_attach_policy = (
                    candidate
                    if candidate in {"adaptive", "immediate", "capemon_only"}
                    else "adaptive"
                )
        if not self._option_is_explicit("frida_child_capemon_exclusive_window"):
            try:
                self.child_capemon_exclusive_window = min(10.0, max(
                    0.0,
                    float(self.profile.get("child_capemon_exclusive_window", 3.0)),
                ))
            except Exception:
                self.child_capemon_exclusive_window = 3.0
        if not self._option_is_explicit("frida_child_observation_max_tick"):
            try:
                self.child_observation_max_tick = min(2.0, max(
                    0.05,
                    float(self.profile.get("child_observation_max_tick", 0.25)),
                ))
            except Exception:
                self.child_observation_max_tick = 0.25
        if not self._option_is_explicit("frida_injector_prewarm"):
            self.frida_injector_prewarm = self._as_bool(self.profile.get("frida_injector_prewarm", False))
        if not self._option_is_explicit("frida_child_require_prewarmed_arch"):
            self.child_require_prewarmed_arch = self._as_bool(
                self.profile.get("child_require_prewarmed_arch", True)
            )

        if not self._option_is_explicit("frida_injection_min_signals"):
            try:
                self.injection_min_signals = max(1, int(self.profile.get("injection_min_signals", 2)))
            except Exception:
                self.injection_min_signals = 2
        if not self._option_is_explicit("frida_injection_signal_window"):
            try:
                self.injection_signal_window = max(0.5, float(self.profile.get("injection_signal_window", 5.0)))
            except Exception:
                self.injection_signal_window = 5.0

        if self.gate_mode == "patched_entry" and (not self.restore_hex or not self.expected_gate_hex):
            log.error(
                "[FridaMuncher] Exact-root profile %s has incomplete patched-entry bytes; disabling gate.",
                self.profile_name,
            )
            self.gate_mode = "none"

        kind = "profile_reselected" if previous != self.profile_name else "profile_revalidated"
        self._emit_evidence(
            kind, previous=previous, selected=self.profile_name,
            exact_root=exe_path, selection=selection, gate_mode=self.gate_mode,
        )
        log.info(
            "[FridaMuncher] %s exact-root profile: previous=%s selected=%s candidate=%s reasons=%s",
            PRODUCT_VERSION, previous, self.profile_name,
            selection.get("candidate"), selection.get("reasons"),
        )
        return previous != self.profile_name

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
            # P3.2.3.4: begin only the Frida agent injection at CAPEMON mapping.
            # Script creation/loading is still deferred until this function has
            # observed CAPEMON-ready and _instrument_process continues.
            self._start_early_agent_attach(
                pid, create_time, role, trigger="capemon_mapping"
            )
            return self._wait_for_capemon_ready_or_grace(
                pid, create_time, grace, mapped_path
            )

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
            "fast_ready": threading.Event(),
            "gate": threading.Event(),
            "last_gate": None,
        }
        with self.session_lock:
            self.process_events[pid] = state
        return state

    def _record_process_outcome(self, pid, role, status, **fields):
        """Store one explicit per-PID instrumentation outcome.

        Attach success is intentionally not equivalent to hooks-ready.  The
        latest outcome is mirrored into lineage for the finalizer and emitted
        as structured evidence for recovery from analysis.log.
        """
        payload = {
            "pid": pid,
            "role": role,
            "status": str(status),
        }
        payload.update(fields)
        with self.session_lock:
            meta = self.lineage.get(pid)
            if meta is not None:
                meta["frida_process_outcome"] = self._p3_json_safe(payload)
        severity = "info" if status in {
            "agent_attached_only", "hooks_ready", "fast_hooks_ready",
            "capemon_only_policy", "capemon_observed_short_lived",
            "fast_hooks_configured_unconfirmed_target_exited",
        } else "warning"
        return self._emit_evidence(
            "frida_process_outcome", severity=severity, **payload
        )

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
                    if hook == "ProcessInjectionTracker" and action == "ready":
                        state["fast_ready"].set()
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

    def _prewarm_frida_device_worker(self):
        started = time.monotonic()
        try:
            device = frida.get_local_device()
            elapsed_ms = round((time.monotonic() - started) * 1000.0, 3)
            with self.frida_device_lock:
                self.frida_device = device
                self.frida_device_error = None
                self.frida_device_acquire_ms = elapsed_ms
            self.frida_device_ready.set()
            self._emit_evidence(
                "frida_device", status="ready", acquire_ms=elapsed_ms,
            )
            log.info(
                "[FridaMuncher] Frida local device prewarmed in %.1fms.",
                elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000.0, 3)
            with self.frida_device_lock:
                self.frida_device = None
                self.frida_device_error = f"{type(exc).__name__}: {exc}"
                self.frida_device_acquire_ms = elapsed_ms
            self.frida_device_ready.set()
            self._emit_evidence(
                "frida_device", severity="warning", status="failed",
                acquire_ms=elapsed_ms, error=self.frida_device_error,
            )
            log.warning(
                "[FridaMuncher] Frida local device prewarm failed after %.1fms: %s",
                elapsed_ms, exc,
            )

    def _start_frida_device_prewarm(self, force=False):
        if not self.frida_device_prewarm and not force:
            return False
        with self.frida_device_lock:
            if self.frida_device is not None:
                self.frida_device_ready.set()
                return True
            if self.frida_device_thread is not None and self.frida_device_thread.is_alive():
                return True
            # A forced retry intentionally clears a previous failure state.
            if force and self.frida_device_ready.is_set() and self.frida_device is None:
                self.frida_device_ready.clear()
                self.frida_device_error = None
            self.frida_device_thread = threading.Thread(
                target=self._prewarm_frida_device_worker,
                name="FridaMuncher-device-prewarm",
                daemon=True,
            )
            self.frida_device_thread.start()
        return True

    def _get_cached_frida_device(self, pid):
        wait_started = time.monotonic()
        with self.frida_device_lock:
            cached = self.frida_device
        if cached is not None:
            return cached, 0.0, None

        # Prewarm is normally started before the malware root exists.  If it was
        # disabled or failed to start, begin one bounded acquisition here.
        self._start_frida_device_prewarm(force=True)
        ready = self.frida_device_ready.wait(timeout=self.frida_device_wait_timeout)
        wait_ms = round((time.monotonic() - wait_started) * 1000.0, 3)
        with self.frida_device_lock:
            device = self.frida_device
            error = self.frida_device_error
        if ready and device is not None:
            return device, wait_ms, None
        if not ready:
            error = f"device acquisition exceeded {self.frida_device_wait_timeout:.2f}s wait budget"
        elif not error:
            error = "local Frida device unavailable"
        self._emit_evidence(
            "frida_device_wait", severity="warning", pid=pid,
            status="unavailable", wait_ms=wait_ms, error=error,
        )
        return None, wait_ms, error

    @staticmethod
    def _pe_architecture(exe_path):
        """Return x86/x64 from the PE machine field without loading the file."""
        try:
            with open(str(exe_path), "rb") as handle:
                header = handle.read(64)
                if len(header) < 64 or header[:2] != b"MZ":
                    return None
                pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
                handle.seek(pe_offset)
                pe_header = handle.read(6)
            if len(pe_header) != 6 or pe_header[:4] != b"PE\x00\x00":
                return None
            machine = struct.unpack_from("<H", pe_header, 4)[0]
            return {0x014C: "x86", 0x8664: "x64"}.get(machine)
        except Exception:
            return None

    def _injector_usable_arches(self):
        result = self.frida_injector_prewarm_results
        if not isinstance(result, dict):
            return ()
        explicit = result.get("usable_arches")
        if isinstance(explicit, (list, tuple, set)):
            return tuple(sorted({str(x).strip().lower() for x in explicit if str(x).strip()}))
        arches = result.get("arches") if isinstance(result.get("arches"), dict) else {}
        return tuple(sorted(
            str(arch).strip().lower() for arch, item in arches.items()
            if isinstance(item, dict) and item.get("status") == "ready"
        ))

    def _child_prewarm_gate(self, exe_path):
        target_arch = self._pe_architecture(exe_path)
        usable_arches = self._injector_usable_arches()
        if child_prewarm_decision is not None:
            decision = child_prewarm_decision(
                require_prewarmed_arch=self.child_require_prewarmed_arch,
                prewarm_enabled=self.frida_injector_prewarm,
                target_arch=target_arch,
                requested_arches=self.frida_injector_prewarm_arches,
                usable_arches=usable_arches,
            )
        else:
            gated = (
                self.child_require_prewarmed_arch
                and self.frida_injector_prewarm
                and target_arch in self.frida_injector_prewarm_arches
            )
            decision = (
                "capemon_only_prewarm_unavailable"
                if gated and target_arch not in usable_arches
                else "attach_allowed"
            )
        return decision, target_arch, usable_arches

    def _prewarm_frida_injector_arch(self, device, arch):
        """Warm Frida's native injector/helper using a sandbox-owned process.

        This is intentionally NOT the malware target.  It exists only to pay the
        one-time cross-bitness helper startup cost before a short-lived sample is
        launched.  The process is always terminated by this method.
        """
        started = time.monotonic()
        result = {"arch": arch, "status": "skipped"}
        proc = None
        session = None
        try:
            windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
            if arch == "x86":
                exe = windir / "SysWOW64" / "cmd.exe"
            else:
                exe = windir / "System32" / "cmd.exe"
            if not exe.exists():
                result.update(status="unavailable", error=f"{exe} not found")
                return result

            creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            proc = subprocess.Popen(
                [str(exe), "/d", "/q", "/c", "ping -n 12 127.0.0.1 >nul"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            target_pid = int(proc.pid)
            attach_result = {}
            done = threading.Event()
            cancel = threading.Event()

            def attach_worker():
                try:
                    late_session = device.attach(target_pid)
                    if cancel.is_set():
                        try:
                            late_session.detach()
                        except Exception:
                            pass
                    else:
                        attach_result["session"] = late_session
                except Exception as exc:
                    attach_result["error"] = str(exc)
                    attach_result["error_type"] = type(exc).__name__
                finally:
                    done.set()

            t = threading.Thread(
                target=attach_worker,
                name=f"FridaMuncher-injector-prewarm-{arch}",
                daemon=True,
            )
            t.start()
            if not done.wait(timeout=self.frida_injector_prewarm_timeout):
                cancel.set()
                result.update(status="timeout", pid=target_pid)
                return result
            session = attach_result.get("session")
            if session is None:
                result.update(
                    status="failed", pid=target_pid,
                    error=attach_result.get("error") or "attach returned no session",
                    error_type=attach_result.get("error_type"),
                )
                return result
            result.update(status="ready", pid=target_pid)
            return result
        except Exception as exc:
            result.update(status="failed", error=str(exc), error_type=type(exc).__name__)
            return result
        finally:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
            if proc is not None:
                try:
                    proc.terminate()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000.0, 3)

    def _prewarm_frida_injector_worker(self):
        if not self.frida_injector_prewarm:
            self.frida_injector_prewarm_results = {
                "status": "disabled",
                "completed": True,
                "usable_arches": [],
                "arches": {},
            }
            self.frida_injector_prewarm_ready.set()
            return
        # Device prewarm normally finishes first.  Keep this bounded so the
        # analyzer can proceed even if Frida itself is unhealthy.
        self.frida_device_ready.wait(timeout=max(1.0, self.frida_device_wait_timeout))
        with self.frida_device_lock:
            device = self.frida_device
        if device is None:
            self.frida_injector_prewarm_results = {
                "status": "device_unavailable",
                "completed": True,
                "usable_arches": [],
                "arches": {},
            }
            self.frida_injector_prewarm_ready.set()
            return

        results = {}
        for arch in self.frida_injector_prewarm_arches:
            if self.stop_event.is_set():
                break
            item = self._prewarm_frida_injector_arch(device, arch)
            results[arch] = item
            self._emit_evidence("frida_injector_prewarm", **item)
            log.info(
                "[FridaMuncher] Frida injector prewarm arch=%s status=%s elapsed=%.1fms.",
                arch, item.get("status"), float(item.get("elapsed_ms") or 0.0),
            )
        requested = list(self.frida_injector_prewarm_arches)
        usable = sorted(
            arch for arch, item in results.items()
            if isinstance(item, dict) and item.get("status") == "ready"
        )
        if requested and len(usable) == len(requested):
            status = "ready"
        elif usable:
            status = "partial"
        else:
            status = "failed"
        self.frida_injector_prewarm_results = {
            "status": status,
            "completed": True,
            "usable_arches": usable,
            "arches": results,
        }
        self.frida_injector_prewarm_ready.set()

    def _start_frida_injector_prewarm(self):
        if not self.frida_injector_prewarm:
            self.frida_injector_prewarm_results = {
                "status": "disabled",
                "completed": True,
                "usable_arches": [],
                "arches": {},
            }
            self.frida_injector_prewarm_ready.set()
            return False
        if self.frida_injector_prewarm_thread is not None and self.frida_injector_prewarm_thread.is_alive():
            return True
        self.frida_injector_prewarm_thread = threading.Thread(
            target=self._prewarm_frida_injector_worker,
            name="FridaMuncher-injector-prewarm",
            daemon=True,
        )
        self.frida_injector_prewarm_thread.start()
        return True

    def _early_attach_snapshot(self):
        out = {}
        with self.early_attach_lock:
            items = list(self.early_attach_tickets.items())
        for pid, ticket in items:
            out[str(pid)] = {
                "role": ticket.get("role"),
                "trigger": ticket.get("trigger"),
                "started_monotonic": ticket.get("started"),
                "attempt": ticket.get("attempt"),
                "done": bool(ticket.get("done_event") and ticket["done_event"].is_set()),
                "claimed": bool(ticket.get("claimed")),
                "cancelled": bool(ticket.get("cancel_event") and ticket["cancel_event"].is_set()),
                "cancel_reason": ticket.get("cancel_reason"),
                "stop_cleanup_detached": ticket.get("stop_cleanup_detached"),
            }
        return out

    def _early_attach_enabled_for(self, role):
        normalized = str(role or "").lower()
        # Adaptive/capemon-only child policy owns the complete pre-attach
        # window.  Users who explicitly need P3.2.3.5 behavior can select
        # child_attach_policy=immediate.
        if normalized == "child" and self.child_attach_policy != "immediate":
            return False
        return bool(self.early_agent_attach and normalized in self.early_agent_roles)

    def _attach_timeout_for_role(self, role):
        if str(role or "").strip().lower() in {"child", "injected"}:
            return self.child_attach_timeout
        return self.attach_timeout

    def _extend_attach_for_helper(self, pid, role, started, deadline, extended):
        """Return an extended deadline when Frida's helper proves progress.

        This deliberately extends the existing blocking RPC instead of
        cancelling it and starting another attach.  Concurrent attach RPCs can
        race inside Frida and were the main risk in the P3.2.3.4 timeout path.
        """
        if extended or self.attach_helper_extension <= 0:
            return deadline, extended
        if str(role or "").strip().lower() not in {"child", "injected"}:
            return deadline, extended
        with self.session_lock:
            helper_seen = (self.lineage.get(pid) or {}).get("frida_helper_seen_monotonic")
        if helper_seen is None:
            return deadline, extended
        new_deadline = time.monotonic() + self.attach_helper_extension
        self._emit_evidence(
            "frida_attach_helper_extension",
            pid=pid,
            role=role,
            helper_delay_ms=round((float(helper_seen) - started) * 1000.0, 3),
            extension_ms=round(self.attach_helper_extension * 1000.0, 3),
        )
        log.info(
            "[FridaMuncher][pid=%d] Frida helper observed; extending the same %s attach RPC by %.2fs.",
            pid,
            role,
            self.attach_helper_extension,
        )
        return new_deadline, True

    def _start_early_agent_attach(self, pid, create_time, role, trigger="capemon_mapping"):
        """Start only Frida's agent attach; scripts stay deferred until CAPEMON-ready."""
        if not self._early_attach_enabled_for(role):
            return False
        if self.stop_event.is_set() or not self._identity_still_alive(pid, create_time):
            return False
        with self.early_attach_lock:
            existing = self.early_attach_tickets.get(pid)
            if existing is not None:
                return True

        device, device_wait_ms, error = self._get_cached_frida_device(pid)
        if device is None:
            self._emit_evidence(
                "frida_early_agent", severity="warning", pid=pid, role=role,
                status="device_unavailable", trigger=trigger,
                device_wait_ms=device_wait_ms, error=error,
            )
            return False

        started = time.monotonic()
        cancel_event = threading.Event()
        done_event = threading.Event()
        result = {}
        attempt = 1
        worker = threading.Thread(
            target=self._attach_rpc_worker,
            args=(device, pid, cancel_event, done_event, result),
            name=f"FridaMuncher-early-agent-{pid}-{attempt}",
            daemon=True,
        )
        ticket = {
            "pid": pid,
            "create_time": create_time,
            "role": role,
            "trigger": trigger,
            "attempt": attempt,
            "started": started,
            "device_wait_ms": device_wait_ms,
            "cancel_event": cancel_event,
            "done_event": done_event,
            "result": result,
            "worker": worker,
            "claimed": False,
            "progress_reported": False,
        }
        with self.early_attach_lock:
            if pid in self.early_attach_tickets:
                return True
            self.early_attach_tickets[pid] = ticket
        with self.session_lock:
            meta = self.lineage.get(pid)
            if meta is not None:
                meta["frida_attach_started_monotonic"] = started
                meta["frida_attach_attempt"] = attempt
                meta["frida_attach_phase"] = "early_agent"
        self._emit_evidence(
            "frida_attach_start", pid=pid, create_time=create_time, attempt=attempt,
            timeout=self._attach_timeout_for_role(role), device_wait_ms=device_wait_ms,
            phase="early_agent", trigger=trigger, role=role,
        )
        self._emit_evidence(
            "frida_early_agent", pid=pid, role=role, status="started",
            trigger=trigger, device_wait_ms=device_wait_ms,
        )
        log.info(
            "[FridaMuncher][pid=%d] Early Frida agent attach started at %s; "
            "JS scripts remain deferred until CAPEMON-ready.",
            pid, trigger,
        )
        with self.session_lock:
            self.attach_worker_threads.append(worker)
        worker.start()
        return True

    def _observe_early_attach_progress(self, pid):
        with self.early_attach_lock:
            ticket = self.early_attach_tickets.get(pid)
        if not ticket or ticket.get("progress_reported") or not ticket["done_event"].is_set():
            return
        result = ticket["result"]
        status = "agent_attached" if result.get("session") is not None else "attach_rpc_finished"
        with self.early_attach_lock:
            ticket["progress_reported"] = True
        self._emit_evidence(
            "frida_early_agent", pid=pid, role=ticket.get("role"), status=status,
            trigger=ticket.get("trigger"),
            elapsed_ms=round((time.monotonic() - ticket["started"]) * 1000.0, 3),
            error=result.get("error"), error_type=result.get("error_type"),
        )
        if result.get("session") is not None:
            log.info(
                "[FridaMuncher][pid=%d] Frida agent attached early; waiting for CAPEMON-ready before loading JS.",
                pid,
            )

    def _claim_early_agent_attach(self, pid, create_time):
        """Claim a mapping-time attach attempt after CAPEMON-ready.

        Returns (session, outcome, had_ticket).  The attach timeout budget starts
        at mapping time, not at claim time.
        """
        with self.early_attach_lock:
            ticket = self.early_attach_tickets.get(pid)
        if ticket is None:
            return None, None, False
        if ticket.get("claimed"):
            return None, "already_claimed", True
        ticket["claimed"] = True

        started = float(ticket["started"])
        done_event = ticket["done_event"]
        cancel_event = ticket["cancel_event"]
        result = ticket["result"]
        role = ticket.get("role")
        attach_budget = self._attach_timeout_for_role(role)
        deadline = started + attach_budget
        helper_extended = False
        terminal_status = None
        while not done_event.is_set():
            if self.stop_event.is_set():
                terminal_status = "stop_requested"
                break
            if not self._identity_still_alive(pid, create_time):
                terminal_status = "target_died"
                break
            now = time.monotonic()
            if now >= deadline:
                deadline, helper_extended = self._extend_attach_for_helper(
                    pid, role, started, deadline, helper_extended
                )
                if deadline > now:
                    continue
                terminal_status = "timeout"
                break
            done_event.wait(timeout=min(self.attach_poll_interval, max(0.0, deadline - now)))

        if terminal_status is not None and not done_event.is_set():
            cancel_event.set()
            helper_seen = None
            with self.session_lock:
                helper_seen = (self.lineage.get(pid) or {}).get("frida_helper_seen_monotonic")
            fields = {
                "target_alive": self._identity_still_alive(pid, create_time),
                "helper_seen": helper_seen is not None,
                "phase": "early_agent",
                "trigger": ticket.get("trigger"),
                "attach_budget": attach_budget,
                "helper_extended": helper_extended,
            }
            if helper_seen is not None:
                fields["helper_delay_ms"] = round((float(helper_seen) - started) * 1000.0, 3)
            self._record_attach_outcome(pid, ticket["attempt"], terminal_status, started, **fields)
            return None, terminal_status, True

        alive = self._identity_still_alive(pid, create_time)
        session = result.get("session")
        helper_seen = None
        with self.session_lock:
            helper_seen = (self.lineage.get(pid) or {}).get("frida_helper_seen_monotonic")
        common = {
            "target_alive": alive,
            "helper_seen": helper_seen is not None,
            "phase": "early_agent",
            "trigger": ticket.get("trigger"),
            "role": role,
            "attach_budget": attach_budget,
            "helper_extended": helper_extended,
        }
        if helper_seen is not None:
            common["helper_delay_ms"] = round((float(helper_seen) - started) * 1000.0, 3)

        if session is not None and alive:
            attached_at = float(result.get("finished_monotonic") or time.monotonic())
            with self.session_lock:
                meta = self.lineage.get(pid)
                if meta is not None:
                    meta["frida_attached_monotonic"] = attached_at
                    meta["frida_attach_phase"] = "early_agent"
            self._record_attach_outcome(pid, ticket["attempt"], "success", started, **common)
            self._emit_evidence(
                "frida_early_agent", pid=pid, role=ticket.get("role"),
                status="claimed", trigger=ticket.get("trigger"),
                attached_before_hooks=True,
            )
            return session, "success", True

        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
            self._record_attach_outcome(
                pid, ticket["attempt"], "target_died", started,
                late_session=True, **common,
            )
            return None, "target_died", True

        error = result.get("error") or "Frida early attach returned no session"
        error_type = result.get("error_type") or "UnknownError"
        status = "failed_exception" if alive else "target_died"
        self._record_attach_outcome(
            pid, ticket["attempt"], status, started,
            error=error, error_type=error_type, **common,
        )
        return None, status, True

    def _record_attach_outcome(self, pid, attempt, status, started, **fields):
        now = time.monotonic()
        elapsed_ms = round((now - started) * 1000.0, 3)
        with self.session_lock:
            meta = self.lineage.get(pid)
            create_time = meta.get("create_time") if meta is not None else None
        payload = {
            "pid": pid,
            "create_time": create_time,
            "status": status,
            "attempt": attempt,
            "elapsed_ms": elapsed_ms,
        }
        payload.update(fields)
        severity = "info" if status == "success" else "warning"
        self._emit_evidence("frida_attach", severity=severity, **payload)
        with self.session_lock:
            meta = self.lineage.get(pid)
            if meta is not None:
                outcomes = meta.setdefault("frida_attach_outcomes", [])
                outcomes.append(self._p3_json_safe(payload))
                if len(outcomes) > 8:
                    del outcomes[:-8]
                meta["frida_attach_last_outcome"] = status
                meta["frida_attach_last_elapsed_ms"] = elapsed_ms
        return payload

    def _attach_rpc_worker(self, device, pid, cancel_event, done_event, result):
        """Run the blocking Frida attach RPC outside the lifecycle worker.

        Python's Frida attach call is not cancellable.  If the lifecycle side
        times out or the target dies, cancel_event marks the result as unwanted;
        a late session is immediately detached so it cannot become an orphaned
        instrumentation session.
        """
        try:
            session = device.attach(pid)
            result["finished_monotonic"] = time.monotonic()
            if cancel_event.is_set() or self.stop_event.is_set():
                detached = False
                try:
                    session.detach()
                    detached = True
                except Exception:
                    pass
                result["late_session_detached"] = detached
                self._emit_evidence(
                    "frida_attach_late_cleanup", pid=pid,
                    status="detached" if detached else "detach_failed",
                )
            else:
                result["session"] = session
        except Exception as exc:
            result["finished_monotonic"] = time.monotonic()
            result["error"] = str(exc)
            result["error_type"] = type(exc).__name__
            if cancel_event.is_set() or self.stop_event.is_set():
                self._emit_evidence(
                    "frida_attach_late_result", severity="info", pid=pid,
                    status="error_after_cancel", error=str(exc),
                    error_type=type(exc).__name__,
                )
        finally:
            done_event.set()

    def _attach_once_bounded(self, device, pid, create_time, attempt, device_wait_ms=0.0):
        started = time.monotonic()
        with self.session_lock:
            meta = self.lineage.get(pid)
            role = (meta or {}).get("role")
            if meta is not None:
                meta["frida_attach_started_monotonic"] = started
                meta["frida_attach_attempt"] = attempt
        attach_budget = self._attach_timeout_for_role(role)
        self._emit_evidence(
            "frida_attach_start", pid=pid, create_time=create_time, attempt=attempt,
            timeout=attach_budget, device_wait_ms=device_wait_ms, role=role,
        )
        log.info(
            "[FridaMuncher][pid=%d] Attaching Frida (attempt %d/%d, timeout=%.2fs)...",
            pid, attempt, self.attach_retries, attach_budget,
        )

        cancel_event = threading.Event()
        done_event = threading.Event()
        result = {}
        worker = threading.Thread(
            target=self._attach_rpc_worker,
            args=(device, pid, cancel_event, done_event, result),
            name=f"FridaMuncher-attach-{pid}-{attempt}",
            daemon=True,
        )
        with self.session_lock:
            self.attach_worker_threads.append(worker)
        worker.start()

        deadline = started + attach_budget
        helper_extended = False
        terminal_status = None
        while not done_event.is_set():
            if self.stop_event.is_set():
                terminal_status = "stop_requested"
                break
            if not self._identity_still_alive(pid, create_time):
                terminal_status = "target_died"
                break
            now = time.monotonic()
            if now >= deadline:
                deadline, helper_extended = self._extend_attach_for_helper(
                    pid, role, started, deadline, helper_extended
                )
                if deadline > now:
                    continue
                terminal_status = "timeout"
                break
            done_event.wait(timeout=min(self.attach_poll_interval, max(0.0, deadline - now)))

        if terminal_status is not None and not done_event.is_set():
            cancel_event.set()
            helper_seen = None
            with self.session_lock:
                helper_seen = (self.lineage.get(pid) or {}).get("frida_helper_seen_monotonic")
            fields = {
                "target_alive": self._identity_still_alive(pid, create_time),
                "helper_seen": helper_seen is not None,
                "role": role,
                "attach_budget": attach_budget,
                "helper_extended": helper_extended,
            }
            if helper_seen is not None:
                fields["helper_delay_ms"] = round((float(helper_seen) - started) * 1000.0, 3)
            self._record_attach_outcome(pid, attempt, terminal_status, started, **fields)
            log.warning(
                "[FridaMuncher][pid=%d] Frida attach attempt %d ended as %s after %.1fms.",
                pid, attempt, terminal_status, (time.monotonic() - started) * 1000.0,
            )
            return None, terminal_status

        # The RPC completed.  Re-check process identity because an exception may
        # be delivered only after Windows has already torn the target down.
        alive = self._identity_still_alive(pid, create_time)
        session = result.get("session")
        helper_seen = None
        with self.session_lock:
            helper_seen = (self.lineage.get(pid) or {}).get("frida_helper_seen_monotonic")
        common = {
            "target_alive": alive,
            "helper_seen": helper_seen is not None,
            "role": role,
            "attach_budget": attach_budget,
            "helper_extended": helper_extended,
        }
        if helper_seen is not None:
            common["helper_delay_ms"] = round((float(helper_seen) - started) * 1000.0, 3)

        if session is not None and alive:
            attached_at = time.monotonic()
            with self.session_lock:
                meta = self.lineage.get(pid)
                if meta is not None:
                    meta["frida_attached_monotonic"] = attached_at
            self._record_attach_outcome(pid, attempt, "success", started, **common)
            return session, "success"

        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
            status = "target_died"
            common["late_session"] = True
            self._record_attach_outcome(pid, attempt, status, started, **common)
            return None, status

        error = result.get("error") or "Frida attach returned no session"
        error_type = result.get("error_type") or "UnknownError"
        status = "failed_exception" if alive else "target_died"
        self._record_attach_outcome(
            pid, attempt, status, started,
            error=error, error_type=error_type, **common,
        )
        log.warning(
            "[FridaMuncher][pid=%d] Frida attach attempt %d %s: %s",
            pid, attempt, status, error,
        )
        return None, status

    def _attach_with_retry(self, pid, create_time, start_attempt=1):
        device, device_wait_ms, device_error = self._get_cached_frida_device(pid)
        if device is None:
            started = time.monotonic()
            self._record_attach_outcome(
                pid, 0, "device_unavailable", started,
                device_wait_ms=device_wait_ms, error=device_error,
                target_alive=self._identity_still_alive(pid, create_time),
            )
            return None, "device_unavailable"

        start_attempt = max(1, int(start_attempt or 1))
        last_outcome = None
        for attempt in range(start_attempt, self.attach_retries + 1):
            if not self._identity_still_alive(pid, create_time):
                return None, last_outcome or "target_died"

            session, outcome = self._attach_once_bounded(
                device, pid, create_time, attempt,
                device_wait_ms=device_wait_ms if attempt == 1 else 0.0,
            )
            if session is not None:
                return session, "success"
            last_outcome = outcome

            # A timed-out RPC is still executing in a daemon worker and will
            # self-detach if it completes late; do not start a concurrent retry.
            if outcome in {"target_died", "timeout", "stop_requested", "device_unavailable"}:
                return None, outcome

            if attempt < self.attach_retries:
                if not self._wait_seconds_while_alive(
                    pid, create_time, self.attach_retry_delay
                ):
                    return None, last_outcome or "target_died"
        return None, last_outcome or "attach_failed_unknown"

    @staticmethod
    def _script_directory():
        return Path.cwd() / "data" / "frida_scripts"

    def _preload_script_sources(self):
        """Read Frida sources before malware launch to remove child-path I/O."""
        if not self.script_source_prewarm:
            self.script_source_prewarm_result = {
                "status": "disabled",
                "scripts": [],
                "bytes": 0,
            }
            return self.script_source_prewarm_result

        started = time.monotonic()
        script_dir = self._script_directory()
        loaded = {}
        errors = []
        for path in sorted(script_dir.glob("*.js")):
            try:
                loaded[path.name] = path.read_text(encoding="utf-8")
            except Exception as exc:
                errors.append({
                    "script": path.name,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                })
        self.script_source_cache = loaded
        result = {
            "status": "ready" if loaded and not errors else ("partial" if loaded else "failed"),
            "scripts": sorted(loaded),
            "bytes": sum(len(source.encode("utf-8")) for source in loaded.values()),
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
            "errors": errors,
        }
        self.script_source_prewarm_result = result
        self._emit_evidence("frida_script_source_prewarm", **result)
        if loaded:
            log.info(
                "[FridaMuncher] Preloaded %d Frida script source(s), %d bytes in %.1fms.",
                len(loaded), result["bytes"], result["elapsed_ms"],
            )
        else:
            log.warning("[FridaMuncher] No Frida script source could be preloaded from %s.", script_dir)
        return result

    def _ordered_script_paths(self, role):
        script_dir = self._script_directory()
        paths = sorted(script_dir.glob("*.js"), key=lambda p: p.name.lower())
        if str(role or "").lower() not in {"child", "injected"} or not self.child_fast_path:
            return paths
        priority = {name: index for index, name in enumerate(self.child_fast_scripts)}
        if str(role or "").lower() == "child" and self.child_fast_only:
            # For an adaptively attached child, keep only the small enrollment
            # tracker.  The general anti-evasion script remains root-owned and
            # cannot collide with CAPEMON hooks in the child.
            return [p for p in paths if p.name.lower() in priority]
        return sorted(
            paths,
            key=lambda p: (
                0 if p.name.lower() in priority else 1,
                priority.get(p.name.lower(), len(priority)),
                p.name.lower(),
            ),
        )

    def _load_scripts(self, pid, session, role, state):
        paths = self._ordered_script_paths(role)
        if not paths:
            raise RuntimeError(f"No Frida .js files found in {self._script_directory()}")

        fast_role = str(role or "").lower() in {"child", "injected"} and self.child_fast_path
        fast_names = set(self.child_fast_scripts) if fast_role else set()
        loaded = []
        preconfigured = set()
        failures = []

        for path in paths:
            name = path.name
            stage_started = time.monotonic()
            self._emit_evidence(
                "frida_script_stage", pid=pid, role=role, script=name,
                stage="create", status="started",
            )
            try:
                source = self.script_source_cache.get(name)
                if source is None:
                    source = path.read_text(encoding="utf-8")
                    self.script_source_cache[name] = source
                script = session.create_script(source)
                script.on(
                    "message",
                    lambda message, data, p=pid, n=name: self._on_message(
                        p, n, message, data
                    ),
                )
                self._emit_evidence(
                    "frida_script_stage", pid=pid, role=role, script=name,
                    stage="create", status="complete",
                    elapsed_ms=round((time.monotonic() - stage_started) * 1000.0, 3),
                )
            except Exception as exc:
                failure = {
                    "script": name,
                    "stage": "create",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "elapsed_ms": round((time.monotonic() - stage_started) * 1000.0, 3),
                }
                failures.append(failure)
                self._emit_evidence(
                    "frida_script_load_failed", severity="warning",
                    pid=pid, role=role, **failure,
                )
                log.warning(
                    "[FridaMuncher][pid=%d] Failed creating %s: %s: %s",
                    pid, name, type(exc).__name__, exc,
                )
                # A closed transport cannot recover for later scripts.
                if "connection is closed" in str(exc).lower() or type(exc).__name__ == "TransportError":
                    break
                continue

            load_started = time.monotonic()
            self._emit_evidence(
                "frida_script_stage", pid=pid, role=role, script=name,
                stage="load", status="started",
            )
            try:
                script.load()
            except Exception as exc:
                failure = {
                    "script": name,
                    "stage": "load",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "elapsed_ms": round((time.monotonic() - load_started) * 1000.0, 3),
                }
                failures.append(failure)
                self._emit_evidence(
                    "frida_script_load_failed", severity="warning",
                    pid=pid, role=role, **failure,
                )
                log.warning(
                    "[FridaMuncher][pid=%d] Failed loading %s: %s: %s",
                    pid, name, type(exc).__name__, exc,
                )
                try:
                    script.unload()
                except Exception:
                    pass
                if "connection is closed" in str(exc).lower() or type(exc).__name__ == "TransportError":
                    break
                continue

            loaded.append((name, script))
            self._emit_evidence(
                "script_loaded", pid=pid, role=role, script=name,
                elapsed_ms=round((time.monotonic() - load_started) * 1000.0, 3),
            )
            log.info("[FridaMuncher][pid=%d] Loaded: %s", pid, name)

            # Configure the small tracker immediately.  Waiting for every
            # general script first forfeits the only useful window in a child
            # that exits within a few hundred milliseconds after attach.
            if fast_role and name.lower() in fast_names:
                if self._configure_scripts(pid, [(name, script)], role) > 0:
                    preconfigured.add(name)
                    self._emit_evidence(
                        "frida_fast_hook_configured", pid=pid, role=role,
                        script=name,
                    )

        return loaded, preconfigured, failures

    @staticmethod
    def _script_setup_failure_status(exc, failures=None):
        texts = [f"{type(exc).__name__}: {exc}"]
        for failure in failures or []:
            texts.append(
                f"{failure.get('error_type', '')}: {failure.get('error', '')}"
            )
        joined = " ".join(texts).lower()
        if "transporterror" in joined or "connection is closed" in joined:
            return "transport_closed_before_scripts"
        if "script is destroyed" in joined or "session is detached" in joined:
            return "target_exited_during_script_setup"
        if "fridahooks-ready timeout" in joined:
            return "hooks_ready_timeout"
        return "script_setup_failed"

    def _configure_scripts(self, pid, scripts, role):
        # Sample-specific gate/exception recovery belongs only to the initial
        # target. Child/injected processes receive the general anti-analysis
        # policy but never inherit an entry-gate patch automatically.
        gate_mode = self.gate_mode if role == "root" else "none"
        legacy_int2a = self.enable_legacy_int2a if role == "root" else False
        exception_diagnostics = (
            self.exception_diagnostics
            if role == "root"
            else self.child_exception_diagnostics
        )
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
            "enable_exception_diagnostics": exception_diagnostics,
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
            "private_exec=%s exception_diagnostics=%s legacy_int2a=%s gate_mode=%s tracker=%s sysmon=%s",
            pid,
            delivered,
            self.profile_name,
            role,
            anti_mode,
            self.private_exec_callers,
            exception_diagnostics,
            legacy_int2a,
            gate_mode,
            tracker_mode,
            bridge_active,
        )
        self._emit_evidence(
            "profile_configured", pid=pid, role=role, profile=self.profile_name,
            anti_analysis=anti_mode, exception_diagnostics=exception_diagnostics,
            gate_mode=gate_mode, tracker_mode=tracker_mode,
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
            self._record_process_outcome(
                pid, role, "target_exited_before_attach",
                phase="capemon_sync",
            )
            return False

        if role == "child":
            if not self._wait_for_root_priority(pid, create_time):
                self.failed_identities.add(identity_key)
                self._record_process_outcome(
                    pid, role, "target_exited_before_attach",
                    phase="root_priority",
                )
                return False

            policy_decision = self._wait_for_child_attach_policy(
                pid, create_time, exe_path=exe_path
            )
            if policy_decision != "attach_now":
                if policy_decision == "capemon_only":
                    status = "capemon_only_policy"
                elif policy_decision == "target_exited_capemon_observed":
                    status = "capemon_observed_short_lived"
                elif policy_decision == "capemon_only_prewarm_unavailable":
                    status = "capemon_observed_prewarm_unavailable"
                else:
                    status = policy_decision
                self._record_process_outcome(
                    pid, role, status,
                    phase="child_attach_policy",
                    policy=self.child_attach_policy,
                    exclusive_window=self.child_capemon_exclusive_window,
                )
                # This is a successful CAPEMON/Sysmon-owned lifecycle outcome,
                # not a failed Frida attempt.
                return policy_decision in {
                    "capemon_only", "target_exited_capemon_observed",
                    "capemon_only_prewarm_unavailable",
                }

        # P3.2.3.4 may already have an agent-attach RPC in flight from the
        # CAPEMON-mapping phase. Claim it now, after CAPEMON readiness and child
        # priority decisions, and only then proceed to script loading.
        session, early_outcome, had_early = self._claim_early_agent_attach(pid, create_time)
        attach_outcome = early_outcome
        if session is None and (not had_early or early_outcome == "failed_exception"):
            # If no early ticket existed, use the normal path. If the early RPC
            # failed quickly while the target remains alive, retry from attempt 2.
            start_attempt = 2 if had_early else 1
            session, attach_outcome = self._attach_with_retry(
                pid, create_time, start_attempt=start_attempt
            )
        if session is None:
            log.warning(
                "[FridaMuncher][pid=%d] Could not attach Frida to %s (outcome=%s, early_outcome=%s).",
                pid, role, attach_outcome, early_outcome,
            )
            self.failed_identities.add(identity_key)
            terminal = attach_outcome or early_outcome or "attach_failed_unknown"
            interference_possible = False
            if role == "child" and terminal == "target_died":
                status = "target_died_during_optional_attach"
                interference_possible = True
            elif terminal == "target_died":
                status = "target_died_during_attach"
            else:
                status = terminal
            self._record_process_outcome(
                pid, role, status,
                phase="attach",
                attach_status=terminal,
                instrumentation_interference_possible=interference_possible,
            )
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

        scripts = []
        preconfigured = set()
        script_failures = []
        setup_started = time.monotonic()
        self._record_process_outcome(
            pid, role, "agent_attached_only", phase="script_setup_pending"
        )
        self._emit_evidence(
            "frida_script_setup_start", pid=pid, role=role,
            fast_path=bool(
                self.child_fast_path
                and str(role or "").lower() in {"child", "injected"}
            ),
        )

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

            scripts, preconfigured, script_failures = self._load_scripts(
                pid, session, role, state
            )
            if not scripts:
                last = script_failures[-1] if script_failures else {}
                detail = "{error_type}: {error}".format(
                    error_type=last.get("error_type") or "UnknownError",
                    error=last.get("error") or "every Frida script failed to load",
                )
                raise RuntimeError(detail)
            with self.session_lock:
                self.scripts_by_pid[pid] = scripts

            log.info(
                "[FridaMuncher][pid=%d] Script load finished for %s: loaded=%d failed=%d.",
                pid, role, len(scripts), len(script_failures),
            )
            remaining = [item for item in scripts if item[0] not in preconfigured]
            if remaining:
                self._configure_scripts(pid, remaining, role)

            fast_only_role = (
                self.child_fast_only
                and self.child_fast_path
                and str(role or "").lower() == "child"
            )
            if fast_only_role:
                loaded_names = [name for name, _ in scripts]
                if state["fast_ready"].wait(timeout=self.child_full_ready_timeout):
                    self._emit_evidence(
                        "frida_hooks_partial_ready", pid=pid, role=role,
                        exe=exe_path, scripts_loaded=loaded_names,
                        script_failures=script_failures,
                        mode="child_fast_only",
                    )
                    self._record_process_outcome(
                        pid, role, "fast_hooks_ready", phase="script_setup",
                        scripts_loaded=loaded_names,
                        script_failures=script_failures,
                        mode="child_fast_only",
                        elapsed_ms=round((time.monotonic() - setup_started) * 1000.0, 3),
                    )
                    return True
                if not self._identity_still_alive(pid, create_time):
                    self._record_process_outcome(
                        pid, role,
                        "fast_hooks_configured_unconfirmed_target_exited",
                        phase="script_setup",
                        scripts_loaded=loaded_names,
                        script_failures=script_failures,
                        mode="child_fast_only",
                        elapsed_ms=round((time.monotonic() - setup_started) * 1000.0, 3),
                    )
                    return True
                raise RuntimeError("ProcessInjectionTracker-ready timeout")

            fast_role = (
                self.child_fast_path
                and str(role or "").lower() in {"child", "injected"}
            )
            ready_timeout = self.child_full_ready_timeout if fast_role else 5.0
            if not state["ready"].wait(timeout=ready_timeout):
                if fast_role and state["fast_ready"].is_set():
                    loaded_names = [name for name, _ in scripts]
                    log.warning(
                        "[FridaMuncher][pid=%d] Fast child hooks ready but full FridaHooks acknowledgement is unavailable for %s.",
                        pid, role,
                    )
                    self._emit_evidence(
                        "frida_hooks_partial_ready", severity="warning",
                        pid=pid, role=role, exe=exe_path,
                        scripts_loaded=loaded_names,
                        script_failures=script_failures,
                    )
                    self._record_process_outcome(
                        pid, role, "fast_hooks_ready",
                        phase="script_setup",
                        scripts_loaded=loaded_names,
                        script_failures=script_failures,
                        elapsed_ms=round((time.monotonic() - setup_started) * 1000.0, 3),
                    )
                    return True
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
            self._emit_evidence(
                "frida_hooks_ready", pid=pid, role=role, exe=exe_path,
            )
            self._record_process_outcome(
                pid, role, "hooks_ready", phase="script_setup",
                scripts_loaded=[name for name, _ in scripts],
                script_failures=script_failures,
                elapsed_ms=round((time.monotonic() - setup_started) * 1000.0, 3),
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

        except Exception as exc:
            target_alive = self._identity_still_alive(pid, create_time)
            expected_exit = (
                not target_alive
                and str(role or "").lower() in {"child", "injected"}
                and (
                    "connection is closed" in str(exc).lower()
                    or "timeout" in str(exc).lower()
                    or type(exc).__name__ == "TransportError"
                )
            )
            if expected_exit:
                log.warning(
                    "[FridaMuncher][pid=%d] %s exited during optional Frida script setup: %s: %s",
                    pid, role, type(exc).__name__, exc,
                )
            else:
                log.exception(
                    "[FridaMuncher][pid=%d] Script/setup failed for role=%s",
                    pid,
                    role,
                )
            status = self._script_setup_failure_status(exc, script_failures)
            if expected_exit:
                if scripts:
                    status = "fast_hooks_configured_unconfirmed_target_exited"
                else:
                    status = "target_exited_during_script_setup"
            loaded_names = [name for name, _ in scripts]
            self._emit_evidence(
                "frida_script_setup_failed", severity="warning",
                pid=pid, role=role, status=status,
                error_type=type(exc).__name__, error=str(exc),
                target_alive=target_alive,
                scripts_loaded=loaded_names,
                script_failures=script_failures,
                elapsed_ms=round((time.monotonic() - setup_started) * 1000.0, 3),
            )
            self._record_process_outcome(
                pid, role, status, phase="script_setup",
                error_type=type(exc).__name__, error=str(exc),
                scripts_loaded=loaded_names,
                script_failures=script_failures,
                elapsed_ms=round((time.monotonic() - setup_started) * 1000.0, 3),
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

    def _pcap_results_dir(self):
        if self.p3_runtime_report_path is not None:
            return self.p3_runtime_report_path.parent
        return self._detect_capesolo_analysis_output_dir()

    def _write_pcap_runtime_snapshot(self):
        """Atomically bind capture state to this run, including failure/disabled states."""
        try:
            path = self._pcap_results_dir() / "pcap_runtime.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(
                json.dumps(self._p3_json_safe(self.pcap_runtime), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(str(temporary), str(path))
            return path
        except Exception:
            log.debug("[FridaMuncher] Failed writing PCAP runtime snapshot", exc_info=True)
            return None

    def _start_pcap_capture(self):
        self.pcap_runtime = {
            "schema": "capesolo-pcap-runtime/1.4",
            "configured": bool(self.pcap_capture_enabled),
            "required": bool(self.pcap_capture_required),
            "agent_url": self.pcap_agent_url,
            "run_id": self.run_id,
            "status": "disabled",
            "started": False,
            "stopped": False,
            "fetched": False,
            "errors": [],
        }
        if not self.pcap_capture_enabled:
            self._write_pcap_runtime_snapshot()
            return False
        if PcapTaskClient is None:
            self.pcap_runtime["status"] = "client_unavailable"
            self.pcap_runtime["errors"].append("pcap_task_client import failed")
            self._emit_evidence(
                "pcap_capture_start", severity="warning", status="client_unavailable"
            )
            self._write_pcap_runtime_snapshot()
            return False
        try:
            self.pcap_client = PcapTaskClient(
                self.pcap_agent_url,
                token=self.pcap_agent_token,
                guest_ip=self.pcap_guest_ip,
                timeout=self.pcap_agent_timeout,
                clock_sample_interval=self.pcap_clock_sample_interval,
            )
            result = self.pcap_client.start(self.run_id, self.pcap_capture_duration)
            result["required"] = bool(self.pcap_capture_required)
            self.pcap_runtime = result
            started = bool(result.get("started"))
            self._emit_evidence(
                "pcap_capture_start",
                severity="info" if started else "warning",
                status=result.get("status"),
                started=started,
                agent_url=self.pcap_agent_url,
                guest_ip=result.get("guest_ip"),
                interface=result.get("interface"),
                duration=self.pcap_capture_duration,
                clock_sync=result.get("clock_sync"),
            )
            if started:
                log.info(
                    "[FridaMuncher] Task PCAP capture started: run_id=%s guest_ip=%s agent=%s interface=%s",
                    self.run_id,
                    result.get("guest_ip"),
                    self.pcap_agent_url,
                    result.get("interface"),
                )
            else:
                log.warning(
                    "[FridaMuncher] Task PCAP capture unavailable: status=%s errors=%s",
                    result.get("status"), result.get("errors"),
                )
            self._write_pcap_runtime_snapshot()
            return started
        except Exception as exc:
            self.pcap_runtime["status"] = "start_failed"
            self.pcap_runtime["errors"].append(str(exc))
            self._emit_evidence(
                "pcap_capture_start", severity="warning", status="start_failed", error=str(exc)
            )
            log.warning("[FridaMuncher] Task PCAP capture start failed: %s", exc)
            self._write_pcap_runtime_snapshot()
            return False

    def _stop_pcap_capture(self):
        if self.pcap_client is None or not self.pcap_runtime.get("started"):
            return dict(self.pcap_runtime)
        try:
            result = self.pcap_client.stop_and_fetch(
                self.run_id,
                self._pcap_results_dir(),
                fetch=self.pcap_capture_fetch,
            )
            result["required"] = bool(self.pcap_capture_required)
            self.pcap_runtime = result
            complete = result.get("status") == "complete" and bool(result.get("fetched"))
            self._emit_evidence(
                "pcap_capture_stop",
                severity="info" if complete else "warning",
                status=result.get("status"),
                stopped=result.get("stopped"),
                fetched=result.get("fetched"),
                bytes=result.get("bytes"),
                sha256=result.get("sha256"),
                packets_captured=result.get("packets_captured"),
                packets_dropped=result.get("packets_dropped"),
                clock_sync=result.get("clock_sync"),
                errors=result.get("errors"),
            )
            log.info(
                "[FridaMuncher] Task PCAP capture finalized: status=%s fetched=%s bytes=%s path=%s",
                result.get("status"), result.get("fetched"), result.get("bytes"), result.get("path"),
            )
        except Exception as exc:
            self.pcap_runtime["status"] = "stop_failed"
            self.pcap_runtime.setdefault("errors", []).append(str(exc))
            self._emit_evidence(
                "pcap_capture_stop", severity="warning", status="stop_failed", error=str(exc)
            )
            log.warning("[FridaMuncher] Task PCAP capture stop/fetch failed: %s", exc)
        self._write_pcap_runtime_snapshot()
        return dict(self.pcap_runtime)

    def _start_sysmon_bridge(self):
        if not self.sysmon_bridge_enabled:
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
        if not isinstance(event, dict):
            return
        event_id = int(event.get("event_id") or 0)
        # During finalization, retain the wire-correlation tail even though new
        # process enrollment is no longer allowed.  Sysmon can deliver EID3/22
        # slightly after the corresponding PCAP packet has been captured.
        if self.stop_event.is_set() and event_id not in (3, 5, 22):
            return
        self.sysmon_events_seen += 1
        self.sysmon_event_counts[event_id] = self.sysmon_event_counts.get(event_id, 0) + 1

        if event_id == 1:
            self._handle_sysmon_process_create(event)
        elif event_id == 3:
            self._handle_sysmon_network_connect(event)
        elif event_id == 5:
            self._handle_sysmon_process_terminate(event)
        elif event_id == 8:
            self._handle_sysmon_remote_thread(event)
        elif event_id == 22:
            self._handle_sysmon_dns_query(event)
        elif event_id == 25:
            self._handle_sysmon_process_tampering(event)

    def _append_sysmon_network_event(self, item):
        with self.session_lock:
            if len(self.sysmon_network_events) < self.sysmon_network_event_limit:
                self.sysmon_network_events.append(item)
                return True
            self.sysmon_network_events_dropped += 1
        if self.sysmon_network_events_dropped in {1, 100, 1000}:
            log.warning(
                "[FridaMuncher] Sysmon network-event limit reached; dropped=%d",
                self.sysmon_network_events_dropped,
            )
        return False

    def _handle_sysmon_network_connect(self, event):
        pid = int(event.get("process_id") or 0)
        if pid <= 0:
            return
        guid = str(event.get("process_guid") or "")
        image = str(event.get("image") or "")
        tracked = self._sysmon_source_is_tracked(pid, guid, image)
        with self.session_lock:
            role = str(self.lineage.get(pid, {}).get("role") or "") if tracked else ""
        item = {
            "event_id": 3,
            "record_id": event.get("record_id"),
            "utc_time": event.get("utc_time"),
            "process_guid": guid,
            "process_id": pid,
            "image": image,
            "user": event.get("user") or "",
            "role": role or None,
            "tracked": tracked,
            "protocol": event.get("protocol") or "",
            "initiated": bool(event.get("initiated")),
            "source_ip": event.get("source_ip") or "",
            "source_port": int(event.get("source_port") or 0),
            "source_hostname": event.get("source_hostname") or "",
            "destination_ip": event.get("destination_ip") or "",
            "destination_port": int(event.get("destination_port") or 0),
            "destination_hostname": event.get("destination_hostname") or "",
        }
        if not self._append_sysmon_network_event(item):
            return
        if tracked:
            self._emit_evidence(
                "sysmon_network_connect",
                pid=pid,
                role=role or None,
                protocol=item["protocol"],
                source_ip=item["source_ip"],
                source_port=item["source_port"],
                destination_ip=item["destination_ip"],
                destination_port=item["destination_port"],
                record_id=item["record_id"],
            )

    def _handle_sysmon_dns_query(self, event):
        pid = int(event.get("process_id") or 0)
        if pid <= 0:
            return
        guid = str(event.get("process_guid") or "")
        image = str(event.get("image") or "")
        tracked = self._sysmon_source_is_tracked(pid, guid, image)
        with self.session_lock:
            role = str(self.lineage.get(pid, {}).get("role") or "") if tracked else ""
        item = {
            "event_id": 22,
            "record_id": event.get("record_id"),
            "utc_time": event.get("utc_time"),
            "process_guid": guid,
            "process_id": pid,
            "image": image,
            "user": event.get("user") or "",
            "role": role or None,
            "tracked": tracked,
            "query_name": str(event.get("query_name") or "")[:2048],
            "query_status": str(event.get("query_status") or "")[:128],
            "query_results": str(event.get("query_results") or "")[:4096],
        }
        if not self._append_sysmon_network_event(item):
            return
        if tracked:
            self._emit_evidence(
                "sysmon_dns_query",
                pid=pid,
                role=role or None,
                query_name=item["query_name"],
                query_status=item["query_status"],
                record_id=item["record_id"],
            )

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

        # P3.2.3.4 timing anchor: Frida's x86/x64 helper creates a remote
        # thread while attach is progressing.  Record it only as instrumentation
        # telemetry for an already tracked target; it never enrolls a process.
        source_basename = os.path.basename(source_image).lower()
        if source_basename.startswith("frida-helper"):
            now_mono = time.monotonic()
            with self.session_lock:
                target_meta = self.lineage.get(target_pid)
                if target_meta is not None:
                    target_meta["frida_helper_seen_monotonic"] = now_mono
                    target_meta["frida_helper_source_pid"] = source_pid
                    attach_started = target_meta.get("frida_attach_started_monotonic")
                else:
                    attach_started = None
            if target_meta is not None:
                helper_delay_ms = None
                if attach_started is not None:
                    try:
                        helper_delay_ms = round((now_mono - float(attach_started)) * 1000.0, 3)
                    except Exception:
                        helper_delay_ms = None
                self._emit_evidence(
                    "frida_helper_seen", pid=target_pid, helper_pid=source_pid,
                    helper_image=source_image, helper_delay_ms=helper_delay_ms,
                )

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
        """Instrument a descendant without a hard dependency on root readiness.

        P3.2.3.14 retains immediate child CAPEMON synchronization and bounded
        root priority, then applies the profile's generic child attach policy.
        Adaptive mode gives CAPEMON an exclusive observation window; a child
        that exits there is deliberately not Frida-attached.
        """
        try:
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
            self.root_identity = (pid, create_time)
            self.root_ready.clear()
            self.root_instrumentation_failed.clear()

            # P3.2.3: auto profile selection becomes authoritative only after
            # the actual CAPE root executable is known.
            self._reselect_profile_for_root(exe_path)

            log.info(
                "[FridaMuncher] NEW analysis target found: "
                "pid=%d create_time=%s exe=%s profile=%s",
                pid,
                create_time,
                exe_path,
                self.profile_name,
            )
            self._emit_evidence(
                "root_target", pid=pid, create_time=create_time, exe=exe_path,
                profile=self.profile_name, profile_selection=self.profile_selection,
            )

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
                self.root_instrumentation_failed.set()
                self._emit_evidence(
                    "root_instrumentation_failed", severity="warning", pid=pid,
                    alive=self._identity_still_alive(pid, create_time), exe=exe_path,
                )
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
        self.root_instrumentation_failed.clear()
        self.root_identity = None
        self.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        self.started_wall = time.time()
        self.stopped_wall = None
        self.sysmon_network_events = []
        self.sysmon_network_events_dropped = 0
        self.sysmon_final_drain = {
            "status": "pending" if self.sysmon_bridge_enabled else "disabled",
            "timeout_seconds": float(self.sysmon_final_drain_timeout),
            "quiet_period_seconds": float(self.sysmon_final_drain_quiet_period),
            "events_added": 0,
        }
        self.pcap_client = None
        if self.p3_runtime_report_path is not None:
            self.p3_run_dir = self.p3_runtime_report_path.parent / "p3_runs" / self.run_id
        self._check_result_storage_preflight()
        self._preload_script_sources()
        self._write_p3_run_marker("running")
        # Start the off-guest capture before target discovery/launch work. The
        # agent's own TCP control port is excluded from its BPF, so this request
        # cannot become malware network evidence.
        self._start_pcap_capture()
        self.baseline_targets = self._snapshot_existing_targets()
        # Warm Frida in parallel with CAPE startup.  Moving first-use device
        # acquisition before target launch preserves short-lived stage windows.
        self._start_frida_device_prewarm()
        if self.frida_injector_prewarm:
            # Complete the controlled injector warmup before enabling the Sysmon
            # bridge and before CAPE launches the malware target. This prevents
            # the prewarm helper activity from entering run enrollment telemetry.
            self.frida_device_ready.wait(timeout=max(1.0, self.frida_device_wait_timeout))
            self._start_frida_injector_prewarm()
            warm_budget = 1.0 + self.frida_injector_prewarm_timeout * max(1, len(self.frida_injector_prewarm_arches))
            self.frida_injector_prewarm_ready.wait(timeout=warm_budget)
        else:
            self.frida_injector_prewarm_results = {
                "status": "disabled",
                "completed": True,
                "usable_arches": [],
                "arches": {},
            }
            self.frida_injector_prewarm_ready.set()
        self._start_sysmon_bridge()

        log.info(
            "[FridaMuncher] %s config: run_id=%s profile=%s target=%s "
            "analysis_dir=%s expected_path=%s gate_mode=%s restore=%s "
            "expected_gate=%s delta=0x%x legacy_int2a=%s "
            "anti_analysis=%s child_anti_analysis=%s private_exec=%s "
            "exception_diagnostics=%s child_exception_diagnostics=%s "
            "follow_children=%s follow_injected=%s max_sessions=%d "
            "capemon_activation=%.1fs capemon_detect=%.1fs capemon_grace=%.1fs capemon_fallback=%.1fs "
            "child_grace=%.1fs child_root_priority=%s child_root_timeout=%.1fs child_priority_window=%.2fs "
            "attach_timeout=%.2fs child_attach_timeout=%.2fs helper_extension=%.2fs "
            "attach_poll=%.2fs retry_delay=%.2fs device_prewarm=%s device_wait=%.2fs "
            "early_agent=%s early_roles=%s child_attach_policy=%s child_exclusive=%.2fs "
            "child_active_tick=%.2fs child_require_prewarm=%s "
            "child_fast_path=%s child_fast_only=%s child_fast_scripts=%s "
            "injector_prewarm=%s injector_arches=%s injector_status=%s injector_usable=%s "
            "injection_grace=%.2fs injection_min_signals=%d "
            "sysmon_bridge=%s sysmon_active=%s "
            "sysmon_ids=%s frida_fallback=%s injected_source_policy=%s",
            PRODUCT_VERSION,
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
            self.exception_diagnostics,
            self.child_exception_diagnostics,
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
            self.child_root_priority_window,
            self.attach_timeout,
            self.child_attach_timeout,
            self.attach_helper_extension,
            self.attach_poll_interval,
            self.attach_retry_delay,
            self.frida_device_prewarm,
            self.frida_device_wait_timeout,
            self.early_agent_attach,
            sorted(self.early_agent_roles),
            self.child_attach_policy,
            self.child_capemon_exclusive_window,
            self.child_observation_max_tick,
            self.child_require_prewarmed_arch,
            self.child_fast_path,
            self.child_fast_only,
            self.child_fast_scripts,
            self.frida_injector_prewarm,
            self.frida_injector_prewarm_arches,
            self.frida_injector_prewarm_results.get("status")
            if isinstance(self.frida_injector_prewarm_results, dict) else "unknown",
            self._injector_usable_arches(),
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
            "[FridaMuncher] %s profile selection: requested=%s selected=%s source=%s score=%s candidate=%s reasons=%s",
            PRODUCT_VERSION,
            self.profile_request, self.profile_name,
            self.profile_selection.get("source"), self.profile_selection.get("score"),
            self.profile_selection.get("candidate"), self.profile_selection.get("reasons"),
        )
        self._emit_evidence(
            "controller_start", profile_request=self.profile_request,
            profile_selected=self.profile_name, profile_selection=self.profile_selection,
            sysmon_bridge_active=self.sysmon_bridge_active, baseline_targets=self.baseline_targets,
            pcap_status=self.pcap_runtime.get("status"),
        )
        log.info(
            "[FridaMuncher] PCAP policy: enabled=%s required=%s agent=%s guest_ip=%s duration=%ss fetch=%s status=%s",
            self.pcap_capture_enabled,
            self.pcap_capture_required,
            self.pcap_agent_url,
            self.pcap_runtime.get("guest_ip") or self.pcap_guest_ip,
            self.pcap_capture_duration,
            self.pcap_capture_fetch,
            self.pcap_runtime.get("status"),
        )
        try:
            logged_options = dict(self.options)
            for option_name in list(logged_options):
                if "pcap" in str(option_name).lower() and "token" in str(option_name).lower():
                    logged_options[option_name] = "<redacted>"
            log.info(
                "[FridaMuncher] CAPE options received: %s",
                logged_options,
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
            "[FridaMuncher] %s worker started; waiting for the NEW "
            "analysis target.",
            PRODUCT_VERSION,
        )
        return True

    def stop(self):
        self.stop_event.set()

        # Cancel only unclaimed mapping-time attach work. Claimed successful
        # tickets are normal history and must not be reported as cancelled.
        with self.early_attach_lock:
            early_tickets = list(self.early_attach_tickets.values())
        for ticket in early_tickets:
            if ticket.get("claimed"):
                continue
            done_event = ticket.get("done_event")
            if done_event is not None and not done_event.is_set():
                try:
                    ticket["cancel_reason"] = "stop_cleanup_unclaimed_inflight"
                    ticket["cancel_event"].set()
                except Exception:
                    pass
                continue

            # A completed but unclaimed ticket can hold a session that was
            # never inserted into self.sessions. Detach it explicitly.
            session = (ticket.get("result") or {}).get("session")
            if session is not None:
                detached = False
                try:
                    session.detach()
                    detached = True
                except Exception:
                    pass
                ticket["stop_cleanup_detached"] = detached
                ticket["cancel_reason"] = "stop_cleanup_unclaimed_complete"

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

        # Capture through the last detach/cleanup activity, then freeze and
        # fetch it before the current runtime JSON is finalized.
        self._stop_pcap_capture()

        # Sysmon is intentionally stopped last. EID3/EID22 can trail the PCAP
        # packet by a short amount, so a bounded quiet-period drain closes the
        # attribution gap without extending malware execution indefinitely.
        if self.sysmon_bridge is not None:
            before = int(self.sysmon_events_seen)
            try:
                drain = self.sysmon_bridge.drain(
                    timeout=self.sysmon_final_drain_timeout,
                    quiet_period=self.sysmon_final_drain_quiet_period,
                )
                self.sysmon_final_drain = dict(drain or {})
                self.sysmon_final_drain.update(
                    {
                        "status": "complete",
                        "drain_status": (drain or {}).get("status", "unknown"),
                        "timeout_seconds": float(self.sysmon_final_drain_timeout),
                        "quiet_period_seconds": float(self.sysmon_final_drain_quiet_period),
                        "events_before": before,
                        "events_after": int(self.sysmon_events_seen),
                        "events_added": max(0, int(self.sysmon_events_seen) - before),
                    }
                )
            except Exception as exc:
                self.sysmon_final_drain = {
                    "status": "failed",
                    "error": str(exc),
                    "timeout_seconds": float(self.sysmon_final_drain_timeout),
                    "quiet_period_seconds": float(self.sysmon_final_drain_quiet_period),
                    "events_before": before,
                    "events_after": int(self.sysmon_events_seen),
                    "events_added": max(0, int(self.sysmon_events_seen) - before),
                }
                log.debug("[FridaMuncher] Sysmon final drain failed", exc_info=True)
            try:
                self.sysmon_bridge.stop()
            except Exception:
                log.debug("[FridaMuncher] Sysmon bridge stop failed", exc_info=True)
        else:
            self.sysmon_final_drain["status"] = "not_available"
        self.sysmon_bridge_active = False

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
            pcap_status=self.pcap_runtime.get("status"),
            pcap_fetched=self.pcap_runtime.get("fetched"),
            sysmon_final_drain=self.sysmon_final_drain,
        )
        self.stopped_wall = stop_event.get("wall_time") if isinstance(stop_event, dict) else time.time()
        self._write_p3_run_marker("stopped")
        self._write_p3_runtime_report(
            session_count=len(sessions),
            excluded_summary=dict(sorted(excluded_summary.items())),
        )
        return True
