"""Coverage-aware MITRE ATT&CK v19.2 mapper for P3.2.3.15.

ATT&CK metadata supplies catalog context and sensor requirements. Executable
detection remains local, deterministic and testable: sensor records are first
normalized to semantic events, then correlated by state machines.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

from CAPEsolo.capelib.attack_state import EvidenceEvent, SequenceRule, evaluate_distinct, evaluate_sequence, parse_timestamp
from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION

SCHEMA = "capesolo-mitre-attack/1.3"
ATTACK_VERSION = "19.2"
ATTACK_DOMAIN = "enterprise-attack"
ACTIVE_PLATFORM = "Windows"
MAX_EVIDENCE = 12
STATUS_RANK = {"insufficient_evidence": 0, "candidate": 1, "attempted": 2, "observed": 3}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
LEGACY_IDS = {
    "T1032": "T1573", "T1093": "T1055.012", "T1181": "T1055.011",
    "T1186": "T1055.013", "T1188": "T1090.003", "T1483": "T1568.002",
    # ATT&CK v19 moved these concepts into the new Defense Impairment family.
    "T1070.001": "T1685.005", "T1562.001": "T1685",
}
TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
    "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
    "stealth": "Stealth", "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access", "discovery": "Discovery",
    "lateral-movement": "Lateral Movement", "collection": "Collection",
    "command-and-control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact",
}
SUPPORTED = {
    "T1003.001", "T1055", "T1055.004", "T1055.012", "T1056.001",
    "T1071.001", "T1071.003", "T1071.004", "T1095", "T1113",
    "T1547.001", "T1573", "T1614",
}
PARTIAL = {
    "T1012", "T1016", "T1027", "T1027.002", "T1033", "T1036", "T1036.005", "T1036.007", "T1047",
    "T1053.005", "T1057", "T1059.001", "T1059.003", "T1059.005",
    "T1059.006", "T1059.007", "T1069.001", "T1069.002", "T1070.001", "T1070.004",
    "T1070.006", "T1082", "T1083", "T1087.001", "T1105", "T1112", "T1115",
    "T1123", "T1135", "T1140", "T1218.005", "T1218.010", "T1218.011", "T1497.001",
    "T1497.003", "T1518.001", "T1543.003", "T1622", "T1685", "T1685.005",
}
SENSORS = {
    "DC0021": {"component": "OS API Execution", "sensors": ["CAPEMON API telemetry", "Frida selected hooks"]},
    "DC0032": {"component": "Process Creation", "sensors": ["CAPEMON process APIs", "Sysmon EID 1"]},
    "DC0039": {"component": "File Creation", "sensors": ["CAPEMON file APIs", "artifact manifest"]},
    "DC0059": {"component": "File Metadata", "sensors": ["PE version information", "Authenticode signer metadata"]},
    "DC0063": {"component": "Windows Registry Key Modification", "sensors": ["CAPEMON registry APIs", "Sysmon EID 12-14"]},
    "DC0064": {"component": "Command Execution", "sensors": ["CAPEMON process APIs", "PowerShell Script Block Logging"]},
    "DC0009": {"component": "Process Access", "sensors": ["CAPEMON process-memory APIs", "Sysmon EID 10"]},
    "DC0082": {"component": "Network Traffic Flow", "sensors": ["PCAP agent", "Sysmon EID 3"]},
    "DC0077": {"component": "Network Traffic Content", "sensors": ["PCAP decoders", "TLS key material"]},
}
NETWORK_PREFIXES = ("http_", "https_", "network_", "smtp_", "irc_", "dns_", "injection_network")

# This is a resource baseline, not a free-text keyword list. A value can only
# contribute after OriginalFilename and another PE identity field agree, the
# runtime identity differs, no signer is present, and execution is observed in
# a user-writable location. It is deliberately small and auditable.
WINDOWS_RESOURCE_NAMES = {
    "calc.exe", "cmd.exe", "conhost.exe", "csrss.exe", "dllhost.exe",
    "dwm.exe", "explorer.exe", "fontdrvhost.exe", "lsass.exe", "mmc.exe",
    "mobsync.exe", "msconfig.exe", "mshta.exe", "notepad.exe", "reg.exe",
    "regsvr32.exe", "rundll32.exe", "services.exe", "smss.exe", "spoolsv.exe",
    "svchost.exe", "taskhostw.exe", "taskmgr.exe", "userinit.exe",
    "werfault.exe", "wininit.exe", "winlogon.exe", "wmic.exe", "wscript.exe",
}
USER_WRITABLE_PATH_MARKERS = (
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\users\\public\\",
    "\\downloads\\", "\\desktop\\",
)


def _safe_json(path: Path) -> dict:
    try: value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, TypeError): return {}
    return value if isinstance(value, dict) else {}


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass


def _compact(value: Any, limit: int = 360) -> str:
    if isinstance(value, (dict, list)): value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def normalize_technique_id(value: Any):
    match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", str(value or "").upper())
    if not match: return None, None
    original = match.group(1); current = LEGACY_IDS.get(original, original)
    return current, original if current != original else None


def _url(technique_id: str) -> str:
    if "." in technique_id:
        parent, child = technique_id.split(".", 1); return f"https://attack.mitre.org/techniques/{parent}/{child}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def _args(call: dict) -> dict:
    value = call.get("arguments") or []
    if isinstance(value, dict): return value
    return {str(item.get("name")): item.get("value") for item in value if isinstance(item, dict) and item.get("name") is not None}


def _text(call: dict) -> str: return " ".join(str(value or "") for value in _args(call).values())
def _path(value: Any) -> str: return str(value or "").strip().strip('"').replace("/", "\\").lower()
def _success(call: dict) -> bool: return call.get("status") is not False and str(call.get("return") or "").lower() not in {"0xffffffff", "-1", "false", "error"}


def _basename(value: Any) -> str:
    normalized = _path(value).rstrip("\\")
    return normalized.rsplit("\\", 1)[-1] if normalized else ""


def _identity_token(value: Any) -> str:
    name = _basename(value)
    if name.endswith((".exe", ".scr", ".com")):
        name = name.rsplit(".", 1)[0]
    return re.sub(r"[^a-z0-9]+", "", name)


def _version_info(target: dict) -> dict[str, str]:
    pe = target.get("pe") or {}
    rows = pe.get("versioninfo") or []
    if isinstance(rows, dict):
        rows = [{"name": key, "value": value} for key, value in rows.items()]
    return {
        str(row.get("name") or "").strip().lower(): str(row.get("value") or "").strip()
        for row in rows if isinstance(row, dict) and row.get("name")
    }


def _arg(args: dict, *names: str) -> Any:
    """Return a structured argument by name without searching free-form text."""
    lowered = {str(key).lower(): value for key, value in args.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _image_format(path: Any, buffer: Any = None, raw_buffer: Any = None) -> Optional[str]:
    """Return an image format only from a structured path or file signature."""
    suffix = Path(_path(path).replace("\\", "/")).suffix.lower()
    by_suffix = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".bmp": "bmp"}.get(suffix)
    raw = str(raw_buffer or "").lower()
    value = str(buffer or "").lower()
    by_magic = None
    if raw.startswith("ffd8ff") or value.startswith("\\xff\\xd8\\xff"):
        by_magic = "jpeg"
    elif raw.startswith("89504e470d0a1a0a") or value.startswith("\\x89png"):
        by_magic = "png"
    elif raw.startswith("424d") or value.startswith("bm"):
        by_magic = "bmp"
    return by_magic or by_suffix


def _smtp_command(value: Any) -> Optional[str]:
    """Parse an SMTP command verb from a structured send buffer."""
    first = str(value or "").lstrip().split(None, 1)[0].upper().rstrip(":")
    return first if first in {"EHLO", "HELO", "MAIL", "RCPT", "DATA", "AUTH", "RSET", "QUIT", "STARTTLS"} else None


def _integer(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return None


def _call_completed(call: dict) -> bool:
    """Treat a false IsDebuggerPresent result as a completed sensor event.

    CAPEMON stores the Boolean return from IsDebuggerPresent in ``status``.
    ``False`` therefore means "no debugger found", not "the API failed".  Other
    APIs retain the normal success gate.
    """
    if str(call.get("api") or "").lower() == "isdebuggerpresent":
        return call.get("return") is not None or call.get("status") is not None
    return _success(call)


def _catalog_path() -> Path: return Path(__file__).resolve().parents[1] / "data" / "mitre" / "attack_v19_2_compact.json"


def load_catalog(domain: str = ATTACK_DOMAIN):
    bundle = _safe_json(_catalog_path()); domains = bundle.get("domains") or {}; selected = domains.get(domain) or {}
    validation = bundle.get("validation") or {}
    return selected.get("techniques") or {}, {
        "source": bundle.get("source") or _catalog_path().name, "source_tag": bundle.get("source_tag") or "v19.2",
        "attack_version": bundle.get("attack_version") or ATTACK_VERSION, "domain": domain,
        "domains": {key: value.get("summary") or {} for key, value in domains.items()},
        "validation": validation,
        "complete_catalog": bool(validation.get("complete")) if validation else all(
            bool((domains.get(key) or {}).get("techniques"))
            for key in ("enterprise-attack", "mobile-attack", "ics-attack")
        ),
    }


def _find(base: Optional[Path], exact: str, pattern: str) -> list[Path]:
    if not base: return []
    paths = []; direct = base / exact
    if direct.is_file(): paths.append(direct)
    paths.extend(path for path in base.glob(pattern) if path.is_file() and path not in paths)
    return sorted(paths, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)


def prepare_clean_behavior(results: dict, analysis_path: Optional[Path]) -> dict:
    """Run provenance before mapping because the external finalizer runs later."""
    if not analysis_path or not (results.get("behavior") or {}).get("processes"):
        return {"available": False, "reason": "analysis_path_or_behavior_missing"}
    temporary = analysis_path / ".p32315_mitre_behavior_input.json"
    try:
        from tools.frida_artifact_filter import classify_analysis
        from tools.frida_behavior_chains import build_behavior_chains
        from tools.frida_behavior_provenance import classify_behavior
        _atomic_json(temporary, results)
        try:
            artifact_result = classify_analysis(analysis_path, output_dir=analysis_path)
        except Exception:
            # The report remains usable when a task has no artifact manifest;
            # behavior classification still applies textual/temporal anchors.
            artifact_result = {}
        outcome = classify_behavior(
            analysis_path, report_json=temporary, output_dir=analysis_path,
            artifact_result=artifact_result,
        )
        chains = build_behavior_chains(analysis_dir=analysis_path, output_dir=analysis_path)
        return {
            "available": bool(outcome.get("available")), "reason": outcome.get("reason"),
            "summary": outcome.get("summary") or {},
            "behavior_chains": len(chains.get("chains") or []),
        }
    except Exception as exc:
        return {"available": False, "reason": f"clean_view_prepare_failed:{exc}"}
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


class AttackMapper:
    def __init__(self, results: dict, analysis_path: Optional[Path] = None):
        self.results = results if isinstance(results, dict) else {}; self.analysis_path = Path(analysis_path) if analysis_path else None
        self.catalog, self.catalog_meta = load_catalog(); self.mappings = {}; self.rejected = []; self.warnings = []; self.state_evaluations = []
        self.lineage = self._json_artifact("frida_p3_runtime.json", "frida_p3_runtime*.json").get("lineage") or {}
        self.p3_report = self._json_artifact("frida_p3_report.json", "frida_p3_report*.json")
        self.chains = self._chains(); self.clean_rows, self.clean_source = self._clean_rows()
        if self.clean_source == "raw_behavior_fallback": self.warnings.append({"code": "clean_behavior_unavailable", "severity": "warning", "message": "Canonical clean behavior was unavailable; conservative raw-call fallback was used."})

    def _json_artifact(self, exact: str, pattern: str) -> dict:
        for path in _find(self.analysis_path, exact, pattern):
            value = _safe_json(path)
            if value: return value
        return {}

    def _chains(self) -> dict:
        embedded = self.results.get("behavior_chains")
        if isinstance(embedded, dict) and embedded.get("chains"): return embedded
        direct = self._json_artifact("frida_behavior_chains.json", "frida_behavior_chains*.json")
        return direct or self.p3_report.get("behavior_chains") or {}

    def _clean_rows(self):
        for path in _find(self.analysis_path, "behavior.filtered.jsonl", "behavior.filtered*.jsonl"):
            try:
                rows = [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
                rows = [row for row in rows if isinstance(row, dict) and isinstance(row.get("call"), dict) and not row.get("filter_from_clean_view")]
                if rows: return rows, path.name
            except (OSError, ValueError): pass
        return [], "raw_behavior_fallback"

    def _technique(self, technique_id: str) -> dict:
        item = self.catalog.get(technique_id) or {}; strategies = item.get("strategies") or []; components = {}
        for strategy in strategies:
            for analytic in strategy.get("analytics") or []:
                for component in analytic.get("data_components") or []:
                    components[component.get("id") or component.get("name")] = {"id": component.get("id"), "name": component.get("name")}
        return {"id": technique_id, "name": item.get("name") or f"Technique {technique_id}", "tactics": list(item.get("tactics") or ["uncategorized"]),
                "platforms": list(item.get("platforms") or []), "url": _url(technique_id), "detection_strategies": strategies,
                "data_components": sorted(components.values(), key=lambda row: str(row.get("id")))}

    def _evidence(self, source: str, summary: str, process=None, call=None, details=None) -> dict:
        process = process or {}; call = call or {}; result = {"source": source, "summary": _compact(summary)}
        pid = process.get("process_id") or process.get("pid") or call.get("pid")
        if pid is not None:
            result["pid"] = pid; role = (self.lineage.get(str(pid)) or {}).get("role")
            if role: result["role"] = role
        name = process.get("process_name") or call.get("process_name")
        if name: result["process_name"] = _compact(name, 120)
        for key in ("timestamp", "api"):
            if call.get(key) is not None: result[key] = _compact(call.get(key), 120)
        if details: result["details"] = {str(key): _compact(value) for key, value in details.items() if value not in (None, "", [], {})}
        return result

    def add(self, technique_id, status, confidence, rule_id, rationale, evidence, original_id=None, state=None):
        technique_id, normalized = normalize_technique_id(technique_id)
        if not technique_id or status not in STATUS_RANK: return
        original_id = original_id or normalized
        if status == "insufficient_evidence":
            row = self._technique(technique_id); row.update({"status": status, "confidence": confidence, "rule_id": rule_id, "rationale": rationale, "evidence": [evidence]})
            if state: row["state_machine"] = state
            if original_id: row["normalized_from"] = original_id
            fp = (technique_id, rule_id, evidence.get("pid"), evidence.get("summary"))
            if not any((x.get("id"), x.get("rule_id"), (x.get("evidence") or [{}])[0].get("pid"), (x.get("evidence") or [{}])[0].get("summary")) == fp for x in self.rejected): self.rejected.append(row)
            return
        row = self.mappings.get(technique_id)
        if row is None:
            row = self._technique(technique_id); row.update({"status": status, "confidence": confidence, "rule_ids": [], "rationales": [], "evidence": [], "sources": [], "state_machines": []}); self.mappings[technique_id] = row
        elif STATUS_RANK[status] > STATUS_RANK[row["status"]]: row["status"] = status
        if CONFIDENCE_RANK.get(confidence, 0) > CONFIDENCE_RANK.get(row.get("confidence"), 0): row["confidence"] = confidence
        if rule_id not in row["rule_ids"]: row["rule_ids"].append(rule_id)
        if rationale not in row["rationales"]: row["rationales"].append(rationale)
        if evidence.get("source") and evidence["source"] not in row["sources"]: row["sources"].append(evidence["source"])
        if state and state not in row["state_machines"]: row["state_machines"].append(state)
        if original_id:
            row.setdefault("normalized_from", [])
            if original_id not in row["normalized_from"]: row["normalized_from"].append(original_id)
        fp = (evidence.get("source"), evidence.get("pid"), evidence.get("timestamp"), evidence.get("api"), evidence.get("summary"))
        old = {(x.get("source"), x.get("pid"), x.get("timestamp"), x.get("api"), x.get("summary")) for x in row["evidence"]}
        if fp not in old and len(row["evidence"]) < MAX_EVIDENCE: row["evidence"].append(evidence)

    def _all_calls(self):
        if self.clean_rows:
            for row in self.clean_rows:
                call = row.get("call") or {}
                yield {"process_id": row.get("pid"), "process_name": row.get("process_name"), "module_path": row.get("process_path")}, call
            return
        for process in (self.results.get("behavior") or {}).get("processes") or []:
            if not isinstance(process, dict): continue
            for call in process.get("calls") or []:
                if not isinstance(call, dict) or call.get("filter_from_clean_view") is True: continue
                if call.get("provenance") == "framework_frida" or "frida-agent" in _text(call).lower(): continue
                yield process, call

    def _calls(self):
        for process, call in self._all_calls():
            if _call_completed(call):
                yield process, call

    @staticmethod
    def _state(rule_id: str, result: dict, gates: list[str]) -> dict:
        return {"engine": "deterministic_state_machine", "rule_id": rule_id, "complete": bool(result.get("complete")), "state_trace": result.get("state_trace") or [], "optional_states": result.get("optional_states") or [], "missing_steps": result.get("missing") or [], "correlation_key": result.get("key"), "quality_gates": gates}

    def _map_target_masquerading(self) -> None:
        """Correlate PE identity with the executed process identity.

        This implements the Windows portion of ATT&CK DET0127/AN0355. The
        detector intentionally requires independent metadata, execution,
        location, and trust gates; no technique is emitted from a descriptive
        string or filename keyword alone.
        """
        target = self.results.get("target") or {}
        if not isinstance(target, dict) or target.get("category") not in {None, "file"}:
            return
        version = _version_info(target)
        original = _basename(version.get("originalfilename"))
        original_token = _identity_token(original)
        if not original or original not in WINDOWS_RESOURCE_NAMES or not original_token:
            return

        identity_fields = ("filedescription", "internalname", "productname")
        corroborating_fields = [
            field for field in identity_fields
            if original_token in _identity_token(version.get(field))
        ]
        if not corroborating_fields:
            return

        processes = [
            process for process in (self.results.get("behavior") or {}).get("processes") or []
            if isinstance(process, dict) and (process.get("process_name") or process.get("module_path"))
        ]
        if not processes:
            return
        process = processes[0]
        runtime_path = _path(process.get("module_path"))
        runtime_name = _basename(process.get("process_name") or runtime_path)
        if not runtime_path or not runtime_name or runtime_name == original:
            return

        signers = (target.get("pe") or {}).get("digital_signers") or []
        unsigned = not bool(signers)
        user_writable = any(marker in runtime_path for marker in USER_WRITABLE_PATH_MARKERS)
        if not unsigned or not user_writable:
            return

        trace = ["runtime_identity", "coherent_pe_identity", "identity_mismatch", "trust_anomaly"]
        result = {
            "complete": True,
            "state_trace": trace,
            "optional_states": [],
            "missing": [],
            "key": target.get("sha256") or runtime_path,
        }
        gates = [
            "executed process identity", "OriginalFilename plus corroborating PE identity field",
            "known Windows resource baseline", "runtime/embedded name mismatch",
            "no Authenticode signer metadata", "user-writable execution path",
        ]
        state = self._state("sm.masquerading.pe_identity", result, gates)
        self.state_evaluations.append(state)
        details = {
            "binding": "target_sha256+executed_process",
            "target_sha256": target.get("sha256"),
            "runtime_name": runtime_name,
            "runtime_path": runtime_path,
            "original_filename": original,
            "file_description": version.get("filedescription"),
            "corroborating_fields": corroborating_fields,
            "digital_signers": len(signers),
            "user_writable_path": user_writable,
        }
        evidence = self._evidence(
            "pe_process_identity",
            f"Unsigned {runtime_name} executed from a user-writable path while coherent PE metadata claimed {original}.",
            process,
            details=details,
        )
        self.add(
            "T1036", "observed", "high", "masquerading.pe_identity_mismatch",
            "Executed process identity conflicted with coherent PE metadata for a known Windows resource and passed location/signature trust gates.",
            evidence, state=state,
        )
        self.add(
            "T1036.005", "candidate", "medium", "masquerading.pe_resource_claim",
            "Embedded metadata claimed a legitimate Windows resource, but the runtime filename did not itself match that resource; the narrower sub-technique remains a candidate.",
            evidence, state=state,
        )

    def _map_calls(self) -> None:
        semantic = {key: [] for key in (
            "persistence", "injection", "lsass", "environment", "registry_query", "debugger",
            "keylogging", "screen_capture", "location", "smtp",
        )}
        processes = (self.results.get("behavior") or {}).get("processes") or []
        module_paths = {_path(proc.get("module_path")) for proc in processes if isinstance(proc, dict) and proc.get("module_path")}
        handle_targets = {}

        # The name hypothesis is bound to target metadata instead of whichever
        # API happened to be visited first.
        for process in processes:
            if not isinstance(process, dict): continue
            name = str(process.get("process_name") or Path(str(process.get("module_path") or "")).name)
            if re.search(r"\.(?:pdf|docx?|xlsx?|jpg|png|txt|scr)\.(?:exe|scr|com|bat|cmd)$", name, re.I):
                evidence = self._evidence("target_metadata", f"Double executable extension in analyzed process name: {name}", process, details={"binding": "process_metadata"})
                self.add("T1036.007", "candidate", "medium", "masquerading.double_extension", "A double-extension executable name was observed; analyst-controlled naming remains possible.", evidence)

        for process, call in self._calls():
            api = str(call.get("api") or ""); low_api = api.lower(); args = _args(call)
            text = _text(call); low_text = text.lower(); pid = str(process.get("process_id") or "")
            process_name = str(process.get("process_name") or "").lower(); ts = parse_timestamp(call.get("timestamp"))
            evidence = self._evidence("behavior_api", f"{api}: {text}", process, call, args)

            # Registry and persistence sensor adapter.
            if low_api.startswith(("regsetvalue", "regdelete")):
                self.add("T1112", "observed", "medium", "registry.modify", "A successful registry modification was observed.", evidence)
            elif low_api.startswith("regcreatekey"):
                self.add("T1112", "candidate", "medium", "registry.open_or_create", "A key was opened/created; disposition does not prove modification.", evidence)
            registry_query_apis = {
                "ntqueryvaluekey", "ntquerymultiplevaluekey", "regqueryvalueexa", "regqueryvalueexw",
                "reggetvaluea", "reggetvaluew", "regqueryinfokeya", "regqueryinfokeyw",
            }
            if low_api in registry_query_apis:
                full_name = _path(_arg(args, "FullName", "KeyName", "ObjectName"))
                value_name = _path(_arg(args, "ValueName", "Value"))
                target = full_name or value_name
                if target:
                    semantic["registry_query"].append(EvidenceEvent(
                        "registry_query", pid, "registry", ts, evidence,
                        {"target_id": target, "api": low_api},
                    ))
            if low_api.startswith("regsetvalue") and ("\\currentversion\\run" in low_text or "\\currentversion\\runonce" in low_text):
                target = _path(args.get("Buffer") or args.get("Data") or args.get("Value") or args.get("FullName"))
                semantic["persistence"].append(EvidenceEvent("run_key_write", pid, target, ts, evidence))
            if low_api.startswith("copyfile"):
                destination = _path(args.get("NewFileName") or args.get("Destination")); semantic["persistence"].append(EvidenceEvent("payload_materialized", pid, destination, ts, evidence))
                base = Path(destination.replace("\\", "/")).name
                if ("google" in base or base in {"svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe", "services.exe"}) and any(token in destination for token in ("\\appdata\\", "\\temp\\", "\\users\\public\\")):
                    self.add("T1036.005", "candidate", "medium", "masquerading.legitimate_name", "A system/vendor-like executable was written to a user-writable path.", evidence)
            process_creation = low_api in {"createprocessa", "createprocessw", "createprocessinternalw", "ntcreateuserprocess", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw", "winexec"}
            if process_creation:
                launched = _path(args.get("ApplicationName") or args.get("ImagePath") or args.get("CommandLine")); semantic["persistence"].append(EvidenceEvent("payload_executed", pid, launched, ts, evidence))
            if low_api.startswith("createservice") or ("\\system\\currentcontrolset\\services\\" in low_text and "imagepath" in low_text):
                self.add("T1543.003", "observed", "high", "persistence.windows_service", "A Windows service creation or ImagePath write was observed.", evidence)
            if ("schtasks" in low_text and "/create" in low_text) or "\\taskcache\\" in low_text:
                self.add("T1053.005", "observed", "high", "persistence.scheduled_task", "A scheduled-task creation operation was observed.", evidence)

            # Indicator removal and masquerading.
            if low_api.startswith(("deletefile", "ntdeletefile", "shfileoperation")):
                deleted = _path(args.get("FileName") or args.get("ObjectName") or text); exact = deleted in module_paths or any(path and path in deleted for path in module_paths)
                self.add("T1070.004", "observed" if exact else "candidate", "high" if exact else "medium", "indicator.file_deletion", "Deletion of an analyzed module was observed." if exact else "A file deletion was observed; cleanup intent is not independently proven.", evidence)
            if low_api in {"cleareventlogw", "cleareventloga", "evtclearlog"} or ("wevtutil" in low_text and re.search(r"\b(cl|clear-log)\b", low_text)):
                self.add("T1070.001", "observed", "high", "indicator.clear_event_log", "A Windows event-log clearing operation was observed.", evidence)
            if low_api in {"setfiletime", "ntsetinformationfile"} and any(token in low_text for token in ("creationtime", "lastwritetime", "filebasicinformation")):
                self.add("T1070.006", "candidate", "medium", "indicator.file_time_change", "File timestamps changed; anti-forensic intent needs confirmation.", evidence)

            # Execution requires a process-creation semantic or the interpreter
            # being the analyzed process; seeing a name during enumeration is insufficient.
            interpreters = {"powershell.exe": "T1059.001", "pwsh.exe": "T1059.001", "cmd.exe": "T1059.003", "cscript.exe": "T1059.005", "wscript.exe": "T1059.005", "python.exe": "T1059.006", "pythonw.exe": "T1059.006", "node.exe": "T1059.007"}
            signed = {"mshta.exe": "T1218.005", "regsvr32.exe": "T1218.010", "rundll32.exe": "T1218.011"}
            for executable, technique in interpreters.items():
                if executable in process_name or (process_creation and executable in low_text): self.add(technique, "observed", "high", "execution.command_interpreter", f"Execution through {executable} was observed.", evidence)
            for executable, technique in signed.items():
                if executable in process_name or (process_creation and executable in low_text): self.add(technique, "observed", "high", "execution.signed_binary_proxy", f"Execution through {executable} was observed.", evidence)
            if "wmic.exe" in process_name or (process_creation and "wmic.exe" in low_text) or low_api.startswith(("iwbem", "execmethod")):
                self.add("T1047", "observed", "medium", "execution.wmi", "WMI execution activity was observed.", evidence)

            # Process-memory adapter creates target-bound events.
            if low_api in {"ntopenprocess", "openprocess"}:
                handle = str(args.get("ProcessHandle") or "").lower(); target_pid = str(args.get("ProcessIdentifier") or args.get("ProcessId") or "")
                target_name = str(args.get("ProcessName") or "").lower(); target = handle or target_pid or "unknown"
                semantic["injection"].append(EvidenceEvent("process_open", pid, target, ts, evidence))
                if handle and ("lsass" in target_name or "lsass" in low_text): handle_targets[(pid, handle)] = "lsass"
                if "lsass" in target_name or "lsass" in low_text: semantic["lsass"].append(EvidenceEvent("lsass_access", pid, "lsass", ts, evidence))
            handle = str(args.get("ProcessHandle") or args.get("hProcess") or "").lower(); target_pid = str(args.get("ProcessId") or args.get("ProcessIdentifier") or "")
            remote = (handle and handle not in {"0xffffffff", "0xffffffffffffffff", "-1", "current"}) or (target_pid and target_pid != pid)
            target = handle or target_pid or "unknown"
            if low_api in {"ntwritevirtualmemory", "writeprocessmemory", "ntmapviewofsection", "mapviewoffileex"} and remote:
                semantic["injection"].append(EvidenceEvent("remote_write", pid, target, ts, evidence))
            if low_api in {"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread", "setthreadcontext"} and remote:
                semantic["injection"].append(EvidenceEvent("remote_execute", pid, target, ts, evidence, {"apc": False}))
            if low_api in {"queueuserapc", "ntqueueapcthread", "ntqueueapcthreadex"} and remote:
                semantic["injection"].append(EvidenceEvent("remote_execute", pid, target, ts, evidence, {"apc": True}))
            if low_api in {"ntreadvirtualmemory", "readprocessmemory", "minidumpwritedump"} and ("lsass" in low_text or handle_targets.get((pid, handle)) == "lsass"):
                semantic["lsass"].append(EvidenceEvent("lsass_read_or_dump", pid, "lsass", ts, evidence))

            # Discovery and collection primitives retained from P3.2.3.14, now
            # operating exclusively on the canonical clean view when available.
            process_query = low_api == "ntquerysysteminformation" and ("systemprocessinformation" in low_text or re.search(r"(?:class|informationclass)[^0-9]*5\b", low_text))
            if low_api in {"createtoolhelp32snapshot", "process32firstw", "process32first", "process32nextw", "process32next"} or process_query: self.add("T1057", "observed", "high", "discovery.processes", "Process enumeration was observed.", evidence)
            if low_api in {"getsysteminfo", "getnativesysteminfo", "getcomputernamew", "getcomputernamea", "rtlgetversion", "getversionexw", "getversionexa"}: self.add("T1082", "candidate", "medium", "discovery.system_information", "A clean-view system-information query was observed; routine use remains possible.", evidence)
            if low_api in {"getusernamew", "getusernamea", "getusernameexw", "getusernameexa"}: self.add("T1033", "observed", "medium", "discovery.user", "User-name discovery was observed.", evidence)
            if low_api in {"netuserenum", "netusergetinfo"}: self.add("T1087.001", "observed", "high", "discovery.local_accounts", "Local account enumeration was observed.", evidence)
            if low_api in {"netshareenum", "wnetenumresourcew", "wnetenumresourcea"}: self.add("T1135", "observed", "high", "discovery.network_shares", "Network-share enumeration was observed.", evidence)
            if low_api in {"netlocalgroupenum", "netlocalgroupgetmembers"}: self.add("T1069.001", "observed", "high", "discovery.local_groups", "Local-group enumeration was observed.", evidence)
            if low_api in {"netgroupenum", "netgroupgetusers"}: self.add("T1069.002", "observed", "high", "discovery.domain_groups", "Domain-group enumeration was observed.", evidence)
            if low_api in {"getadaptersaddresses", "getadaptersinfo", "getnetworkparams", "wsaioctl"} or "ipconfig" in low_text: self.add("T1016", "observed", "medium", "discovery.network_configuration", "Network configuration discovery was observed.", evidence)
            if low_api.startswith(("findfirstfile", "findnextfile")): self.add("T1083", "candidate", "medium", "discovery.files", "File/directory enumeration was observed; routine access remains possible.", evidence)
            if any(token in low_text for token in ("msmpeng", "windefend", "securityhealth", "avast", "kaspersky", "crowdstrike", "sentinelone")): self.add("T1518.001", "candidate", "medium", "discovery.security_software", "Security-product identifiers were queried.", evidence)
            if low_api in {"getclipboarddata", "openclipboard"}: self.add("T1115", "observed", "medium", "collection.clipboard", "Clipboard access was observed.", evidence)

            # Keylogging is a structured state machine. HookIdentifier 2 is
            # WH_KEYBOARD and 13 is WH_KEYBOARD_LL; ThreadId 0 makes the hook
            # global. Other message hooks and integer-like text are excluded.
            if low_api in {"setwindowshookexa", "setwindowshookexw"}:
                hook_id = _integer(_arg(args, "HookIdentifier", "idHook"))
                thread_id = _integer(_arg(args, "ThreadId", "dwThreadId"))
                if hook_id in {2, 13}:
                    kind = "keyboard_hook" if thread_id == 0 else "keyboard_hook_thread"
                    semantic["keylogging"].append(EvidenceEvent(
                        kind, pid, "keyboard", ts, evidence,
                        {"hook_id": hook_id, "global": thread_id == 0},
                    ))
            elif low_api in {"getasynckeystate", "getkeystate"}:
                semantic["keylogging"].append(EvidenceEvent("keyboard_poll", pid, "keyboard", ts, evidence))

            file_path = _path(_arg(args, "HandleName", "FileName", "ObjectName", "lpFileName"))
            if low_api in {"ntwritefile", "writefile"} and _basename(file_path) in {"key.bin", "keys.log", "keylog.dat"}:
                semantic["keylogging"].append(EvidenceEvent("keylog_artifact", pid, "keyboard", ts, evidence, {"path": file_path}))

            # Screen capture can be proven either by an explicit capture API or
            # by repeated image materialization with an image magic signature.
            if low_api in {"bitblt", "stretchblt", "printwindow"}:
                semantic["screen_capture"].append(EvidenceEvent("screen_api", pid, "screen", ts, evidence, {"api": low_api}))
            image_kind = _image_format(file_path)
            if low_api in {"ntcreatefile", "createfilea", "createfilew"} and image_kind:
                access = _integer(_arg(args, "DesiredAccess", "dwDesiredAccess"))
                disposition = _integer(_arg(args, "CreateDisposition", "dwCreationDisposition"))
                if (access is not None and access & 0x40000000) or disposition in {2, 4, 5}:
                    semantic["screen_capture"].append(EvidenceEvent(
                        "image_artifact", pid, "screen", ts, evidence,
                        {"artifact_id": file_path, "format": image_kind},
                    ))
            if low_api in {"ntwritefile", "writefile"} and file_path:
                image_kind = _image_format(
                    file_path, _arg(args, "Buffer", "Data"),
                    next((item.get("raw_value") for item in call.get("arguments") or [] if isinstance(item, dict) and str(item.get("name") or "").lower() in {"buffer", "data"}), None),
                )
                raw_buffer = next((item.get("raw_value") for item in call.get("arguments") or [] if isinstance(item, dict) and str(item.get("name") or "").lower() in {"buffer", "data"}), None)
                if image_kind and (
                    str(raw_buffer or "").lower().startswith(("ffd8ff", "89504e470d0a1a0a", "424d"))
                    or str(_arg(args, "Buffer", "Data") or "").lower().startswith(("\\xff\\xd8\\xff", "\\x89png", "bm"))
                ):
                    semantic["screen_capture"].append(EvidenceEvent(
                        "image_content", pid, "screen", ts, evidence,
                        {"artifact_id": file_path, "format": image_kind},
                    ))

            location_apis = {
                "getuserdefaultlcid": "locale", "getsystemdefaultlcid": "locale",
                "getuserdefaultlocalename": "locale", "getsystemdefaultlocalename": "locale",
                "gettimezoneinformation": "timezone", "getdynamictimezoneinformation": "timezone",
                "getusergeoid": "geo", "getgeoinfoa": "geo", "getgeoinfow": "geo",
            }
            if low_api in location_apis:
                semantic["location"].append(EvidenceEvent(
                    "location_query", pid, "location", ts, evidence,
                    {"location_type": location_apis[low_api], "api": low_api},
                ))

            if low_api in {"connect", "wsaconnect"}:
                port = _integer(_arg(args, "port", "RemotePort", "sin_port"))
                socket = str(_arg(args, "socket", "s", "Socket") or "unknown")
                if port in {25, 465, 587}:
                    semantic["smtp"].append(EvidenceEvent("smtp_connect_success", pid, socket, ts, evidence, {"port": port}))
            if low_api in {"send", "wsasend"}:
                command = _smtp_command(_arg(args, "buffer", "Buffer", "Data"))
                socket = str(_arg(args, "socket", "s", "Socket") or "unknown")
                if command:
                    semantic["smtp"].append(EvidenceEvent("smtp_command_success", pid, socket, ts, evidence, {"command": command}))
            if low_api in {"waveinopen", "mcisendstringw", "mcisendstringa"}: self.add("T1123", "candidate", "medium", "collection.audio", "Audio-capture primitives were observed.", evidence)
            debugger_probe = low_api in {"isdebuggerpresent", "checkremotedebuggerpresent"}
            if low_api == "ntqueryinformationprocess":
                info_class = _integer(_arg(args, "ProcessInformationClass", "InformationClass", "Class"))
                debugger_probe = info_class in {7, 30, 31}
            if debugger_probe:
                semantic["debugger"].append(EvidenceEvent(
                    "debugger_probe", pid, "debugger", ts, evidence,
                    {"probe_api": low_api, "debugger_found": str(call.get("return") or "").lower() not in {"", "0", "0x0", "0x00000000", "false"}},
                ))
            check_types = {"getsystemmetrics": "display", "globalmemorystatusex": "memory", "getdiskfreespaceexw": "disk", "cpuid": "cpu"}
            if low_api in check_types: semantic["environment"].append(EvidenceEvent("system_check", pid, "environment", ts, evidence, {"check_type": check_types[low_api]}))
            if low_api in {"sleep", "sleepex", "ntdelayexecution"}:
                numbers = [int(value) for value in re.findall(r"\d+", low_text)]
                if numbers and max(numbers) >= 30000: self.add("T1497.003", "candidate", "medium", "evasion.long_delay", "A long execution delay was requested.", evidence)
            if any(token in low_text for token in ("windefend", "msmpeng", "set-mppreference", "disableantispyware")) and any(token in low_api + " " + low_text for token in ("terminate", "delete", "disable", "stop", "regset")):
                self.add("T1562.001", "candidate", "medium", "evasion.impair_defenses", "An operation targeting security controls was observed.", evidence)

        # Failed socket calls are excluded from the successful behavior view,
        # but remain useful as explicit protocol attempts. Preserve them under
        # a separate status so they cannot be mistaken for completed C2.
        for process, call in self._all_calls():
            if _call_completed(call):
                continue
            api = str(call.get("api") or ""); low_api = api.lower(); args = _args(call)
            pid = str(process.get("process_id") or ""); ts = parse_timestamp(call.get("timestamp"))
            evidence = self._evidence("behavior_api", f"{api}: {_text(call)}", process, call, args)
            socket = str(_arg(args, "socket", "s", "Socket") or "unknown")
            if low_api in {"connect", "wsaconnect"}:
                port = _integer(_arg(args, "port", "RemotePort", "sin_port"))
                if port in {25, 465, 587}:
                    semantic["smtp"].append(EvidenceEvent("smtp_connect_attempt", pid, socket, ts, evidence, {"port": port}))
            elif low_api in {"send", "wsasend"}:
                command = _smtp_command(_arg(args, "buffer", "Buffer", "Data"))
                if command:
                    semantic["smtp"].append(EvidenceEvent("smtp_command_attempt", pid, socket, ts, evidence, {"command": command}))

        self._evaluate_states(semantic)

    def _evaluate_states(self, semantic: dict) -> None:
        run = evaluate_sequence(SequenceRule("sm.persistence.run_key", ("run_key_write",), ("payload_materialized", "payload_executed"), 600), semantic["persistence"])
        if run.get("matched"):
            state = self._state("sm.persistence.run_key", run, ["successful registry write", "structured Run/RunOnce path", "same PID/target for corroboration"]); self.state_evaluations.append(state)
            self.add("T1547.001", "observed", "high" if run.get("optional") else "medium", "sm.persistence.run_key", "Run-key persistence satisfied the registry-write state; materialization/execution raises confidence.", run["matched"][-1].evidence, state=state)

        injection = evaluate_sequence(SequenceRule("sm.injection.write_execute", ("remote_write", "remote_execute"), ("process_open",), 60), semantic["injection"])
        state = self._state("sm.injection.write_execute", injection, ["clean behavior", "same source PID", "same remote target", "ordered within 60 seconds"])
        if injection.get("complete"):
            self.state_evaluations.append(state); event = injection["matched"][-1]
            self.add("T1055", "observed", "high", "sm.injection.write_execute", "Remote write and execution states matched the same target.", event.evidence, state=state)
            if event.attributes.get("apc"): self.add("T1055.004", "observed", "high", "sm.injection.apc", "Remote write was followed by APC execution on the same target.", event.evidence, state=state)
        elif injection.get("matched") or semantic["injection"]:
            self.state_evaluations.append(state); event = (injection.get("matched") or semantic["injection"])[0]
            self.add("T1055", "insufficient_evidence", "medium", "sm.injection.incomplete", "Injection precursor exists, but same-target write and execution states are incomplete.", event.evidence, state=state)

        lsass = evaluate_sequence(SequenceRule("sm.credential.lsass", ("lsass_access", "lsass_read_or_dump"), (), 120), semantic["lsass"])
        state = self._state("sm.credential.lsass", lsass, ["clean behavior", "LSASS identity", "same PID", "access before read/dump"])
        if lsass.get("complete"):
            self.state_evaluations.append(state); self.add("T1003.001", "observed", "high", "sm.credential.lsass", "LSASS access followed by read/dump satisfied the state machine.", lsass["matched"][-1].evidence, state=state)
        elif lsass.get("matched"):
            self.state_evaluations.append(state); self.add("T1003.001", "insufficient_evidence", "medium", "sm.credential.lsass_incomplete", "LSASS evidence is incomplete.", lsass["matched"][-1].evidence, state=state)

        environment = evaluate_distinct("sm.evasion.environment", semantic["environment"], 2, 30)
        state = self._state("sm.evasion.environment", environment, ["two distinct system characteristics", "same PID", "within 30 seconds"])
        if environment.get("complete"):
            self.state_evaluations.append(state); self.add("T1497.001", "candidate", "medium", "sm.evasion.environment", "Multiple environment checks correlated; an evasion-dependent branch is not proven.", environment["matched"][-1].evidence, state=state)
        elif environment.get("matched"):
            self.state_evaluations.append(state); self.add("T1497.001", "insufficient_evidence", "low", "sm.evasion.environment_incomplete", "One generic system query is insufficient for virtualization/sandbox evasion.", environment["matched"][-1].evidence, state=state)

        registry = evaluate_distinct(
            "sm.discovery.registry_query", semantic["registry_query"], 2, 120,
            attribute="target_id", target_label="registry",
            missing_label="distinct Registry query target(s)",
        )
        state = self._state("sm.discovery.registry_query", registry, [
            "completed Registry query API", "structured key/value target",
            "same source PID", "two distinct targets within 120 seconds",
        ])
        if registry.get("complete"):
            self.state_evaluations.append(state)
            self.add("T1012", "observed", "medium", "sm.discovery.registry_query", "Multiple distinct Registry query targets were observed in the same analyzed process.", registry["matched"][-1].evidence, state=state)
        elif registry.get("matched"):
            self.state_evaluations.append(state)
            self.add("T1012", "candidate", "low", "sm.discovery.registry_query_single", "A Registry value was queried, but one distinct target alone has a strong benign alternative.", registry["matched"][-1].evidence, state=state)

        debugger = evaluate_sequence(
            SequenceRule("sm.evasion.debugger_probe", ("debugger_probe",), (), 30),
            semantic["debugger"],
        )
        state = self._state("sm.evasion.debugger_probe", debugger, [
            "completed debugger-query API", "clean analyzed-process lineage",
            "exact API or ProcessInformationClass; no keyword matching",
        ])
        if debugger.get("complete"):
            self.state_evaluations.append(state)
            self.add("T1622", "observed", "medium", "sm.evasion.debugger_probe", "The analyzed process explicitly queried whether it was being debugged; a negative result does not negate the probe.", debugger["matched"][-1].evidence, state=state)

        key_hook = evaluate_sequence(
            SequenceRule("sm.collection.keylogging_hook", ("keyboard_hook",), ("keylog_artifact",), 600, require_same_target=False),
            semantic["keylogging"],
        )
        state = self._state("sm.collection.keylogging_hook", key_hook, [
            "successful SetWindowsHookExA/W", "HookIdentifier is WH_KEYBOARD or WH_KEYBOARD_LL",
            "global ThreadId=0", "clean analyzed-process lineage",
        ])
        if key_hook.get("complete"):
            self.state_evaluations.append(state)
            self.add(
                "T1056.001", "observed", "high", "sm.collection.keylogging_hook",
                "A successful global keyboard hook directly established a keystroke-capture callback.",
                key_hook["matched"][-1].evidence, state=state,
            )
        else:
            weak = [event for event in semantic["keylogging"] if event.kind in {"keyboard_hook_thread", "keyboard_poll"}]
            if weak:
                result = {
                    "complete": False, "matched": weak[:1], "missing": ["successful global keyboard hook"],
                    "optional": [], "key": {"pid": weak[0].pid, "target": "keyboard"},
                    "state_trace": [weak[0].kind], "optional_states": [],
                }
                state = self._state("sm.collection.keylogging_hook", result, [
                    "keyboard API is necessary but not sufficient", "global capture state required for observed",
                ])
                self.state_evaluations.append(state)
                self.add(
                    "T1056.001", "candidate", "medium", "sm.collection.keylogging_precursor",
                    "Keyboard polling or a thread-scoped hook was observed, but global keystroke capture was not proven.",
                    weak[0].evidence, state=state,
                )

        capture_api = evaluate_sequence(
            SequenceRule("sm.collection.screen_capture_api", ("screen_api",), (), 30, require_same_target=False),
            semantic["screen_capture"],
        )
        if capture_api.get("complete"):
            state = self._state("sm.collection.screen_capture_api", capture_api, [
                "successful BitBlt/StretchBlt/PrintWindow", "clean analyzed-process lineage",
            ])
            self.state_evaluations.append(state)
            self.add(
                "T1113", "observed", "high", "sm.collection.screen_capture_api",
                "A successful screen-capture primitive was observed.",
                capture_api["matched"][-1].evidence, state=state,
            )

        image_artifacts = [event for event in semantic["screen_capture"] if event.kind == "image_artifact"]
        image_content = [event for event in semantic["screen_capture"] if event.kind == "image_content"]
        repeated_images = evaluate_distinct(
            "sm.collection.screen_capture_artifacts", image_artifacts, 2, 300,
            attribute="artifact_id", target_label="screen", missing_label="distinct image artifact(s)",
        )
        content = next((event for event in image_content if str(event.pid) == str((repeated_images.get("key") or {}).get("pid"))), None)
        artifact_complete = bool(repeated_images.get("complete") and content)
        artifact_result = {
            "complete": artifact_complete,
            "matched": list(repeated_images.get("matched") or []) + ([content] if content else []),
            "missing": ([] if artifact_complete else list(repeated_images.get("missing") or []) + ([] if content else ["image magic signature"])),
            "optional": [], "key": repeated_images.get("key"),
            "state_trace": (["image_artifact"] * len(repeated_images.get("matched") or [])) + (["image_content"] if content else []),
            "optional_states": [],
        }
        if artifact_result["matched"]:
            state = self._state("sm.collection.screen_capture_artifacts", artifact_result, [
                "same source PID", "two distinct image paths within 300 seconds",
                "successful image write with JPEG/PNG/BMP magic", "not sandbox-generated screenshots",
            ])
            self.state_evaluations.append(state)
            if artifact_complete:
                self.add(
                    "T1113", "observed", "high", "sm.collection.screen_capture_artifacts",
                    "Repeated image materialization plus an image magic signature proved automated screen-image collection.",
                    content.evidence, state=state,
                )
            else:
                self.add(
                    "T1113", "candidate", "medium", "sm.collection.screen_capture_artifacts_incomplete",
                    "Image artifacts were created, but repetition and content gates for automated screen capture were incomplete.",
                    artifact_result["matched"][-1].evidence, state=state,
                )

        location = evaluate_distinct(
            "sm.discovery.system_location", semantic["location"], 2, 120,
            attribute="location_type", target_label="location", missing_label="distinct location signal(s)",
        )
        if location.get("matched"):
            state = self._state("sm.discovery.system_location", location, [
                "structured locale/time-zone/geolocation API", "same source PID",
                "two distinct signal types required for observed",
            ])
            self.state_evaluations.append(state)
            self.add(
                "T1614", "observed" if location.get("complete") else "candidate",
                "medium" if location.get("complete") else "low", "sm.discovery.system_location",
                "Multiple independent location signals were queried." if location.get("complete") else "A locale signal was queried, but one signal alone has a strong benign alternative.",
                location["matched"][-1].evidence, state=state,
            )

        smtp_success = evaluate_sequence(
            SequenceRule("sm.network.smtp_success", ("smtp_connect_success", "smtp_command_success"), (), 120),
            semantic["smtp"],
        )
        if smtp_success.get("complete"):
            state = self._state("sm.network.smtp_success", smtp_success, [
                "successful connection to TCP 25/465/587", "same PID and socket",
                "successful structured SMTP command", "ordered within 120 seconds",
            ])
            self.state_evaluations.append(state)
            self.add(
                "T1071.003", "observed", "high", "sm.network.smtp_success",
                "A successful SMTP connection and protocol command were observed on the same socket.",
                smtp_success["matched"][-1].evidence, state=state,
            )

        smtp_attempt = evaluate_sequence(
            SequenceRule("sm.network.smtp_attempt", ("smtp_connect_attempt", "smtp_command_attempt"), (), 120),
            semantic["smtp"],
        )
        if smtp_attempt.get("complete"):
            state = self._state("sm.network.smtp_attempt", smtp_attempt, [
                "failed connection to TCP 25/465/587", "same PID and socket",
                "structured SMTP command attempted", "no completed SMTP session",
            ])
            state["outcome"] = "attempted"
            state["scoreable"] = False
            self.state_evaluations.append(state)
            self.add(
                "T1071.003", "attempted", "medium", "sm.network.smtp_attempt",
                "The analyzed process attempted SMTP on a mail port, but the connection and send failed; this is not completed C2.",
                smtp_attempt["matched"][-1].evidence, state=state,
            )

    def _map_chains(self) -> None:
        chains = self.chains.get("chains") if isinstance(self.chains, dict) else []
        for chain in chains or []:
            if not isinstance(chain, dict): continue
            kind = str(chain.get("chain_type") or ""); confidence = str(chain.get("confidence") or "medium")
            steps = chain.get("steps") or []
            last = (steps[-1].get("evidence") or {}) if steps and isinstance(steps[-1], dict) else (chain.get("open_process") or chain.get("create") or {})
            evidence = self._evidence("behavior_chain", chain.get("interpretation") or kind, last, last, {"chain_type": kind})
            technique = chain.get("mitre_candidate")
            if technique:
                self.add(str(technique), "observed" if confidence == "high" else "candidate", confidence, f"chain.{kind}", chain.get("interpretation") or "Validated behavior chain matched.", evidence)
            if kind == "injection_precursor" and not chain.get("confirmed_injection_sequence"):
                self.add("T1055", "insufficient_evidence", "medium", "chain.injection_precursor", chain.get("interpretation") or "Injection prerequisites were incomplete.", evidence)
            if kind in {"process_hollowing", "injection_process_hollowing"} and chain.get("confirmed_injection_sequence"):
                self.add("T1055.012", "observed", "high", "chain.process_hollowing", "A confirmed process-hollowing chain was observed.", evidence)

    def _eligible_network(self):
        rows = []
        for protocol in ("http", "dns", "tls", "smtp", "irc", "tcp", "udp", "icmp"):
            for row in (self.results.get("network") or {}).get(protocol) or []:
                if not isinstance(row, dict): continue
                attributions = row.get("requester_attributions") or [row.get("attribution") or {}]
                if any(item.get("tracked") is True for item in attributions if isinstance(item, dict)) and row.get("signature_eligible") is True:
                    rows.append((protocol, row))
        return rows

    def _map_signatures(self) -> None:
        overrides = {
            "unpacker": ["T1027.002", "T1140"], "compression": ["T1027.002", "T1140"],
            "decryption": ["T1027", "T1140"], "network_payload_download": ["T1105"],
            "network_dns_suspicious": ["T1071.004"], "network_smtp": ["T1071.003"],
            "network_cnc_encrypted": ["T1573"],
        }
        payload_evidence = []
        for payload in self.results.get("payloads") or []:
            values = payload.values() if isinstance(payload, dict) else []
            for metadata in values:
                if isinstance(metadata, dict) and metadata.get("sha256"):
                    payload_evidence.append({
                        "sha256": metadata.get("sha256"), "size": metadata.get("size"),
                        "cape_type": metadata.get("cape_type") or metadata.get("type") or "",
                        "pid": metadata.get("pid"),
                    })
        payload_count = len(payload_evidence)
        payload_evidence = payload_evidence[:5]
        for signature in self.results.get("signatures") or []:
            if not isinstance(signature, dict): continue
            name = str(signature.get("name") or ""); low = name.lower(); ids = signature.get("ttps") or []
            if isinstance(ids, str): ids = [ids]
            if not ids: ids = [row.get("ttp") for row in self.results.get("ttps") or [] if row.get("signature") == name]
            if low in overrides: ids = overrides[low]
            elif low.startswith(("http_", "https_", "network_http", "network_cnc_http")): ids = ["T1071.001"]
            signature_details = {"signature": name, "severity": signature.get("severity"), "confidence": signature.get("confidence")}
            if low in {"unpacker", "compression", "decryption"}:
                signature_details["extracted_payload_count"] = payload_count
                signature_details["extracted_payloads"] = payload_evidence
            evidence = self._evidence("signature", signature.get("description") or name, details=signature_details)
            for raw_id in ids:
                technique, original = normalize_technique_id(raw_id)
                if not technique: continue
                if low.startswith(NETWORK_PREFIXES) and not self._eligible_network():
                    self.add(technique, "insufficient_evidence", "medium", "signature.network_unattributed", "Network content matched, but no eligible flow was attributed to analyzed lineage.", evidence, original); continue
                if technique == "T1140" and low in {"unpacker", "compression", "decryption"} and not payload_count:
                    self.add(technique, "candidate", "medium", f"signature.{name}", "Unpacking/deobfuscation behavior matched, but no extracted artifact was preserved to corroborate completion.", evidence, original)
                    continue
                observed = "injection" in low or (signature.get("confidence") or 0) >= 90
                self.add(technique, "observed" if observed else "candidate", "high" if observed else "medium", f"signature.{name}", "A matched signature declared this ATT&CK ID; signature logic remains independently testable.", evidence, original)

    def _network_quality(self) -> dict:
        network = self.results.get("network") or {}; capture = network.get("capture") or {}; runtime = capture.get("runtime") or {}
        attribution = network.get("attribution") or {}; clock = attribution.get("clock_correlation") or runtime.get("clock_sync") or {}
        clock_status = str(clock.get("status") or "unknown")
        segmented = clock_status == "clock_segmented"
        discontinuity = clock_status == "clock_discontinuity" or (
            bool(clock.get("discontinuity_detected")) and not bool(clock.get("usable"))
        )
        clock_usable = bool(clock.get("usable")) if "usable" in clock else clock_status not in {"unreliable", "unsynchronized", "clock_discontinuity"}
        if discontinuity and not segmented:
            clock_usable = False
        return {
            "capture_status": runtime.get("status") or ("complete" if capture.get("path") else "missing"),
            "clock_status": clock_status, "clock_usable": clock_usable, "clock_discontinuity": discontinuity,
            "clock_segmented": segmented, "slew_detected": bool(clock.get("slew_detected")) or clock_status == "clock_slew_compensated",
            "drift_detected": bool(clock.get("drift_detected")), "packet_loss_status": runtime.get("packet_loss_status") or "unknown",
            "mapped_flows": (attribution.get("flows") or {}).get("mapped", 0), "tracked_flows": (attribution.get("flows") or {}).get("tracked", 0),
        }

    def _map_network(self) -> None:
        quality = self._network_quality()
        if quality["capture_status"] != "complete":
            self.warnings.append({"code": "network_capture_incomplete", "severity": "warning", "message": "Network mappings are suppressed because capture is incomplete."}); return
        if not quality["clock_usable"]:
            if quality.get("clock_discontinuity"):
                self.warnings.append({"code": "network_clock_discontinuity", "severity": "error", "message": "Network mappings are suppressed because the guest/server clock jumped during capture; PID attribution would be unsafe."})
            else:
                self.warnings.append({"code": "network_clock_unusable", "severity": "warning", "message": "Network mappings are suppressed because clock correlation is unusable."})
            return
        if quality["clock_segmented"]:
            self.warnings.append({"code": "network_clock_segmented", "severity": "warning", "message": "Only events outside isolated clock-discontinuity intervals are eligible for network mapping."})
        if quality["slew_detected"]:
            self.warnings.append({"code": "network_clock_slew", "severity": "warning", "message": "Continuous clock slew was compensated with the measured piecewise model; attributed network techniques remain candidates."})
        elif quality["drift_detected"]:
            self.warnings.append({"code": "network_clock_drift", "severity": "warning", "message": "Clock drift was detected; attributed network techniques remain candidates."})
        if quality["packet_loss_status"] not in {"none_observed", "unknown"}:
            self.warnings.append({"code": "network_packet_loss", "severity": "warning", "message": "Packet drops were reported; absence is inconclusive."})
        technique_by_protocol = {"http": "T1071.001", "dns": "T1071.004", "smtp": "T1071.003", "tls": "T1573", "irc": "T1071", "icmp": "T1095"}
        for protocol, row in self._eligible_network():
            technique = technique_by_protocol.get(protocol)
            if not technique: continue
            attribution = row.get("attribution") or {}
            if protocol == "dns" and row.get("requester_attributions"):
                attribution = next((item for item in row["requester_attributions"] if item.get("tracked") is True), attribution)
            status = "candidate" if quality["drift_detected"] or quality["clock_segmented"] else "observed"
            confidence = "medium" if status == "candidate" or attribution.get("confidence") != "high" else "high"
            host = row.get("host") or row.get("request") or row.get("server_name") or row.get("dst") or ""
            evidence = self._evidence("network_attribution", f"Tracked {protocol.upper()} activity: {host}", attribution,
                                      {"timestamp": row.get("time") or row.get("first_seen")},
                                      {"host": host, "src": row.get("src"), "sport": row.get("sport"), "dst": row.get("dst"), "dport": row.get("dport"), "traffic_class": row.get("traffic_class"), "attribution_confidence": attribution.get("confidence")})
            self.add(technique, status, confidence, f"network.{protocol}.tracked", "Protocol activity was attributed to analyzed lineage and passed capture, clock and traffic-class gates.", evidence)

    def _detector_coverage(self) -> dict:
        all_domains = _safe_json(_catalog_path()).get("domains") or {}; rows = {}
        for domain, metadata in all_domains.items():
            techniques = metadata.get("techniques") or {}; total = len(techniques)
            if domain != ATTACK_DOMAIN:
                rows[domain] = {"catalog_techniques": total, "supported": 0, "partially_supported": 0, "unsupported_by_sensor": total, "not_applicable_to_platform": 0, "sensor_domain_enabled": False}; continue
            applicable = {tid for tid, item in techniques.items() if ACTIVE_PLATFORM in (item.get("platforms") or [])}
            supported = applicable & SUPPORTED; partial = applicable & PARTIAL
            rows[domain] = {
                "catalog_techniques": total, "supported": len(supported), "partially_supported": len(partial),
                "unsupported_by_sensor": max(0, len(applicable) - len(supported) - len(partial)),
                "not_applicable_to_platform": max(0, total - len(applicable)), "sensor_domain_enabled": True,
                "supported_ids": sorted(supported), "partial_ids": sorted(partial),
            }
        return {"active_domain": ATTACK_DOMAIN, "active_platform": ACTIVE_PLATFORM, "domains": rows, "sensor_matrix": SENSORS,
                "meaning": "Catalog coverage is not detector coverage. Unsupported techniques were not evaluated and must not be interpreted as absent."}

    def _coverage(self) -> dict:
        processes = (self.results.get("behavior") or {}).get("processes") or []
        raw_calls = sum(len(process.get("calls") or []) for process in processes if isinstance(process, dict)); signatures = self.results.get("signatures") or []
        if not processes: self.warnings.append({"code": "behavior_missing", "severity": "error", "message": "No behavior was available; ATT&CK absence is not meaningful."})
        if self.p3_report and (self.p3_report.get("telemetry_continuity") or {}).get("status") not in {None, "complete_observed"}:
            self.warnings.append({"code": "behavior_continuity_degraded", "severity": "warning", "message": "Behavior continuity was degraded; some techniques may be missing."})
        return {
            "behavior": {"available": bool(processes), "processes": len(processes), "raw_calls": raw_calls, "clean_calls": len(self.clean_rows) if self.clean_rows else raw_calls, "source": self.clean_source},
            "signatures": {"matched": len(signatures), "with_attack_ids": sum(bool(row.get("ttps")) for row in signatures if isinstance(row, dict))},
            "behavior_chains": {"available": bool(self.chains), "chains": len(self.chains.get("chains") or []) if isinstance(self.chains, dict) else 0},
            "network": self._network_quality(), "detectors": self._detector_coverage(), "limitations": [row["code"] for row in self.warnings],
        }

    def build(self) -> dict:
        self._map_target_masquerading(); self._map_calls(); self._map_chains(); self._map_signatures(); self._map_network(); coverage = self._coverage()
        resolved = {technique for technique, row in self.mappings.items() if row.get("status") in {"observed", "attempted"}}
        rejected = [row for row in self.rejected if row.get("id") not in resolved]
        mappings = sorted(self.mappings.values(), key=lambda row: (-STATUS_RANK.get(row.get("status"), 0), -CONFIDENCE_RANK.get(row.get("confidence"), 0), row.get("id", "")))
        tactic_rows = {}
        for mapping in mappings:
            for tactic in mapping.get("tactics") or ["uncategorized"]:
                row = tactic_rows.setdefault(tactic, {"id": tactic, "name": TACTIC_LABELS.get(tactic, tactic.replace("-", " ").title()), "observed": 0, "attempted": 0, "candidate": 0, "techniques": []})
                row[mapping["status"]] += 1; row["techniques"].append(mapping["id"])
        tactics = sorted(tactic_rows.values(), key=lambda row: row["name"])
        return {
            "schema": SCHEMA, "attack_version": self.catalog_meta.get("attack_version") or ATTACK_VERSION,
            "domain": ATTACK_DOMAIN, "platform": ACTIVE_PLATFORM, "processor_version": PRODUCT_VERSION, "catalog": self.catalog_meta,
            "summary": {
                "techniques": len(mappings),
                "observed": sum(row.get("status") == "observed" for row in mappings),
                "attempted": sum(row.get("status") == "attempted" for row in mappings),
                "candidate": sum(row.get("status") == "candidate" for row in mappings),
                "insufficient_evidence": len({row.get("id") for row in rejected}),
                "tactics": len(tactics),
            },
            "tactics": tactics, "mappings": mappings,
            "rejected_candidates": sorted(rejected, key=lambda row: (row.get("id", ""), row.get("rule_id", ""))),
            "state_machine_evaluations": self.state_evaluations, "coverage": coverage, "coverage_warnings": self.warnings,
            "semantics": {
                "observed": "Successful semantic evidence or a validated state machine supports the technique.",
                "attempted": "A direct technique action was attempted but failed; completion is not claimed.",
                "candidate": "Evidence is compatible but has a benign alternative or quality limitation.",
                "insufficient_evidence": "A precursor was seen but required states were missing.",
                "unsupported_by_sensor": "The catalog technique was not evaluated by the current sensor/rule profile.",
                "legacy_status_aliases": {"not_supported": "insufficient_evidence"},
            },
        }


def map_mitre_attack(results: dict, analysis_path: Optional[Any] = None, write_artifact: bool = True) -> dict:
    path = Path(analysis_path) if analysis_path else None
    preparation = prepare_clean_behavior(results, path) if path else {"available": False, "reason": "not_requested"}
    report = AttackMapper(results, path).build()
    if path and not preparation.get("available"):
        report["coverage_warnings"].append({"code": "clean_behavior_prepare_failed", "severity": "warning", "message": str(preparation.get("reason"))})
        report["coverage"]["limitations"] = [row.get("code") for row in report["coverage_warnings"]]
    if write_artifact and path: _atomic_json(path / "mitre_attack.json", report)
    return report
