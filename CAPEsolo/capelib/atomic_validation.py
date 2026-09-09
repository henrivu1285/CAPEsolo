"""Offline Atomic catalog, preparation and independent detection evaluation.

Preparing a case does not run it, install prerequisites, or contact a server.
Expected technique IDs are only consumed here, never by native/Sigma/capa.
"""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
import uuid
from pathlib import Path

STARTER_TECHNIQUES = ("T1543.003", "T1547.001", "T1012")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_catalog(repo, techniques=STARTER_TECHNIQUES):
    import yaml
    repo = Path(repo).resolve()
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{40,64}", commit):
        raise ValueError("repository_commit_unavailable")
    rows = []
    seen = set()
    for technique in techniques:
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            raise ValueError("invalid_technique")
        path = repo / "atomics" / technique / (technique + ".yaml")
        if not path.resolve().is_relative_to(repo):
            raise ValueError("test_path_outside_repository")
        if not path.is_file():
            continue
        committed = subprocess.run(["git", "-C", str(repo), "show", commit + ":" + path.relative_to(repo).as_posix()],
                                   capture_output=True, check=True).stdout
        if hashlib.sha256(committed).hexdigest() != sha(path):
            raise ValueError("selected_yaml_differs_from_pinned_commit")
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if doc.get("attack_technique") != technique:
            raise ValueError("technique_directory_mismatch")
        for case in doc.get("atomic_tests", []):
            if "windows" not in case.get("supported_platforms", []):
                continue
            guid = str(uuid.UUID(case["auto_generated_guid"]))
            if guid in seen:
                raise ValueError("duplicate_atomic_guid")
            seen.add(guid)
            if (case.get("executor") or {}).get("name") not in {"powershell", "command_prompt"}:
                continue
            rows.append({"guid": guid, "technique": technique, "name": case["name"],
                         "repo_commit": commit, "yaml_sha256": sha(path),
                         "source_path": path.relative_to(repo).as_posix(), "definition": case})
    return rows


def _substitute(text, inputs, atomics):
    def replace(match):
        name = match.group(1)
        if name not in inputs:
            raise ValueError("missing_atomic_input:" + name)
        return str(inputs[name])
    return re.sub(r"#\{([^}]+)\}", replace, str(text or "")).replace("PathToAtomicsFolder", str(atomics))


def prepare_case(repo, guid, output, overrides=None, oracle=None, timeout=60):
    if not 1 <= timeout <= 1800:
        raise ValueError("timeout_out_of_range")
    output, repo = Path(output).resolve(), Path(repo).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("output_must_be_new_or_empty")
    matches = [r for r in read_catalog(repo) if r["guid"] == str(uuid.UUID(guid))]
    if len(matches) != 1:
        raise ValueError("guid_not_in_windows_starter_catalog")
    row = matches[0]; definition = row["definition"]; executor = definition["executor"]
    inputs = {key: spec.get("default") for key, spec in definition.get("input_arguments", {}).items()}
    if set(overrides or {}) - set(inputs):
        raise ValueError("unknown_atomic_input")
    inputs.update(overrides or {})
    if any(v is None for v in inputs.values()):
        raise ValueError("required_atomic_input_missing")
    inputs = {k: str(v).replace("PathToAtomicsFolder", str(repo / "atomics")) for k, v in inputs.items()}
    if any(any(ch in val for ch in ("\n", "\r", "\0")) for val in inputs.values()):
        raise ValueError("multiline_atomic_input_rejected")
    # Free-form inputs are part of the reviewed command, never shell arguments
    # assembled by Python. The generated command is reviewable before execution.
    command = _substitute(executor.get("command"), inputs, repo / "atomics")
    cleanup = _substitute(executor.get("cleanup_command"), inputs, repo / "atomics")
    if not command.strip():
        raise ValueError("empty_atomic_command")
    dependencies = [{"description": dep.get("description", ""),
                     "executor": definition.get("dependency_executor_name", executor["name"]),
                     "command": _substitute(dep.get("prereq_command"), inputs, repo / "atomics")}
                    for dep in definition.get("dependencies", [])]
    if oracle is None and row["technique"] == "T1543.003" and "service_name" in inputs:
        oracle = {"kind": "service_exists", "name": inputs["service_name"]}
    if oracle and oracle.get("kind") not in {"service_exists", "registry_value", "file_exists", "output_regex"}:
        raise ValueError("unsupported_oracle")
    if oracle:
        for key in {"service_exists": ["name"], "registry_value": ["path", "name", "value"], "file_exists": ["path"], "output_regex": ["pattern"]}[oracle["kind"]]:
            if key not in oracle:
                raise ValueError("missing_oracle_field:" + key)
    case_id = str(uuid.uuid4())
    output.mkdir(parents=True, exist_ok=True)
    extension = ".ps1" if executor["name"] == "powershell" else ".cmd"
    body = ("$ErrorActionPreference = 'Stop'\n$global:LASTEXITCODE = 0\n" + command + "\nif ($LASTEXITCODE) { exit $LASTEXITCODE }\n") if extension == ".ps1" else ("@echo off\r\n" + command + "\r\n")
    script = output / ("command" + extension)
    script.write_text(body, encoding="utf-8-sig" if extension == ".ps1" else "utf-8")
    # Cleanup is a separate phase, not called during the P3 evidence window.
    cleanup_path = output / ("cleanup" + extension)
    cleanup_path.write_text(cleanup or ("# No cleanup specified" if extension == ".ps1" else "rem No cleanup specified"), encoding="utf-8-sig" if extension == ".ps1" else "utf-8")
    manifest = {"schema": "p3-atomic-case/1.0", "case_id": case_id, "source": {k:v for k,v in row.items() if k != "definition"},
                "inputs": inputs, "command_file": script.name, "command_sha256": sha(script),
                "cleanup_file": cleanup_path.name, "cleanup_sha256": sha(cleanup_path),
                "timeout_seconds": timeout, "executor": executor["name"],
                "elevation_required": bool(executor.get("elevation_required")), "prerequisites": dependencies,
                "oracle": oracle, "expected": {"native_id": row["technique"], "minimum_status": "observed"},
                "capa_applicability": "script_target_not_supported_by_current_pe_adapter",
                "state": "prepared_not_executed"}
    template = Path(__file__).resolve().parents[2] / "tools" / "p32318_atomic_runner.ps1"
    (output / "run.ps1").write_bytes(("# Atomic case: " + case_id + "\n").encode() + template.read_bytes())
    manifest["runner_sha256"] = sha(output / "run.ps1")
    (output / "atomic_case.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def evaluate_case(case, execution, results, runtime, clean_rows, case_hash=None):
    """Execution/oracle facts and detection evidence are separate prerequisites."""
    expected = case["expected"]["native_id"]
    output = {"schema": "p3-atomic-validation/1.0", "case_id": case["case_id"], "technique": expected,
              "status": "inconclusive", "native": "not_evaluated", "sigma": "not_evaluated",
              "capa": case.get("capa_applicability"), "reason": "", "unexpected_candidates": [],
              "coverage_semantics": "Only this test variant; not full technique coverage or malware probability."}
    def stop(status, reason):
        output.update(status=status, reason=reason)
        return output
    if execution.get("case_id") != case["case_id"] or (case_hash and execution.get("case_sha256") != case_hash):
        return stop("identity_mismatch", "execution_case_mismatch")
    target = results.get("target") or {}; target = target.get("file") or target
    if target.get("sha256") != case.get("runner_sha256"):
        return stop("identity_mismatch", "report_is_not_this_runner")
    if execution.get("command_sha256") != case["command_sha256"]:
        return stop("identity_mismatch", "executed_command_hash_mismatch")
    if execution.get("state") != "completed" or execution.get("exit_code") != 0:
        return stop("execution_failed", execution.get("reason") or execution.get("state") or "no_execution_result")
    if execution.get("oracle_passed") is not True:
        return stop("inconclusive", "behavior_not_independently_confirmed")
    root = str(execution.get("execution_pid") or "")
    wrapper = str(execution.get("wrapper_pid") or "")
    if str(runtime.get("target_pid") or "") != wrapper or root not in runtime.get("lineage", {}):
        return stop("sensor_gap", "execution_pid_not_enrolled_in_this_run")
    # Commands and descendants only. Wrapper/prerequisite/oracle calls cannot
    # validate a test that they happen to resemble.
    allowed = {root}
    lineage = runtime.get("lineage") or {}
    for _ in range(len(lineage)):
        added = {str(pid) for pid, row in lineage.items() if str(row.get("parent_pid") or row.get("ppid")) in allowed}
        if added <= allowed: break
        allowed.update(added)
    observed = [r for r in clean_rows if str(r.get("pid")) in allowed and r.get("provenance") not in {"unknown", "framework_frida"}]
    if not observed:
        return stop("sensor_gap", "no_clean_calls_for_execution")
    attack = results.get("mitre_attack") or {}; quality = results.get("analysis_quality") or {}
    if quality.get("evidence_consistency", {}).get("status") in {"mismatch", "capa_source_mismatch"}:
        return stop("normalization_error", "evidence_consistency_failed")
    rank = {"candidate": 1, "attempted": 0, "observed": 2}
    required = rank.get(case["expected"].get("minimum_status", "candidate"), 1)
    mappings = [m for m in attack.get("mappings", []) if m.get("id") == expected]
    native = any(rank.get(m.get("status"), 0) >= required and any(str(e.get("pid")) in allowed and e.get("source") not in {"sigma_rule", "capa_dynamic", "capa_static"} for e in m.get("evidence", [])) for m in mappings)
    output["native"] = "pass" if native else "miss"
    sigma = attack.get("sigma") or {}
    output["sigma"] = "no_match" if sigma.get("available") else "unavailable"
    output["sigma_coverage"] = sigma.get("coverage", {})
    # Sigma matching is supplementary; never require every atomic to hit a rule.
    if any(str((m.get("evidence") or {}).get("pid")) in allowed for m in sigma.get("matches", [])):
        output["sigma"] = "match_review_technique_and_rule"
    output["unexpected_candidates"] = sorted({m.get("id") for m in attack.get("mappings", []) if m.get("id") != expected and any(str(e.get("pid")) in allowed for e in m.get("evidence", []))})
    output["eligible_pids"] = sorted(allowed)
    output["acquisition_quality"] = quality.get("status", "unknown")
    return stop("pass_with_limits" if native and quality.get("status") != "complete" else "pass" if native else "detector_miss",
                "variant_detected" if native else "confirmed_execution_with_clean_telemetry_not_detected")
