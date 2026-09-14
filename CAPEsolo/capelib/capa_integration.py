"""Offline capa 9.4.0 enrichment. Never executes a sample or changes risk scores.

The adapter consumes canonical clean records, NOT display compaction or raw
fallback. Static results and dynamic candidates remain separate from native P3
observations. Engine result documents retain source-call provenance.
"""
from __future__ import annotations
import copy
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from CAPEsolo.capelib.analysis_quality import collect_quality, read_json
from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION
from CAPEsolo.capelib.evidence_snapshot import REVISION, validate_snapshot, validate_calls

ENGINE_VERSION = "9.4.0"
DATA = Path(__file__).resolve().parents[1] / "data" / "capa"
DEFAULTS = {"enabled": True, "dynamic": True, "static": True, "cache": True, "python": "",
            "executable": "", "rules_dir": "", "signatures_dir": "", "dynamic_timeout": 600,
            "static_timeout": 600, "max_static_files": 8, "max_file_bytes": 67108864,
            "max_clean_bytes": 268435456, "max_calls": 250000, "max_output_bytes": 134217728}


def _retry_file_operation(operation, *args):
    for attempt in range(4):
        try:
            return operation(*args)
        except OSError as exc:
            transient = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 32, 33} or exc.errno in {13, 16}
            if not transient or attempt == 3:
                raise
            time.sleep(0.05 * (attempt + 1))


def _cleanup_file(path, warnings):
    try:
        _retry_file_operation(os.unlink, path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        warnings.append({"operation": "remove_temporary_file", "path": str(path),
                         "error": f"{type(exc).__name__}: {exc}"})


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
        _retry_file_operation(os.replace, temp, path)
    finally:
        # A cleanup sharing violation must never hide the publication error.
        _cleanup_file(temp, [])


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def rule_identity(directory):
    h = hashlib.sha256()
    files = sorted(p for p in Path(directory).rglob("*") if p.is_file() and p.suffix in {".yml", ".yaml"})
    for p in files:
        h.update(p.relative_to(directory).as_posix().encode() + b"\0" + bytes.fromhex(sha256(p)))
    return {"sha256": h.hexdigest(), "rule_files": len(files)}


def signature_identity(directory):
    h = hashlib.sha256()
    files = sorted(Path(directory).glob("*.sig"))
    for p in files:
        h.update(p.name.encode() + b"\0" + bytes.fromhex(sha256(p)))
    return {"sha256": h.hexdigest(), "files": len(files)}


def load_settings(overrides=None):
    config = dict(DEFAULTS)
    selected = os.environ.get("P32317_CAPA_SETTINGS")
    path = Path(selected) if selected else DATA / "settings.json"
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("capa settings must be an object")
        config.update(value)
    elif selected:
        raise ValueError("P32317_CAPA_SETTINGS does not exist")
    config.update(overrides or {})
    for k in ("dynamic_timeout", "static_timeout", "max_static_files", "max_file_bytes", "max_clean_bytes", "max_calls", "max_output_bytes"):
        if not isinstance(config[k], int) or isinstance(config[k], bool) or config[k] <= 0:
            raise ValueError("invalid positive integer setting: " + k)
    for k in ("enabled", "dynamic", "static", "cache"):
        if not isinstance(config[k], bool):
            raise ValueError("invalid boolean setting: " + k)
    config["rules_dir"] = str(Path(config["rules_dir"]).resolve()) if config["rules_dir"] else str(DATA / "rules")
    config["signatures_dir"] = str(Path(config["signatures_dir"]).absolute()) if config["signatures_dir"] else str(DATA / "sigs")
    return config


def _number(value):
    text = str(value).strip()
    return int(text, 16 if text.lower().startswith("0x") else 10)


def project_dynamic(results, clean_path, config):
    """Validate each projected call against its original PID/call ID/content."""
    clean_path = Path(clean_path)
    if not clean_path.is_file():
        raise ValueError("missing_clean_behavior")
    if clean_path.stat().st_size > config["max_clean_bytes"]:
        raise ValueError("clean_input_size_limit")
    target = results.get("target") or {}
    target = target.get("file") or target
    if "PE" not in str(target.get("type")) or not (target.get("pe") or {}).get("imagebase"):
        raise ValueError("dynamic_requires_pe_target_metadata")
    for k in ("md5", "sha1", "sha256"):
        if not re.fullmatch("[0-9a-fA-F]{%d}" % {"md5":32,"sha1":40,"sha256":64}[k], str(target.get(k, ""))):
            raise ValueError("missing_target_hash_" + k)
    snapshot = validate_snapshot(clean_path.parent, results, read_json(clean_path.parent / "frida_p3_runtime.json"))
    if snapshot:
        validate_calls(results, clean_path)
    processes = {}
    originals = {}
    for process in (results.get("behavior") or {}).get("processes") or []:
        pid = _number(process["process_id"])
        if pid in processes:
            raise ValueError("ambiguous_duplicate_process_id")
        processes[pid] = process
        for call in process.get("calls") or []:
            key = (pid, str(call.get("id")))
            # Duplicate original identities cannot be reliably linked.
            if key in originals:
                raise ValueError("ambiguous_original_call_id")
            originals[key] = call
    projected, sources, seen = {}, {}, set()
    counters = Counter()
    with clean_path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("provenance") == "unknown":
                raise ValueError("target_lineage_unresolved_unknown_clean_calls")
            pid = _number(row["pid"])
            call = row["call"]
            key = (pid, str(call.get("id")))
            if key not in originals or (not snapshot and originals[key] != call):
                raise ValueError("clean_original_mismatch_at_line_%d" % lineno)
            if key in seen:
                raise ValueError("duplicate_clean_call_identity")
            seen.add(key)
            if row.get("filter_from_clean_view") is True or row.get("provenance") == "framework_frida":
                raise ValueError("non_clean_row_in_canonical_input")
            counters["clean_records"] += 1
            if counters["clean_records"] > config["max_calls"]:
                raise ValueError("clean_call_limit")
            if call.get("category") == "__notification__":
                counters["notification_records_omitted"] += 1
                continue
            tid = _number(call["thread_id"])
            process = processes[pid]
            if pid not in projected:
                projected[pid] = {"process_id": pid, "parent_id": _number(process["parent_id"]),
                    "process_name": str(process["process_name"]), "calls": [], "threads": [],
                    "environ": {str(k): str(v) for k, v in (process.get("environ") or {}).items() if v is not None}}
            out = projected[pid]
            if tid not in out["threads"]:
                out["threads"].append(tid)
            index = len(out["calls"])
            arguments = call.get("arguments")
            if not isinstance(arguments, list):
                raise ValueError("unsupported_argument_shape")
            args = []
            for a in arguments:
                if a.get("redacted") is True:
                    counters["redacted_arguments_omitted"] += 1
                    continue
                v = a.get("value")
                if not isinstance(v, (str, int)) and v != []:
                    raise ValueError("unsupported_argument_value")
                args.append({"name": str(a["name"]), "value": v})
            api = call.get("api")
            if not isinstance(api, str) or not api:
                raise ValueError("missing_api_name")
            out["calls"].append({"thread_id": tid, "api": api, "arguments": args, "return": _number(call["return"])})
            sources[f"{pid}:{tid}:{index}"] = {"pid": pid, "ppid": out["parent_id"], "thread_id": tid,
                "call_index": index, "call_id": call.get("id"), "timestamp": call.get("timestamp"),
                "api": api, "status": call.get("status"), "return": call.get("return"),
                "repeated": call.get("repeated", 0), "clean_line": lineno, "provenance": row.get("provenance")}
            counters["projected_calls"] += 1
            counters["failed_status_calls"] += int(call.get("status") is False)
            counters["records_with_repetitions"] += int(bool(call.get("repeated")))
    if not projected:
        raise ValueError("empty_clean_behavior")
    # CAPE extractor requires PE metadata. Deliberately omit static imports,
    # strings and global behavior summaries: this projection is API-only.
    file_meta = {k: target[k] for k in ("type", "md5", "sha1", "sha256")}
    file_meta["pe"] = {"imagebase": target["pe"]["imagebase"]}
    projection = {"info": {"version": PRODUCT_VERSION}, "target": {"file": file_meta},
                  "behavior": {"processes": list(projected.values())}}
    provenance = {"schema": "capesolo-capa-sources/1.0", "clean_sha256": sha256(clean_path),
                  "target_sha256": target["sha256"], "source": "behavior.filtered.jsonl",
                  "counts": dict(counters), "calls": sources,
                  "limitations": ["api_only_projection_static_features_omitted", "failed_calls_retained_capa_does_not_validate_success", "repetitions_not_expanded_or_retimed"]}
    if counters["redacted_arguments_omitted"]:
        provenance["limitations"].append("historical_redacted_arguments_not_recoverable")
    if snapshot:
        provenance["snapshot_origin"] = snapshot["origin"]
        provenance["snapshot_manifest_sha256"] = sha256(clean_path.parent / "behavior.snapshot.json")
    return projection, provenance


def _locations(node):
    if isinstance(node, dict):
        if node.get("success") is False:
            return
        if "type" in node and "value" in node:
            yield node
        for k, v in node.items():
            if k not in {"source", "meta"}:
                yield from _locations(v)
    elif isinstance(node, (tuple, list)):
        for item in node:
            yield from _locations(item)


def summarize_engine(document, sources=None):
    if not isinstance(document, dict) or not isinstance(document.get("rules"), dict) or not isinstance(document.get("meta"), dict):
        raise ValueError("invalid_capa_result_document")
    rows = []
    for name, rule in sorted(document["rules"].items()):
        meta = rule.get("meta") or {}
        if meta.get("lib") or (meta.get("maec") or {}).get("analysis-conclusion"):
            continue
        refs, seen = [], set()
        call_status = Counter()
        locations = []
        for loc in _locations(rule.get("matches") or []):
            if len(locations) < 20 and loc not in locations:
                locations.append(loc)
            value = loc.get("value")
            if loc.get("type") == "call" and isinstance(value, (list, tuple)) and len(value) == 4 and sources:
                ppid, pid, tid, index = value
                key = f"{pid}:{tid}:{index}"
                ref = (sources.get("calls") or {}).get(key)
                if ref and ref.get("ppid") == ppid and key not in seen:
                    seen.add(key)
                    call_status["success_status" if ref.get("status") is True else "failed_status" if ref.get("status") is False else "unknown_status"] += 1
                    if len(refs) < 32:
                        refs.append(ref)
        attack = meta.get("attack") or []
        ids = sorted({str(a.get("id")) for a in attack if isinstance(a, dict) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(a.get("id")))})
        rows.append({"name": name, "namespace": meta.get("namespace"), "scopes": meta.get("scopes"),
                     "attack_ids": ids, "attack": attack, "mbc": meta.get("mbc") or [],
                     "match_count": len(rule.get("matches") or []), "locations": locations,
                     "call_evidence": refs, "linked_calls": len(seen), "call_status_counts": dict(call_status), "evidence_display_truncated": len(seen) > len(refs),
                     "interpretation": "candidate_requires_native_validation" if sources else "static_capability_not_execution"})
    return rows


def _engine_command(config):
    if config.get("executable"):
        return [str(config["executable"])]
    return [str(config.get("python") or sys.executable), "-m", "capa.main"]


def _run_engine(command, input_path, output, config, dynamic):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    cache_path = output.with_suffix(".cache.json")
    fingerprint = {"input_sha256": sha256(input_path), "engine_version": ENGINE_VERSION,
                   "rules_sha256": config.get("_rules_sha256"), "dynamic": dynamic, "command": command}
    if not dynamic:
        fingerprint["signatures_sha256"] = config.get("_signatures_sha256")
    if config.get("cache", True) and output.is_file() and output.stat().st_size <= config["max_output_bytes"]:
        cached = read_json(cache_path)
        if cached.get("fingerprint") == fingerprint and cached.get("raw_sha256") == sha256(output):
            try:
                doc = json.loads(output.read_text(encoding="utf-8"))
                summarize_engine(doc)
                return {"status": "ok", "capabilities": [], "raw_result": output.name, "raw_sha256": cached["raw_sha256"],
                        "document": doc, "cache_hit": True, "elapsed_seconds": 0, "exit_code": 0,
                        "original_elapsed_seconds": cached.get("original_elapsed_seconds"),
                        "cache_created_utc": cached.get("created_utc"), "timing_semantics": "cached_result_no_engine_execution"}
            except (OSError, ValueError, TypeError):
                pass
    started = time.monotonic()
    status = {"status": "error", "capabilities": [], "cache_hit": False, "cleanup_warnings": []}
    process, temporary = None, []
    try:
        args = command + ["-j", "-r", config["rules_dir"], "-f", "cape" if dynamic else "auto"]
        if not dynamic:
            args += ["-s", config["signatures_dir"]]
        args.append(str(input_path))
        # ExitStack closes even the first descriptor if allocating the second fails.
        # Close parent handles immediately after spawn; wait for child exit before
        # parsing/replacing/removing the files (Windows sharing semantics).
        with ExitStack() as handles:
            fd, stdout_path = tempfile.mkstemp(dir=str(output.parent), suffix=".capa.tmp")
            temporary.append(stdout_path)
            out = handles.enter_context(os.fdopen(fd, "wb"))
            errfd, stderr_path = tempfile.mkstemp(dir=str(output.parent), suffix=".stderr.tmp")
            temporary.append(stderr_path)
            err = handles.enter_context(os.fdopen(errfd, "wb"))
            process = subprocess.Popen(args, stdout=out, stderr=err, shell=False, close_fds=True)
        status["engine_pid"] = process.pid
        deadline = started + config["dynamic_timeout" if dynamic else "static_timeout"]
        while process.poll() is None:
            if time.monotonic() > deadline:
                status.update(status="timeout", reason="engine_timeout")
                process.kill()
                break
            if os.path.getsize(stdout_path) + os.path.getsize(stderr_path) > config["max_output_bytes"]:
                status.update(status="output_limit", reason="engine_output_limit")
                process.kill()
                break
            time.sleep(0.1)
        process.wait()
        status["exit_code"] = process.returncode
        with open(stderr_path, "rb") as f:
            status["diagnostic"] = f.read(4096).decode("utf-8", "replace")
        if status["status"] in {"timeout", "output_limit"}:
            return status
        if os.path.getsize(stdout_path) + os.path.getsize(stderr_path) > config["max_output_bytes"]:
            status.update(status="output_limit", reason="engine_output_limit")
            return status
        if process.returncode != 0:
            status["reason"] = "engine_nonzero_exit"
            return status
        with open(stdout_path, encoding="utf-8") as f:
            doc = json.load(f)
        summarize_engine(doc)
        try:
            _retry_file_operation(os.replace, stdout_path, output)
        except OSError as exc:
            status.update(status="output_publish_error", reason=f"{type(exc).__name__}: {exc}")
            return status
        digest = sha256(output)
        status.update(status="ok", raw_result=output.name, raw_sha256=digest, document=doc)
        try:
            atomic_json(cache_path, {"fingerprint": fingerprint, "raw_sha256": digest,
                "original_elapsed_seconds": round(time.monotonic() - started, 3),
                "created_utc": datetime.now(timezone.utc).isoformat()})
        except OSError as exc:
            status["cache_warning"] = str(exc)
        return status
    except (OSError, ValueError, TypeError) as exc:
        status["reason"] = f"{type(exc).__name__}: {exc}"
        return status
    finally:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as exc:
                status["cleanup_warnings"].append({"operation": "stop_engine", "error": str(exc)})
        status["elapsed_seconds"] = round(time.monotonic() - started, 3)
        for path in temporary:
            _cleanup_file(path, status["cleanup_warnings"])


def _static_candidates(results, base, explicit):
    target = results.get("target") or {}
    target = target.get("file") or target
    expected = str(target.get("sha256") or "").lower()
    # Explicit target always binds by hash. No unrelated sample gets attributed.
    if explicit:
        yield Path(explicit), "target", expected
    else:
        candidates = [Path(str(target.get("path") or "")), base / str(target.get("name") or ""), base / ("s_" + expected)]
        path = next((p for p in candidates if p.is_file()), candidates[-1])
        yield path, "target", expected
    classified = read_json(base / "frida_artifact_classification.json")
    runtime = read_json(base / "frida_p3_runtime.json")
    if runtime.get("run_id") and classified.get("run_id") != runtime["run_id"]:
        return
    for row in classified.get("artifacts") or []:
        if not isinstance(row, dict) or not row.get("is_pe") or row.get("instrumentation") or row.get("instrumentation_possible"):
            continue
        rel = str(row.get("path") or "").replace("\\", "/")
        p = (base / rel).resolve()
        expected_artifact = str(row.get("sha256") or "").lower()
        if not expected_artifact and re.fullmatch(r"[0-9a-fA-F]{64}", p.name):
            expected_artifact = p.name.lower()
        if p.is_relative_to(base.resolve()) and expected_artifact:
            yield p, "retained_artifact", expected_artifact


def analyze_capa(results, analysis_dir, output_dir=None, overrides=None, static_file=None, static_dir=None):
    base, out = Path(analysis_dir), Path(output_dir or analysis_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = {"schema": "capesolo-capa/1.1", "processor_version": PRODUCT_VERSION, "processor_revision": REVISION,
              "expected_engine_version": ENGINE_VERSION,
              "policy": {"dynamic": "candidate_only", "static": "capability_only", "risk_score_contribution": 0},
              "dynamic": {"status": "not_run", "capabilities": []}, "static": {"status": "not_run", "files": []}}
    progress = {"schema": "capesolo-capa-execution/1.0", "processor_revision": REVISION,
                "owner_pid": os.getpid(), "started_utc": datetime.now(timezone.utc).isoformat()}
    def publish(phase, current_file=None):
        progress.update(phase=phase, updated_utc=datetime.now(timezone.utc).isoformat(), current_file=current_file)
        progress["dynamic_status"] = result["dynamic"]["status"]
        progress["static_status"] = result["static"]["status"]
        try:
            atomic_json(out / "capa_execution.json", progress)
        except OSError as exc:
            result.setdefault("publication_warnings", []).append(str(exc))
    try:
        publish("preflight")
        config = load_settings(overrides)
        result["execution_settings"] = {key: config[key] for key in ("static_timeout", "dynamic_timeout", "cache")}
        if not config["enabled"] or not (config["dynamic"] or config["static"]):
            result["status"] = "disabled"
            result["dynamic"]["status"] = result["static"]["status"] = "disabled"
            return result
        command = _engine_command(config)
        try:
            version = subprocess.run(command + ["--version"], capture_output=True, text=True, timeout=20, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result.update(status="engine_unavailable", reason=str(exc))
            return result
        actual = (version.stdout + version.stderr).strip()
        if version.returncode or not re.search(r"(?<![\d.])9\.4\.0(?![\d.])", actual):
            result.update(status="engine_unavailable" if version.returncode else "version_mismatch", reason=actual[:1000])
            return result
        result["engine_version"] = ENGINE_VERSION
        identity = rule_identity(config["rules_dir"])
        manifest = read_json(DATA / "rules_manifest.json")
        identity["pinned_pack"] = identity["sha256"] == manifest.get("tree_sha256")
        identity["tag"] = manifest.get("tag") if identity["pinned_pack"] else "custom"
        result["rules"] = identity
        config["_rules_sha256"] = identity["sha256"]
        if not identity["rule_files"]:
            result.update(status="rules_unavailable")
            return result
        if config["dynamic"]:
            result["dynamic"]["status"] = "running"
            publish("dynamic")
            try:
                projection, sources = project_dynamic(results, base / "behavior.filtered.jsonl", config)
                atomic_json(out / "capa_dynamic_input.json", projection)
                atomic_json(out / "capa_dynamic_sources.json", sources)
                dynamic = _run_engine(command, out / "capa_dynamic_input.json", out / "capa_dynamic_raw.json", config, True)
                dynamic["input_sha256"] = sha256(out / "capa_dynamic_input.json")
                dynamic["clean_sha256"] = sources["clean_sha256"]
                dynamic["counts"] = sources["counts"]
                dynamic["limitations"] = sources["limitations"]
                dynamic["snapshot_origin"] = sources.get("snapshot_origin", "unmanifested")
                doc = dynamic.pop("document", None)
                if doc:
                    dynamic["capabilities"] = summarize_engine(doc, sources)
                result["dynamic"] = dynamic
            except (OSError, ValueError, TypeError, KeyError) as exc:
                result["dynamic"] = {"status": "input_error", "reason": str(exc), "capabilities": []}
        else:
            result["dynamic"]["status"] = "disabled"
        if config["static"]:
            sigs = signature_identity(config["signatures_dir"])
            result["signatures"] = sigs
            config["_signatures_sha256"] = sigs["sha256"]
            seen = {}
            files = []
            result["static"] = {"status": "running", "files": files}
            publish("static")
            for path, role, expected in _static_candidates(results, Path(static_dir or base), static_file):
                entry = {"path": str(path), "role": role, "expected_sha256": expected, "capabilities": [], "status": "running"}
                files.append(entry)
                publish("static", str(path))
                try:
                    if not sigs["files"]:
                        entry["status"] = "signatures_unavailable"
                    elif not path.is_file():
                        entry["status"] = "missing_file"
                    elif path.stat().st_size > config["max_file_bytes"]:
                        entry["status"] = "input_size_limit"
                    else:
                        digest = sha256(path)
                        entry["sha256"] = digest
                        if digest != expected:
                            entry["status"] = "hash_mismatch"
                        elif digest in seen:
                            entry["status"] = "duplicate"
                            entry["original_status"] = seen[digest].get("status")
                        else:
                            seen[digest] = entry
                            with path.open("rb") as f:
                                pe = f.read(2) == b"MZ"
                            if not pe:
                                entry["status"] = "unsupported_format"
                            elif len(seen) > config["max_static_files"]:
                                entry["status"] = "file_count_limit"
                            else:
                                engine = _run_engine(command, path, out / ("capa_static_" + digest + "_raw.json"), config, False)
                                doc = engine.pop("document", None)
                                entry.update(engine)
                                if sha256(path) != digest:
                                    entry.update(status="input_changed", capabilities=[])
                                elif doc:
                                    entry["capabilities"] = summarize_engine(doc)
                except Exception as exc:
                    entry.update(status="file_error", reason=f"{type(exc).__name__}: {exc}", capabilities=[])
            good = sum(e["status"] == "ok" or (e["status"] == "duplicate" and e.get("original_status") == "ok") for e in files)
            result["static"] = {"status": "ok" if files and good == len(files) else "partial" if good else "unavailable", "files": files}
        else:
            result["static"]["status"] = "disabled"
        states = [result[k]["status"] for k in ("dynamic", "static")]
        result["status"] = "ok" if all(s in {"ok", "disabled"} for s in states) else "partial" if "ok" in states or "partial" in states else "unavailable"
    except Exception as exc:
        result.update(status="integration_error", reason=f"{type(exc).__name__}: {exc}")
    finally:
        progress["result_status"] = result.get("status", "integration_error")
        publish("finished")
        atomic_json(out / "capa_analysis.json", result)
    return result


def correlate_attack(results):
    """Cross-reference pinned capa tags with P3 IDs without changing mappings."""
    from CAPEsolo.capelib.mitre_attack_v12 import normalize_technique_id, load_catalog
    catalog, metadata = load_catalog()
    native = {r.get("id"): r for r in (results.get("mitre_attack") or {}).get("mappings") or []}
    comparison = {}
    capa = results.get("capa") or {}
    groups = [("dynamic", (capa.get("dynamic") or {}).get("capabilities") or [])]
    for file in (capa.get("static") or {}).get("files") or []:
        groups.append(("static", file.get("capabilities") or []))
    for origin, capabilities in groups:
        for capability in capabilities:
            for raw in capability.get("attack_ids") or []:
                current, _ = normalize_technique_id(raw)
                row = comparison.setdefault(current, {"id": current, "original_capa_ids": [],
                    "catalog_known": current in catalog, "p3_status": native.get(current, {}).get("status", "not_mapped"),
                    "p3_sources": native.get(current, {}).get("sources", []), "dynamic_rules": [], "static_rules": []})
                if raw not in row["original_capa_ids"]: row["original_capa_ids"].append(raw)
                if capability["name"] not in row[origin+"_rules"]: row[origin+"_rules"].append(capability["name"])
    return {"catalog_version": metadata.get("attack_version"), "policy": "comparison_only_no_promotion_or_score", "techniques": sorted(comparison.values(), key=lambda r:r["id"])}


def enrich_report(results, analysis_dir, output_dir=None, overrides=None, static_file=None, static_dir=None):
    out = Path(output_dir or analysis_dir)
    results["capa"] = analyze_capa(results, analysis_dir, out, overrides, static_file, static_dir)
    quality = collect_quality(results, out)
    results["analysis_quality"] = quality
    results["capa"]["attack_comparison"] = correlate_attack(results)
    atomic_json(out / "capa_analysis.json", results["capa"])
    atomic_json(out / "analysis_quality.json", quality)
    from CAPEsolo.capelib.rule_coverage import attach_rule_coverage
    attach_rule_coverage(results, out)
    return results["capa"]
