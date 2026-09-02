import json
import logging
import os
from json import dump
from pathlib import Path

from CAPEsolo.capelib.behavior import BehaviorAnalysis
from CAPEsolo.capelib.cape_utils import get_cape_name_from_yara_hit, metadata_processing
from CAPEsolo.capelib.js_log import JsLog
from CAPEsolo.capelib.mitre_attack import ATTACK_DOMAIN, ATTACK_VERSION, SCHEMA as MITRE_SCHEMA, map_mitre_attack
from CAPEsolo.capelib.network import NetworkData
from CAPEsolo.capelib.network_decrypt import DecryptStreams
from CAPEsolo.capelib.network_pid import (
    correlate_capture,
    discover_task_capture,
    load_clock_sync,
    load_network_evidence,
)
from CAPEsolo.capelib.network_summary import InterpretNetworkAbsence, NetworkSummary
from CAPEsolo.capelib.objects import File
from CAPEsolo.capelib.parse_pe import PortableExecutable
from CAPEsolo.capelib.path_utils import path_exists
from CAPEsolo.capelib.signatures import RunSignatures
from CAPEsolo.capelib.threat_assessment import SCHEMA as THREAT_SCHEMA, assess_threat
from CAPEsolo.capelib.utils import LoadFilesJson, extract_strings
from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION

from .behavior_panel import Options
from .configs_panel import Extract
from .process_yara import ProcessYara

log = logging.getLogger(__name__)


def TargetInfo(targetFile):
    fileObj = File(str(targetFile))
    fileinfo = fileObj.get_all()[0]
    peData = PortableExecutable(str(targetFile)).run()
    fileinfo["pe"] = peData
    # The signature runner skips any signature declaring filter_analysistypes unless this
    # matches (signatures.py:1263). Nothing set it, so 8 of the 29 community signatures -
    # including network_http and network_cnc_http - were never even evaluated. CAPEsolo
    # always analyses a file.
    fileinfo["category"] = "file"
    return fileinfo


def BehaviorResults(analysisDir):
    options = Options()
    options.analysis_call_limit = 0
    options.ram_boost = True
    behavior = BehaviorAnalysis()
    behavior.set_path(analysisDir)
    behavior.set_options(options)
    results = behavior.run()

    # Materialise each process's OWN lazy calls (ParseProcessLog) into a plain, JSON-serialisable
    # list. A prior version shared one accumulator across processes, so every process ended up
    # with the cumulative calls of all processes - which made report.json's per-process calls
    # (and any per-process signature reading them) unusable.
    for proc in results.get("processes", []):
        try:
            proc["calls"] = list(proc.get("calls", []))
        except Exception:
            return None

    return results


def Signatures(results, analysisDir):
    RunSignatures(results=results, analysis_path=analysisDir).run()
    return results.get("signatures")


def Payloads(analysisDir):
    data = LoadFilesJson(analysisDir)
    if "error" in data:
        return []
    else:
        data = dict(sorted(data.items(), key=lambda x: x[1]["size"], reverse=True))

    results = []
    for key, value in data.items():
        payloadData = {}
        if key.startswith("aux_"):
            continue

        path = Path(analysisDir) / key
        fileinfo = File(str(path)).get_all()[0]
        metadata = data[key].get("metadata", "")
        if metadata:
            payloadData = metadata_processing(metadata, data[key].get("pids"))

        for key, value in fileinfo.items():
            if key not in "path" and value:
                payloadData[key] = value

        results.append({str(path): payloadData})

    return results


def Configs(yara, analysisDir):
    configHits = []
    detections = []
    for filehits in yara:
        paths = filehits.keys()
        for file in paths:
            for hit in filehits[file]:
                capename = get_cape_name_from_yara_hit(hit)
                if capename:
                    configHits.append({file: capename})
                    if not capename in detections:
                        detections.append(capename)

    configs = Extract(configHits, analysisDir, jsonResults=True)

    return configs, detections


def WriteJsonFile(results, analysisDir=None):
    try:
        desktop = Path(os.path.expanduser("~/Desktop"))
        filepath = desktop / "report.json"
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            dump(results, f, indent=4)

        # P3.2.3.4 keeps the official Desktop report for compatibility and also
        # stores the same current-run report with the raw analysis evidence.
        # Post-processing and the Full/Review result exporters can therefore use
        # one self-contained analysis directory without guessing at a stale
        # report left on the Desktop by a previous run.
        if analysisDir:
            analysis_path = Path(analysisDir).resolve() / "report.json"
            if analysis_path != filepath.resolve():
                with open(analysis_path, "w", encoding="utf-8", errors="replace") as f:
                    dump(results, f, indent=4)

        return True, ""
    except Exception as e:
        return False, e


def GetYara(yara, path):
    for hit in yara:
        data = hit.get(path)
        if data:
            return data

    return None


def Network(analysisDir, results, pcapPath=""):
    """Build the network summary the signatures and reports read.

    Works with no capture at all - the behaviour log and the JS console log are enough for
    hosts, DNS lookups and HTTP requests. A capture adds the wire view, and TLS secrets from
    the analysis add the decrypted plaintext on top of that.
    """
    capture = None
    decrypted = None
    selected_path = Path(pcapPath) if pcapPath else discover_task_capture(analysisDir)
    if selected_path and path_exists(str(selected_path)):
        try:
            capture = NetworkData(analysisDir, selected_path)
            sysmon_events, lineage = load_network_evidence(analysisDir)
            capture = correlate_capture(
                capture,
                sysmon_events,
                lineage,
                clock_sync=load_clock_sync(analysisDir),
            )
        except Exception as e:
            log.warning("Could not parse/correlate the capture %s: %s", selected_path, e)

        try:
            decrypted = DecryptStreams(analysisDir, selected_path)
        except Exception as e:
            log.warning("Could not decrypt streams in %s: %s", selected_path, e)

    network = NetworkSummary(
        behavior=results.get("behavior"),
        jsLog=results.get("js_log"),
        capture=capture,
        decrypted=decrypted,
    )
    runtime_path = Path(analysisDir) / "pcap_runtime.json"
    if runtime_path.is_file():
        try:
            runtime = json.loads(runtime_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            runtime = {}
        if isinstance(runtime, dict):
            network.setdefault("capture", {})["runtime"] = runtime
    runtime = network.get("capture", {}).get("runtime") or {}
    counts = network.get("capture", {}).get("counts") or {}
    flow_counts = network.get("attribution", {}).get("flows") or {}
    if selected_path and capture is not None:
        capture_status = "empty" if counts and int(counts.get("frames") or 0) == 0 else "complete"
    elif str(runtime.get("status") or "").lower() in {"start_failed", "stop_failed", "fetch_failed", "client_unavailable"}:
        capture_status = "failed"
    elif runtime.get("configured") is False or str(runtime.get("status") or "").lower() == "disabled":
        capture_status = "disabled"
    else:
        capture_status = "missing"
    network["absence_interpretation"] = InterpretNetworkAbsence(
        capture_status,
        counts.get("frames"), counts.get("packets"),
        flow_counts.get("total"), flow_counts.get("mapped"), flow_counts.get("tracked"),
        network.get("attribution", {}).get("clock_correlation"),
    )
    network.setdefault("capture", {})["selection"] = (
        "explicit" if pcapPath else ("task_auto" if selected_path else "missing")
    )
    return network


def GetResults(targetFile, analysisDir, writeFile=True, includeStrings=True, pcapPath=""):
    """Build the full analysis report.

    includeStrings=False skips string extraction entirely rather than extracting and then
    discarding: it is the expensive part on an analysis with many payloads.

    pcapPath is the capture the user supplied on the Network tab, if any.
    """
    results = {}
    results["target"] = TargetInfo(targetFile)
    results["behavior"] = BehaviorResults(analysisDir)
    # js_log and network are built before the signatures, which read both: 14 of the shipped
    # network signatures look up results["network"], and previously js_log was populated
    # after they had already run.
    results["js_log"] = JsLog(analysisDir)
    results["network"] = Network(analysisDir, results, pcapPath)
    results["signatures"] = Signatures(results, analysisDir)
    results["payloads"] = Payloads(analysisDir)

    yara = ProcessYara(analysisDir)
    yara.Scan(str(targetFile))
    yara.ScanPayloads()
    yaraData = GetYara(yara.yara_results, str(targetFile))
    if yaraData:
        results["target"]["yara"] = yaraData

    if includeStrings:
        extracted = extract_strings(str(targetFile), dedup=True, minchars=4)
        if extracted:
            results["target"]["strings"] = sorted(list(set(extracted)), key=lambda x: (len(x), x))

    for payload in results.get("payloads", []):
        for path in payload.keys():
            subpath = "/".join(Path(path).parts[-2:])
            yaraData = GetYara(yara.yara_results, subpath)

            if yaraData:
                payload[path]["yara"] = yaraData

            if includeStrings:
                extracted = extract_strings(path, dedup=True, minchars=4)
                if extracted:
                    payload[path]["strings"] = sorted(list(set(extracted)), key=lambda x: (len(x), x))

    results["configs"], results["detections"] = Configs(yara.yara_results, analysisDir)
    try:
        results["mitre_attack"] = map_mitre_attack(results, analysisDir, write_artifact=True)
    except Exception as e:
        # ATT&CK enrichment must never destroy the primary sandbox report. The
        # visible error schema also prevents a silently empty MITRE tab.
        log.exception("Could not build MITRE ATT&CK mapping: %s", e)
        results["mitre_attack"] = {
            "schema": MITRE_SCHEMA,
            "attack_version": ATTACK_VERSION,
            "domain": ATTACK_DOMAIN,
            "processor_version": PRODUCT_VERSION,
            "summary": {"techniques": 0, "observed": 0, "candidate": 0, "insufficient_evidence": 0, "tactics": 0},
            "tactics": [],
            "mappings": [],
            "rejected_candidates": [],
            "coverage": {},
            "coverage_warnings": [{"code": "mapper_failed", "severity": "error", "message": str(e)}],
        }
    try:
        results["threat_assessment"] = assess_threat(results)
    except Exception as e:
        # Scoring is an enrichment layer. A failure must stay visible but must
        # never prevent the evidence report from being written.
        log.exception("Could not build threat assessment: %s", e)
        results["threat_assessment"] = {
            "schema": THREAT_SCHEMA, "score": 0, "maximum_score": 100,
            "verdict": "inconclusive", "threshold_verdict": "benign",
            "confidence": "low", "provisional": True, "components": [],
            "top_reasons": [], "quality": {"limitations": ["assessment_failed"]},
            "interpretation": f"Threat assessment failed: {e}",
        }
    if writeFile:
        return WriteJsonFile(results, analysisDir=analysisDir)
    else:
        return results
