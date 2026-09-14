"""Offline Windows CAR pattern evaluator. Never executes recorded commands.

CAR matches retain the source event and remain candidate/context evidence.
Unsupported telemetry and missing fields are separate from evaluated-no-match.
"""
from __future__ import annotations
import fnmatch, hashlib, json, re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from CAPEsolo.capelib import native_semantics as ns
from CAPEsolo.capelib.sigma_runtime import normalize_events, _field
from CAPEsolo.lib.common.frida_version import PROCESSOR_REVISION
DATA=Path(__file__).resolve().parents[1]/"data/car/windows_catalog.json"
MAX_HITS_PER_ANALYTIC=20
IRREGULAR={"smss.exe":{"smss.exe","system"},"csrss.exe":{"smss.exe","svchost.exe"},
 "wininit.exe":{"smss.exe"},"winlogon.exe":{"smss.exe"},"lsass.exe":{"wininit.exe","winlogon.exe"},
 "logonui.exe":{"winlogon.exe","wininit.exe"},"services.exe":{"wininit.exe"},"spoolsv.exe":{"services.exe"},
 "taskhost.exe":{"services.exe","svchost.exe"},"taskhostw.exe":{"services.exe","svchost.exe"},
 "userinit.exe":{"dwm.exe","winlogon.exe"}}
SYSTEM_NAMES={"svchost.exe","smss.exe","wininit.exe","taskhost.exe","lsass.exe","winlogon.exe",
              "csrss.exe","services.exe","lsm.exe","explorer.exe"}
@lru_cache(maxsize=1)
def load_catalog():
    value=json.loads(DATA.read_text(encoding="utf-8"))
    if value.get("schema")!="capesolo-car-windows/1.0":raise ValueError("invalid_car_catalog")
    return value

def predicate(node, fields):
    """Return True, False or None. None means unknown, including exclusions."""
    op=node[0]
    if op in {"all","any"}:
        values=[predicate(x,fields) for x in node[1:]]
        if op=="all" and False in values:return False
        if op=="any" and True in values:return True
        if None in values:return None
        return bool(values) and (all(values) if op=="all" else any(values))
    field,arg=node[1],node[2];present,value=_field(fields,field)
    if not present:return None
    text=str(value).casefold();path=ns.path(value);name=ns.basename(value)
    if op in {"equal","not_equal"}:
        vals=[str(x).casefold() for x in arg]
        answer=text in vals
        return answer if op=="equal" else not answer
    if op in {"basename","not_basename"}:
        answer=name in [str(x).casefold() for x in arg]
        return answer if op=="basename" else not answer
    if op=="glob":return any(fnmatch.fnmatchcase(path,ns.path(x)) for x in arg)
    if op=="basename_glob":return any(fnmatch.fnmatchcase(name,x.casefold()) for x in arg)
    if op=="regex":return re.search(arg,str(value)) is not None
    if op=="integer":return ns.integer(value) in arg
    if op=="dword":
        number=ns.integer(value)
        if number is None:
            match=re.fullmatch(r"(?i)DWORD\s+\((0x[0-9a-f]+)\)",str(value).strip())
            number=ns.integer(match.group(1)) if match else None
        return number in arg if number is not None else None
    if op in {"tokens_any","first_arg"}:
        tokens=ns.command_tokens(value)
        if not tokens:return None
        args=[x.casefold() for x in tokens[1:]]
        if ns.basename(fields.get("Image")) == "certutil.exe":
            # Captured upstream CAR test data includes slash and Unicode-dash
            # spellings of certutil switches. Normalize only this executable,
            # retaining the original command line in the evidence.
            args=["-"+x[1:] if x and x[0] in "/–—―" else x for x in args]
        return bool(args) and (args[0] in arg if op=="first_arg" else any(x in args for x in arg))
    if op=="different_pid":
        present2,other=_field(fields,arg)
        a,b=ns.integer(value),ns.integer(other)
        if not present2 or not a or not b or a<0 or b<0:return None
        return a!=b
    if op=="irregular_parent":
        present2,other=_field(fields,arg)
        if not present2:return None
        return name in IRREGULAR and ns.basename(other) not in IRREGULAR[name]
    if op=="masquerade_system_path":
        if name not in SYSTEM_NAMES:return False
        if not re.match(r"^[a-z]:\\",path):return None
        allowed={rf"c:\windows\system32\{name}",rf"c:\windows\syswow64\{name}"}
        if name=="explorer.exe":allowed={r"c:\windows\explorer.exe"}
        return path not in allowed
    raise ValueError("unsupported_car_predicate:"+str(op))

def fields_required(node):
    if node[0] in {"all","any"}:return set().union(*(fields_required(x) for x in node[1:]))
    fields={node[1]}
    if node[0] in {"different_pid","irregular_parent"}:fields.add(node[2])
    return fields

def operation_ids(cid, fields, fallback):
    name=ns.basename(fields.get("Image"));args=ns.command_args({"CommandLine":fields.get("CommandLine")})
    if cid in {"CAR-2016-03-001","CAR-2020-11-006"}:
        ids={"hostname.exe":["T1082"],"systeminfo.exe":["T1082"],"ipconfig.exe":["T1016"],
             "tasklist.exe":["T1057"],"whoami.exe":["T1033"],"quser.exe":["T1033"],"qwinsta.exe":["T1033"]}
        if name in ids:return ids[name]
        if name=="sc.exe" and args and args[0] in {"query","qc"}:return ["T1007"]
        if name=="net.exe" and args:
            if "/add" in args or "/delete" in args:return []
            if args[0]=="start" and len(args)==1:return ["T1007"]
            if args[0]=="user":return ["T1087.002" if "/domain" in args else "T1087.001"]
            if args[0]=="localgroup":return ["T1069.001"]
            if args[0]=="group" and "/domain" in args:return ["T1069.002"]
        return []
    if cid=="CAR-2021-05-010":
        if args and args[0]=="user" and "/add" in args:return ["T1136.001"]
        if args and args[0]=="localgroup" and "/add" in args:return ["T1098"]
        return []
    return fallback

def evaluate_car_events(events, available_categories, *, canonical=True):
    catalog=load_catalog();by_category=defaultdict(list)
    for event in events:
        if event.get("excluded") or event.get("provenance") in {"framework_frida","unknown"}:continue
        by_category[event["category"]].append(event)
    evaluations=[];matches=[]
    for analytic in catalog["analytics"]:
        row={k:analytic[k] for k in ("id","title","url","source_url","source_sha256","attack_ids","implementation_status")}
        row.update(status="not_implemented",reason=analytic["deferred_reason"],variants=[],hits=0)
        if not analytic["variants"]:evaluations.append(row);continue
        if not canonical:
            row.update(status="not_evaluable",reason="canonical_clean_evidence_unavailable");evaluations.append(row);continue
        for variant in analytic["variants"]:
            category=variant["category"];relevant=by_category[category]
            vr={"category":category,"variant":variant["variant"],"required_fields":sorted(fields_required(variant["condition"])),
                "status":"not_evaluable","reason":"sensor_unavailable","events":len(relevant),"missing_fields":[]}
            if category not in available_categories:row["variants"].append(vr);continue
            if not relevant:
                vr.update(status="no_events",reason="no_relevant_events_observed");row["variants"].append(vr);continue
            unknown=set();decided=0;found=False
            for event in relevant:
                result=predicate(variant["condition"],event["fields"])
                if result is None:
                    unknown.update(field for field in vr["required_fields"] if not _field(event["fields"],field)[0])
                    if not unknown:unknown.add("unparseable_required_value")
                    continue
                decided+=1
                if result is not True:continue
                found=True
                fallback=variant["attack_ids_override"] if variant["attack_ids_override"] is not None else analytic["attack_ids"]
                ids=operation_ids(analytic["id"],event["fields"],fallback)
                if row["hits"]<MAX_HITS_PER_ANALYTIC:
                    evidence=dict(event.get("evidence") or {})
                    key={"category":category,"pid":evidence.get("pid"),"timestamp":evidence.get("timestamp"),
                         "call_id":evidence.get("call_id"),"api":evidence.get("api"),"fields":event["fields"]}
                    fingerprint=hashlib.sha256(json.dumps(key,sort_keys=True,default=str).encode()).hexdigest()
                    matches.append({"car_id":analytic["id"],"title":analytic["title"],"variant":variant["variant"],
                        "attack_ids":ids,"status":"candidate" if ids else "context","scoreable":False,
                        "evidence":evidence,"evidence_fingerprint":fingerprint,
                        "matched_fields":{f:event["fields"].get(f) for f in vr["required_fields"]},
                        "source_url":analytic["source_url"],"source_sha256":analytic["source_sha256"]})
                row["hits"]+=1
            vr.update(status="matched" if found else "not_evaluable" if unknown else "evaluated_no_match",
                      reason="missing_or_unparseable_event_fields" if unknown and not found else None,
                      missing_fields=sorted(unknown),decided_events=decided)
            row["variants"].append(vr)
        statuses={x["status"] for x in row["variants"]}
        row["status"]="matched" if "matched" in statuses else "not_evaluable" if "not_evaluable" in statuses else "evaluated_no_match" if "evaluated_no_match" in statuses else "no_events"
        row["reason"]=next((x["reason"] for x in row["variants"] if x.get("reason")),None) if row["status"] in {"not_evaluable","no_events"} else None
        evaluations.append(row)
    return {"schema":"capesolo-car-runtime/1.0","revision":PROCESSOR_REVISION,"available":True,"commit":catalog["commit"],
        "policy":{"mapping":"candidate_or_context_only","risk_score_contribution":0,
                  "independence":"CAR/Sigma/native may reuse the same sensor event; rule agreement is not independent acquisition.",
                  "variant_scope":"Selected variants are implemented; all Windows analytics are inventoried."},
        "coverage":{"catalog_analytics":len(evaluations),"runtime_analytics":catalog["runtime_analytics"],
                    "statuses":dict(Counter(x["status"] for x in evaluations)),"retained_matches":len(matches),
                    "truncated_analytics":[x["id"] for x in evaluations if x["hits"]>MAX_HITS_PER_ANALYTIC]},
        "evaluations":evaluations,"matches":matches}

def evaluate_car(results, analysis_path=None, clean_rows=None):
    events,telemetry=normalize_events(results,clean_rows,analysis_path)
    # Do not treat background/sandbox process metadata as malware. Successful
    # canonical rows provide the source-process scope; empty metadata-only
    # processes remain outside this sample-scoped engine.
    pids={str(x.get("pid")) for x in clean_rows or [] if not x.get("filter_from_clean_view") and x.get("provenance") not in {"unknown","framework_frida"}}
    events=[e for e in events if str((e.get("evidence") or {}).get("pid")) in pids]
    report=evaluate_car_events(events,set(telemetry["available_logsources"]),canonical=clean_rows is not None)
    report["telemetry"]={**telemetry,"scope":"canonical_sample_lineage","processes":sorted(pids)}
    if analysis_path:
        from CAPEsolo.capelib.capa_integration import atomic_json
        atomic_json(Path(analysis_path)/"car_analysis.json",report)
    return report
