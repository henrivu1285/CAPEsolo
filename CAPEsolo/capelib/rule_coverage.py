"""Single report of catalog, implementation and run-time eligibility."""
from pathlib import Path
from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION, PROCESSOR_REVISION
def attach_rule_coverage(results, analysis_dir):
    attack=results.get("mitre_attack") or {};sigma=attack.get("sigma") or {};car=attack.get("car") or {}
    capa=results.get("capa") or {};rules=capa.get("rules") or {}
    value={"schema":"capesolo-rule-coverage/1.0","version":PRODUCT_VERSION,"revision":PROCESSOR_REVISION,
        "car":{"commit":car.get("commit"),**(car.get("coverage") or {})},
        "sigma":{"commit":(sigma.get("source") or {}).get("commit"),"pack":sigma.get("pack_summary") or {},
                 "run":sigma.get("coverage") or {}},
        "capa":{"engine":capa.get("engine_version"),"rule_pack":rules,
                "dynamic_status":(capa.get("dynamic") or {}).get("status"),
                "static_status":(capa.get("static") or {}).get("status"),
                "dynamic_matched_capabilities":len((capa.get("dynamic") or {}).get("capabilities") or []),
                "dynamic_projection":"API-only canonical records; missing behavior/static features cannot match",
                "rule_file_count_is_not_evaluated_rule_count":True,
                "static_execution_not_proven":True},
        "interpretation":"Catalog presence, implemented variants, evaluated events and ATT&CK coverage are different denominators. Shared events are not independent corroboration."}
    results["rule_coverage"]=value
    if analysis_dir:
        from CAPEsolo.capelib.capa_integration import atomic_json
        base=Path(analysis_dir)
        atomic_json(base/"rule_coverage.json",value)
        atomic_json(base/"sigma_coverage.json",{"source":sigma.get("source"),"pack":sigma.get("pack_summary"),
            "coverage":sigma.get("coverage"),"rule_evaluations":sigma.get("rule_evaluations",[])})
    return value
