#!/usr/bin/env python3
"""Build a pinned full Windows CAR catalog and explicitly scoped runtime variants."""
import argparse, hashlib, json, shutil
from pathlib import Path
import yaml
from car_runtime_specs import SPECS
COMMIT="1b922fe1527d956e222a99473472e594f10f610b"
HISTORY={"CAR-2013-01-002","CAR-2013-02-008","CAR-2013-02-012","CAR-2013-09-005","CAR-2013-10-001","CAR-2014-11-002","CAR-2015-07-001","CAR-2020-05-003","CAR-2021-01-002"}
PROTOCOL={"CAR-2013-05-003","CAR-2013-05-005","CAR-2014-03-001","CAR-2014-11-005","CAR-2014-11-007","CAR-2014-12-001","CAR-2015-04-001","CAR-2015-04-002"}
WINDOWS_LOG={"CAR-2016-04-002","CAR-2016-04-003","CAR-2016-04-004","CAR-2016-04-005","CAR-2019-07-001","CAR-2021-05-012"}
def build(source, output):
    output.mkdir(parents=True,exist_ok=True); rows=[]
    for path in sorted((source/"analytics").glob("*.yaml")):
        raw=path.read_bytes(); data=yaml.safe_load(raw)
        if "Windows" not in data.get("platforms",[]):continue
        cid=data["id"]; specs=SPECS.get(cid,[])
        attack=sorted({tid for c in data.get("coverage",[]) for tid in (c.get("subtechniques") or [c.get("technique")]) if tid})
        reason=("requires_historical_baseline_or_multi_host_context" if cid in HISTORY else
                "requires_decoded_smb_rpc_and_correlation" if cid in PROTOCOL else
                "requires_windows_security_or_system_log_adapter" if cid in WINDOWS_LOG else
                "implementation_pending_semantic_review")
        dst=output/"analytics"/path.name;dst.parent.mkdir(exist_ok=True);dst.write_bytes(raw)
        rows.append({"id":cid,"title":data["title"],"platforms":data.get("platforms"),
            "analytic_types":data.get("analytic_types",[]),"attack_ids":attack,
            "url":"https://car.mitre.org/analytics/"+cid+"/",
            "source_url":f"https://github.com/mitre-attack/car/blob/{COMMIT}/analytics/{path.name}",
            "source_sha256":hashlib.sha256(raw).hexdigest(),"source_file":"analytics/"+path.name,
            "data_model_references":data.get("data_model_references",[]),
            "implementation_status":"implemented_selected_variants" if specs else "not_implemented",
            "deferred_reason":None if specs else reason,"variants":specs,
            "upstream_implementation_count":len(data.get("implementations",[])),
            "validation_scope":"See tests/p32319 and validation/P32319_VALIDATION.json; catalog presence is not validation."})
    pack={"schema":"capesolo-car-windows/1.0","revision":"p32319","commit":COMMIT,
          "source_analytic_count":len(list((source/"analytics").glob("*.yaml"))),
          "windows_analytics":len(rows),"runtime_analytics":sum(bool(x["variants"]) for x in rows),
          "semantics":"Full Windows catalog. Runtime evaluates selected documented variants, not every upstream implementation.",
          "analytics":rows}
    (output/"windows_catalog.json").write_text(json.dumps(pack,ensure_ascii=False,indent=2),encoding="utf-8")
    for name in ["LICENSE.txt","NOTICE.txt"]:
        if (source/name).exists():shutil.copy2(source/name,output/name)
    return pack
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("source",type=Path);p.add_argument("output",type=Path);a=p.parse_args()
    result=build(a.source,a.output)
    print(json.dumps({k:v for k,v in result.items() if k!="analytics"},indent=2))
