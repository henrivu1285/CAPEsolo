"""Bind passive service evidence to the analysis artifacts; never execute samples."""
from pathlib import Path
import json
from CAPEsolo.lib.common.service_graph import (correlate, service_exe, path_key, stamp, pid, sha, read_json, norm, ref)
from CAPEsolo.lib.common.evtx_recovery import recover_evtx_sidecars

def attach_service_processes(results, analysis_dir):
    base=Path(analysis_dir);runtime=read_json(base/'frida_p3_runtime.json')
    recovery = recover_evtx_sidecars(base, runtime.get('run_id'))
    manifest=read_json(base/'evtx_collection.json');ev=base/'evtx_events.jsonl'
    events=list((runtime.get('sysmon') or {}).get('process_events') or [])
    events.extend((runtime.get('service_tracking') or {}).get('events') or [])
    sources={'frida_p3_runtime.json':sha(base/'frida_p3_runtime.json')} if (base/'frida_p3_runtime.json').is_file() else {}
    warnings=list(recovery.get('warnings', []))
    if manifest:
        if not runtime.get('run_id') or manifest.get('run_id')!=runtime.get('run_id'): warnings.append('evtx_run_id_mismatch')
        elif not ev.is_file() or sha(ev)!=(manifest.get('events') or {}).get('sha256'): warnings.append('evtx_events_missing_or_hash_mismatch')
        else:
            with ev.open(encoding='utf-8') as f:
                for i,line in enumerate(f):
                    if i>=200000: warnings.append('evtx_events_limit');break
                    if line.strip(): events.append(json.loads(line))
            sources.update({ev.name:sha(ev),'evtx_collection.json':sha(base/'evtx_collection.json')})
    clean=[]
    cp=base/'behavior.filtered.jsonl'
    if cp.is_file():
        with cp.open(encoding='utf-8') as f:
            for line in f:
                if line.strip():clean.append(json.loads(line))
        sources[cp.name]=sha(cp)
    value=correlate(results,runtime,events,clean)
    value['source_sha256']=sources
    value['evtx_status']=manifest.get('status','unavailable') if not warnings else 'invalid'
    if (runtime.get('sysmon') or {}).get('process_events_dropped'):
        warnings.append('sysmon_process_event_retention_truncated')
    value['limitations']+=warnings
    value['evtx_recovery']=recovery.get('status')
    value['evtx_expected']=bool((runtime.get('service_tracking') or {}).get('enabled') or value['links'] or value['unresolved_services'] or 'service_creation_missing_scm_evidence' in value['limitations'])
    if value['evtx_status']=='unavailable' and value['evtx_expected']:
        value['limitations'].append('evtx_export_unavailable')
        value['status']='partial'
    if warnings:value['status']='partial'
    results['service_processes']=value
    from CAPEsolo.capelib.capa_integration import atomic_json
    atomic_json(base/'service_processes.json',value)
    return value
