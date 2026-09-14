"""Passive, evidence-bound service process correlation. Never starts/attaches a process.

A service is an indirect execution edge, not an OS parent-child edge. Keep those
identities separate and never manufacture CAPEMON calls or successful SCM state.
"""
from __future__ import annotations
import hashlib
import json
import ntpath
import re
from datetime import datetime
from pathlib import Path


def read_json(path):
    try:
        v = json.loads(Path(path).read_text(encoding='utf-8'))
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError): return {}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1048576), b''): h.update(b)
    return h.hexdigest()

def pid(v):
    try: return int(str(v), 0)
    except (ValueError, TypeError):
        try: return int(v)
        except (ValueError, TypeError): return 0

def stamp(value):
    try:
        d=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return d.timestamp() if d.tzinfo else None
    except (ValueError, TypeError, OverflowError): return None

def path_key(value):
    s=str(value or '').strip().replace('/', '\\')
    if s.startswith('\\??\\'): s=s[4:]
    if s.startswith('\\\\?\\'): s=s[4:]
    if not re.match(r'^[A-Za-z]:\\', s) or '%' in s: return ''
    return ntpath.normpath(s).casefold()

def service_exe(value):
    s=str(value or '').strip()
    if s.startswith('"'):
        end=s.find('"',1)
        return path_key(s[1:end]) if end>1 else ''
    # Unquoted paths containing spaces are ambiguous to SCM. Do not guess.
    first=s.split()[0] if s else ''
    return path_key(first) if first.lower().endswith('.exe') else ''

def norm(e):
    d=e.get('data') or {}
    return {**e, 'event_id':pid(e.get('event_id', e.get('event'))),
            'record_id':e.get('record_id',e.get('record')), 'utc_time':e.get('utc_time',e.get('time','')),
            'data':d}

def ref(e):
    return {'channel':e.get('channel'), 'provider':e.get('provider'), 'record_id':e.get('record_id'), 'utc_time':e.get('utc_time')}

def correlate(results, runtime, events, clean_rows):
    run_id=runtime.get('run_id'); start=runtime.get('run_started_wall'); stop=runtime.get('run_stopped_wall')
    out={'schema':'capesolo-service-processes/1', 'revision':'p32319-fix1', 'run_id':run_id,
         'status':'unavailable', 'links':[], 'unresolved_services':[], 'limitations':[],
         'interpretation':'Process creation does not prove service RUNNING, DLL loading, API coverage or network activity.'}
    if not run_id or not isinstance(start,(int,float)) or not isinstance(stop,(int,float)) or stop < start:
        out['limitations'].append('run_window_unavailable'); return out
    es=[]; seen=set()
    for raw in events:
        e=norm(raw); t=stamp(e['utc_time'])
        if t is None or not start <= t <= stop+2: continue
        key=(e.get('provider'),e.get('computer'),e.get('record_id'),e.get('utc_time'))
        if key in seen: continue
        seen.add(key);es.append(e)
    es.sort(key=lambda e:(stamp(e['utc_time']),str(e.get('record_id'))))
    lineage=runtime.get('lineage') or {}
    allowed={pid(k):v for k,v in lineage.items() if isinstance(v,dict)}
    root=pid(runtime.get('target_pid'))
    if root and root not in allowed: allowed[root]={}
    def tracked(p, at):
        m=allowed.get(p)
        if m is None or not m.get('sysmon_guid') or (m.get('create_time') or 0)>at: return False
        instances=[e for e in es if e.get('provider')=='Microsoft-Windows-Sysmon' and e['event_id']==1
                   and pid(e['data'].get('ProcessId'))==p and stamp(e['utc_time'])<=at]
        if not instances: return False
        current=str(instances[-1]['data'].get('ProcessGuid') or '').strip('{}').upper()
        return current==str(m['sysmon_guid']).strip('{}').upper()
    api=[]
    for row in clean_rows:
        c=row.get('call') or {}; p=pid(row.get('pid'))
        if p not in allowed or row.get('filter_from_clean_view') or row.get('provenance') in {'framework','instrumentation','background'}: continue
        if c.get('api') not in {'CreateServiceW','CreateServiceA'} or c.get('status') is not True: continue
        args={a.get('name'):a.get('value') for a in c.get('arguments',[]) if isinstance(a,dict)}
        name=str(args.get('ServiceName') or '').casefold(); image=service_exe(args.get('BinaryPathName'))
        if name and image: api.append((name,image,p,{'source':'behavior.filtered.jsonl','pid':p,'call_id':row.get('call_id',c.get('id'))}))
    anchors=[]
    for e in es:
        d=e['data'];p=pid(d.get('ClientProcessId'));at=stamp(e['utc_time'])
        name=str(d.get('ServiceName') or '').casefold()
        image=service_exe(d.get('ServiceFileName') or d.get('ImagePath'))
        if not name or not image: continue
        source=[]
        if e.get('provider')=='Microsoft-Windows-Security-Auditing' and e['event_id']==4697 and tracked(p,at):
            source=[ref(e)]
        elif e.get('provider')=='Service Control Manager' and e['event_id']==7045:
            match=[a for a in api if a[0]==name and a[1]==image]
            if len({a[2] for a in match})==1 and tracked(match[0][2],at):
                p=match[0][2];source=[ref(e),match[0][3]]
        if source: anchors.append({'name':name,'display_name':str(d.get('ServiceName') or name),'image':image,'creator_pid':p,'time':at,'computer':e.get('computer'), 'evidence':source})
    # Merge dual 7045/4697 observations of the same installation, not different creators.
    merged=[]
    for a in anchors:
        old=next((x for x in merged if (x['name'],x['image'],x['creator_pid'],x['computer'])==(a['name'],a['image'],a['creator_pid'],a['computer']) and abs(x['time']-a['time'])<=2),None)
        if old: old['evidence'].extend(a['evidence']);old['time']=min(old['time'],a['time'])
        else: merged.append(a)
    creations=[e for e in es if e.get('provider')=='Microsoft-Windows-Sysmon' and e['event_id']==1]
    linked=set()
    for e in creations:
        d=e['data'];at=stamp(e['utc_time']);image=path_key(d.get('Image'));guid=str(d.get('ProcessGuid') or '').strip('{}').upper()
        if path_key(d.get('ParentImage')) != r'c:\windows\system32\services.exe': continue
        if not guid or not pid(d.get('ProcessId')): continue
        candidates=[a for a in merged if a['image']==image and a['time']<=at and a['computer']==e.get('computer')]
        # A later reconfiguration of a service supersedes its earlier installation.
        candidates=[a for a in candidates if not any(b['name']==a['name'] and b['computer']==a['computer'] and a['time']<b['time']<=at for b in merged)]
        if len(candidates)!=1:
            if candidates: out['limitations'].append('ambiguous_service_image_match')
            continue
        a=candidates[0];linked.add(id(a));p=pid(d.get('ProcessId'))
        own=[v for v in es if str(v['data'].get('ProcessGuid') or '').strip('{}').upper()==guid and v.get('provider')=='Microsoft-Windows-Sysmon' and v.get('computer')==e.get('computer')]
        loaded=[{'image_loaded':v['data'].get('ImageLoaded'),**ref(v)} for v in own if v['event_id']==7]
        terminated=[ref(v) for v in own if v['event_id']==5]
        service_errors=[v for v in es if v.get('provider')=='Service Control Manager' and v['event_id'] in {7009,7000,7031,7034}
                        and v.get('computer')==a['computer'] and stamp(v['utc_time'])>=at and str(v['data'].get('param2') if v['event_id']==7009 else v['data'].get('param1') or '').casefold()==a['name']]
        monitored=[v for v in (results.get('behavior') or {}).get('processes',[]) if pid(v.get('process_id'))==p and path_key(v.get('module_path') or v.get('process_path'))==image and v.get('calls')]
        # Only consider CAPEMON coverage when its process instance is corroborated by runtime GUID.
        m=allowed.get(p,{})
        api_observed=bool(monitored and str(m.get('sysmon_guid') or '').strip('{}').upper()==guid)
        hashes=dict(part.split('=',1) for part in str(d.get('Hashes') or '').split(',') if '=' in part)
        out['links'].append({'service_name':a['display_name'], 'creator_pid':a['creator_pid'], 'process_id':p,
            'process_guid':guid, 'image':d.get('Image'), 'parent_pid':pid(d.get('ParentProcessId')),
            'parent_image':d.get('ParentImage'), 'user':d.get('User'), 'session_id':d.get('TerminalSessionId'),
            'command_line':d.get('CommandLine'), 'current_directory':d.get('CurrentDirectory'),
            'binary_sha256':hashes.get('SHA256'), 'role':'service_process', 'link_status':'observed',
            'process_created_utc':e['utc_time'], 'service_state':'startup_timeout_observed' if any(v['event_id']==7009 for v in service_errors) else 'unknown',
            'api_coverage':'observed' if api_observed else 'not_observed', 'loaded_images':loaded,
            'dll_load_coverage':'observed' if loaded else 'not_observed', 'termination_events':terminated,
            'evidence':a['evidence']+[ref(e)]+[ref(v) for v in service_errors]})
    for a in merged:
        if id(a) not in linked: out['unresolved_services'].append({'service_name':a['display_name'],'image':a['image'],'creator_pid':a['creator_pid'],'status':'process_not_correlated','evidence':a['evidence']})
    out['status']='partial' if out['unresolved_services'] or any(l['api_coverage']=='not_observed' for l in out['links']) else 'linked' if out['links'] else 'no_links'
    if any(l['api_coverage']=='not_observed' for l in out['links']): out['limitations'].append('service_process_api_not_observed')
    out['events_in_run']=len(es); out['limitations']=sorted(set(out['limitations']))
    return out

def attach_service_processes(results, analysis_dir):
    base=Path(analysis_dir);runtime=read_json(base/'frida_p3_runtime.json')
    manifest=read_json(base/'evtx_collection.json');ev=base/'evtx_events.jsonl'
    events=list((runtime.get('sysmon') or {}).get('process_events') or [])
    sources={'frida_p3_runtime.json':sha(base/'frida_p3_runtime.json')} if (base/'frida_p3_runtime.json').is_file() else {}
    warnings=[]
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
    if warnings:value['status']='partial'
    results['service_processes']=value
    from CAPEsolo.capelib.capa_integration import atomic_json
    atomic_json(base/'service_processes.json',value)
    return value
