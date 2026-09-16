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
    return {'channel':e.get('channel') or ('Microsoft-Windows-Sysmon/Operational' if e.get('provider')=='Microsoft-Windows-Sysmon' else None), 'provider':e.get('provider'), 'record_id':e.get('record_id'), 'utc_time':e.get('utc_time')}


def extend_service_descendants(out, events, results, allowed):
    """Follow observed OS edges, keeping service creator separate from OS parent.

    GUID, host, PID, image and lifetime must agree. A later instance of the same
    PID must never inherit an earlier instance's relationship.
    """
    creations = [e for e in events if e.get('provider') == 'Microsoft-Windows-Sysmon' and e['event_id'] == 1]
    known = {(p.get('computer'), p['process_guid']): p for p in out['links']}
    for _ in range(32):
        added = False
        for e in creations:
            d = e['data']; host = e.get('computer')
            guid = str(d.get('ProcessGuid') or '').strip('{}').upper()
            parent_guid = str(d.get('ParentProcessGuid') or '').strip('{}').upper()
            parent = known.get((host, parent_guid)); at = stamp(e['utc_time'])
            if not guid or (host, guid) in known or not parent or guid == parent_guid:
                continue
            if pid(d.get('ParentProcessId')) != parent['process_id'] or path_key(d.get('ParentImage')) != path_key(parent['image']):
                continue
            if at < stamp(parent['process_created_utc']):
                continue
            if any(stamp(v['utc_time']) <= at for v in parent.get('termination_events', [])):
                continue
            instances = [v for v in creations if v.get('computer') == host and pid(v['data'].get('ProcessId')) == parent['process_id'] and stamp(v['utc_time']) <= at]
            if instances and str(instances[-1]['data'].get('ProcessGuid') or '').strip('{}').upper() != parent_guid:
                continue
            p = pid(d.get('ProcessId')); image = path_key(d.get('Image'))
            if not p or not image:
                continue
            own = [v for v in events if v.get('provider') == 'Microsoft-Windows-Sysmon' and v.get('computer') == host and str(v['data'].get('ProcessGuid') or '').strip('{}').upper() == guid]
            loaded = [{'image_loaded': v['data'].get('ImageLoaded'), **ref(v)} for v in own if v['event_id'] == 7]
            meta = allowed.get(p, {})
            api = any(pid(v.get('process_id')) == p and path_key(v.get('module_path') or v.get('process_path')) == image and v.get('calls') for v in (results.get('behavior') or {}).get('processes', []))
            api = bool(api and str(meta.get('sysmon_guid') or '').strip('{}').upper() == guid)
            hashes = dict(s.split('=', 1) for s in str(d.get('Hashes') or '').split(',') if '=' in s)
            link = {'service_name': parent['service_name'], 'creator_pid': parent['creator_pid'],
                    'service_process_id': parent.get('service_process_id', parent['process_id']),
                    'process_id': p, 'process_guid': guid, 'image': d.get('Image'),
                    'parent_pid': pid(d.get('ParentProcessId')), 'parent_image': d.get('ParentImage'),
                    'parent_process_guid': parent_guid, 'computer': host,
                    'user': d.get('User'), 'session_id': d.get('TerminalSessionId'),
                    'command_line': d.get('CommandLine'), 'current_directory': d.get('CurrentDirectory'),
                    'binary_sha256': hashes.get('SHA256'), 'role': 'service_descendant',
                    'link_status': 'observed', 'process_created_utc': e['utc_time'],
                    'service_state': 'not_applicable_descendant',
                    'api_coverage': 'observed' if api else 'not_observed',
                    'loaded_images': loaded, 'dll_load_coverage': 'observed' if loaded else 'not_observed',
                    'termination_events': [ref(v) for v in own if v['event_id'] == 5],
                    'evidence': parent['evidence'] + [ref(e)]}
            out['links'].append(link); known[(host, guid)] = link; added = True
            if len(known) >= 1000:
                out['limitations'].append('service_graph_node_limit'); return
        if not added:
            return
    out['limitations'].append('service_graph_depth_limit')

def correlate(results, runtime, events, clean_rows):
    run_id=runtime.get('run_id'); start=runtime.get('run_started_wall'); stop=runtime.get('run_stopped_wall')
    out={'schema':'capesolo-service-processes/1', 'revision':'p32320', 'run_id':run_id,
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
    def tracked(p, at, host):
        m=allowed.get(p)
        if m is None or not m.get('sysmon_guid') or (m.get('create_time') or 0)>at: return False
        instances=[e for e in es if e.get('provider')=='Microsoft-Windows-Sysmon' and e['event_id']==1
                   and e.get('computer')==host and pid(e['data'].get('ProcessId'))==p and stamp(e['utc_time'])<=at]
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
        if e.get('provider')=='Microsoft-Windows-Security-Auditing' and e['event_id']==4697 and tracked(p,at,e.get('computer')):
            source=[ref(e)]
        elif e.get('provider')=='Service Control Manager' and e['event_id']==7045:
            match=[a for a in api if a[0]==name and a[1]==image]
            if len({a[2] for a in match})==1 and tracked(match[0][2],at,e.get('computer')):
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
            'parent_image':d.get('ParentImage'), 'parent_process_guid':str(d.get('ParentProcessGuid') or '').strip('{}').upper(), 'computer':e.get('computer'), 'user':d.get('User'), 'session_id':d.get('TerminalSessionId'),
            'command_line':d.get('CommandLine'), 'current_directory':d.get('CurrentDirectory'),
            'binary_sha256':hashes.get('SHA256'), 'role':'service_process', 'link_status':'observed',
            'process_created_utc':e['utc_time'], 'service_state':'startup_timeout_observed' if any(v['event_id']==7009 for v in service_errors) else 'unknown',
            'api_coverage':'observed' if api_observed else 'not_observed', 'loaded_images':loaded,
            'dll_load_coverage':'observed' if loaded else 'not_observed', 'termination_events':terminated,
            'evidence':a['evidence']+[ref(e)]+[ref(v) for v in service_errors]})
    extend_service_descendants(out, es, results, allowed)
    for a in merged:
        if id(a) not in linked: out['unresolved_services'].append({'service_name':a['display_name'],'image':a['image'],'creator_pid':a['creator_pid'],'status':'process_not_correlated','evidence':a['evidence']})
    out['status']='partial' if out['limitations'] or out['unresolved_services'] or any(l['api_coverage']=='not_observed' for l in out['links']) else 'linked' if out['links'] else 'no_links'
    if any(l['api_coverage']=='not_observed' for l in out['links']): out['limitations'].append('service_process_api_not_observed')
    if api and not anchors:
        out['limitations'].append('service_creation_missing_scm_evidence')
        out['status']='partial'
    out['events_in_run']=len(es); out['limitations']=sorted(set(out['limitations']))
    return out
