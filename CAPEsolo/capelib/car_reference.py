"""Pinned CAR review metadata and four explicitly scoped event comparators.

Comparators are an offline validation aid, not a feed that adds ATT&CK scores.
Native, Sigma and capa evidence retain their original producers.
"""
from __future__ import annotations
import fnmatch
import json
import re
from pathlib import Path
from CAPEsolo.capelib import native_semantics as ns
DATA = Path(__file__).resolve().parents[1] / 'data/car'
COMMIT = '1b922fe1527d956e222a99473472e594f10f610b'

def normalize_event(raw):
    source = raw.get('_source', raw)
    return {'event_id': ns.integer(source.get('event_id', source.get('EventID'))),
            'image': ns.path(source.get('process_path', source.get('Image'))),
            'parent': ns.path(source.get('process_parent_path', source.get('ParentImage')) or source.get('process_parent_name')),
            'command_line': source.get('process_command_line', source.get('CommandLine')),
            'pid': ns.integer(source.get('process_id', source.get('SourceProcessId'))),
            'target_pid': ns.integer(source.get('process_target_id', source.get('TargetProcessId'))),
            'start_function': source.get('thread_start_function', source.get('StartFunction')),
            'file': ns.path(source.get('file_name', source.get('TargetFilename'))),
            'timestamp': source.get('@event_date_creation', source.get('UtcTime')),
            'event_record_id': source.get('record_number', source.get('EventRecordID'))}

def evaluate_event(raw, trusted_injectors=()):
    """Return analytic hits; missing fields cannot satisfy negative predicates.

    CAR implementations have differing details. This selects documented
    pseudocode variants, with explicit PID checks for the injection variant.
    A hit means suspicious pattern, not proof of attack intent or UAC bypass.
    """
    e=normalize_event(raw);hits=[]; name=ns.basename(e['image'])
    if e['event_id'] == 8 and e['start_function'] in {'LoadLibraryA','LoadLibraryW'} and e['pid'] and e['target_pid'] and e['pid'] != e['target_pid'] and e['image'] and e['image'] not in {ns.path(x) for x in trusted_injectors}:
        hits.append({'car_id':'CAR-2013-10-002','attack_ids':['T1055.001'],'variant':'remote LoadLibrary + explicit different PIDs; UAC not inferred'})
    if e['event_id'] == 1 and name == 'powershell.exe' and e['parent'] and ns.basename(e['parent']) != 'explorer.exe':
        hits.append({'car_id':'CAR-2014-04-003','attack_ids':['T1059.001'],'variant':'non-interactive parent pseudocode'})
    if e['event_id'] == 1 and name in {'hostname.exe','ipconfig.exe','net.exe','quser.exe','qwinsta.exe','sc.exe','systeminfo.exe','tasklist.exe','whoami.exe'} and e['command_line']:
        args=ns.command_args({'CommandLine':e['command_line']})
        ids={'hostname.exe':['T1082'],'ipconfig.exe':['T1016'],'quser.exe':['T1033'],'qwinsta.exe':['T1033'],'systeminfo.exe':['T1082'],'tasklist.exe':['T1057'],'whoami.exe':['T1033']}.get(name,[])
        if name == 'sc.exe' and args and args[0] in {'query','qc'}:ids=['T1007']
        if name == 'net.exe' and args:
            if args[0]=='start' and len(args)==1:ids=['T1007']
            elif args[0]=='user':ids=['T1087.002' if '/domain' in args else 'T1087.001']
            elif args[0]=='localgroup':ids=['T1069.001']
            elif args[0]=='group' and '/domain' in args:ids=['T1069.002']
        # The upstream analytic broadly monitors net.exe. Keep empty tags if
        # operation intent is not supported; never emit every upstream tag.
        if name != 'sc.exe' or ids:
            hits.append({'car_id':'CAR-2016-03-001','attack_ids':ids,'variant':'exact command monitor; operation-specific tags only'})
    if e['event_id'] == 11 and name == 'taskmgr.exe' and e['image'].startswith('c:\\windows\\') and fnmatch.fnmatchcase(ns.basename(e['file']),'lsass*.dmp'):
        hits.append({'car_id':'CAR-2019-08-001','attack_ids':['T1003.001'],'variant':'Task Manager file-create pattern; dump content unverified'})
    return hits

def annotate_report(report):
    try:
        audit=json.loads((DATA/'native_audit.json').read_text(encoding='utf-8'))
        if audit['car_commit'] != COMMIT:
            raise ValueError('CAR commit mismatch')
    except (OSError, ValueError, KeyError) as exc:
        report['car_review']={'available':False,'error':str(exc),'changes_detection_status':False}
        return
    rows={r['rule_id']:r for r in audit['rules']}
    for mapping in report.get('mappings',[])+report.get('rejected_candidates',[]):
        reviews=[]
        for rule_id in mapping.get('rule_ids',[]) or [mapping.get('rule_id')]:
            key=rule_id
            if key not in rows and key:
                key=next((p+'.*' for p in ('chain','signature','sigma') if key.startswith(p+'.')),key)
            row=rows.get(key)
            reviews.append({'rule_id':rule_id,'review':row or {'review_status':'not_reviewed'}})
        mapping['car_review']=reviews
    report['car_review']={'available':True,'commit':COMMIT,'revision':audit['revision'],
        'native_literal_rules_reviewed':audit['native_literal_rule_count'],'review_entries':len(rows),
        'changes_detection_status':False,'external_event_comparators':4,
        'meaning':'CAR references support a source-code review, not certification or automatic corroboration. See per-rule relation and packaged validation results; Sigma/capa remain separate evidence sources.'}
