#!/usr/bin/env python3
"""Focused, offline regression checks. Fixtures contain no executable malware."""
from __future__ import annotations
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT))
from CAPEsolo.capelib.sigma_runtime import normalize_events, normalize_pipe_name, evaluate_sigma
from CAPEsolo.capelib.capa_integration import DEFAULTS, DATA, analyze_capa, project_dynamic, summarize_engine, rule_identity, _run_engine
from CAPEsolo.capelib.analysis_quality import collect_quality
from CAPEsolo.capelib.threat_assessment import assess_threat
from tools.frida_behavior_chains import extract_behavior_chains_from_records
from tools.frida_p3_finalize import build_analysis_hygiene


def call(api, args=None, **kw):
    row = {"api":api,"id":1,"thread_id":20,"timestamp":"2026-09-06 01:00:00,000", "category":"process","status":True,"return":"0x0","repeated":0,
           "arguments":[{"name":k,"value":v} for k,v in (args or {}).items()]}
    row.update(kw)
    return row


def report(calls):
    return {"target":{"type":"PE32 executable", "name":"fixture.exe","md5":"a"*32,"sha1":"b"*40,"sha256":"c"*64,"pe":{"imagebase":"0x400000"}},
            "behavior":{"processes":[{"process_id":10,"parent_id":9,"process_name":"fixture.exe","module_path":"C:\\fixture.exe","threads":[20],"environ":{},"calls":calls}]}}


def clean_rows(calls):
    return [{"pid":10,"api":c["api"],"call_id":c["id"],"provenance":"malware_candidate","filter_from_clean_view":False,"call":copy.deepcopy(c)} for c in calls]


def write_rows(path, rows):
    path.write_text("".join(json.dumps(r)+"\n" for r in rows), encoding="utf-8")


class Normalization(unittest.TestCase):
    def test_pipe_namespaces_preserve_inner_components(self):
        for prefix in ("\\??\\pipe\\", "\\\\.\\pipe\\", "\\\\?\\pipe\\", "\\Device\\NamedPipe\\", "\\DEVICE\\NAMEDPIPE\\"):
            self.assertEqual(normalize_pipe_name(prefix+"PSHost.123"), "\\PSHost.123")
            self.assertEqual(normalize_pipe_name(prefix+"evil\\pipe\\svc"), "\\evil\\pipe\\svc")
        self.assertEqual(normalize_pipe_name("\\evil\\pipe\\svc"), "\\evil\\pipe\\svc")

    def test_official_efspotato_negative_and_positive(self):
        rid="637f689e-b4a5-4a86-be0e-0100a0a33ba2"
        def hits(name):
            c=call("NtCreateNamedPipeFile", {"PipeName":name})
            return {r["rule_id"] for r in evaluate_sigma(report([c]), clean_rows=clean_rows([c]))["matches"]}
        self.assertNotIn(rid,hits("\\??\\pipe\\PSHost.123"))
        self.assertIn(rid,hits("\\??\\pipe\\evil\\pipe\\svc"))

    def test_raw_pipe_evidence_unchanged(self):
        c=call("NtCreateNamedPipeFile",{"PipeName":"\\??\\pipe\\PSHost.1"}); d=report([c]); saved=copy.deepcopy(d)
        events,t=normalize_events(d)
        e=next(e for e in events if e['category']=='pipe_created')
        self.assertEqual(e['fields']['PipeName'],'\\PSHost.1')
        self.assertEqual(e['evidence']['raw_pipe_name'],'\\??\\pipe\\PSHost.1')
        self.assertEqual(d,saved)
        self.assertEqual(t['normalization']['pipe_namespace_normalized'],1)

    def test_self_thread_and_pseudohandles_never_remote(self):
        for args in ({'ProcessId':10},{'ProcessId':'0xa'},{'ProcessId':99,'ProcessHandle':-1},{'ProcessHandle':'0xffffffff'},{'ProcessHandle':'0xffffffffffffffff'}):
            events,t=normalize_events(report([call('NtCreateThreadEx',args)]))
            self.assertFalse(any(e['category']=='create_remote_thread' for e in events))
            self.assertEqual(t['normalization']['self_thread_skipped'],1)

    def test_remote_thread_positive_unknown_and_failed(self):
        events,_=normalize_events(report([call('CreateRemoteThread',{'TargetProcessId':99,'ProcessHandle':'0x20'})]))
        e=next(e for e in events if e['category']=='create_remote_thread')
        self.assertEqual(e['fields']['TargetProcessId'],99)
        for c in (call('NtCreateThreadEx',{'ProcessHandle':'0x20'}),call('CreateRemoteThread',{'ProcessId':99},status=False)):
            events,_=normalize_events(report([c]))
            self.assertFalse(any(e['category']=='create_remote_thread' for e in events))

    def test_empty_clean_does_not_fall_back_raw(self):
        events,_=normalize_events(report([call('NtCreateNamedPipeFile',{'PipeName':'\\evil\\pipe\\svc'})]),[])
        self.assertFalse(any(e['category']=='pipe_created' for e in events))


class DynamicProjection(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.path=self.base/'behavior.filtered.jsonl'
        self.c=call('connect',{'IpAddress':'192.0.2.1'},status=False,repeated=17)
        self.report=report([self.c]);self.rows=clean_rows([self.c]);write_rows(self.path,self.rows)
    def tearDown(self): self.tmp.cleanup()
    def test_projection_links_failed_call_and_preserves_repetitions(self):
        d,src=project_dynamic(self.report,self.path,DEFAULTS)
        self.assertEqual(d['behavior']['processes'][0]['calls'][0]['api'],'connect')
        self.assertEqual(src['calls']['10:20:0']['status'],False)
        self.assertEqual(src['calls']['10:20:0']['repeated'],17)
        self.assertEqual(len(d['behavior']['processes'][0]['calls']),1)
        self.assertNotIn('summary',d['behavior']);self.assertNotIn('strings',d)
        self.assertNotIn('imports',d['target']['file']['pe'])
    def test_real_cape_schema(self):
        try:
            from capa.features.extractors.cape.models import CapeReport
        except ImportError:
            self.skipTest('flare-capa unavailable; run under capa venv for schema validation')
        d,_=project_dynamic(self.report,self.path,DEFAULTS)
        self.assertEqual(CapeReport.model_validate(d).behavior.processes[0].process_id,10)
    def test_reject_stale_and_tampered_call(self):
        for field,value in [('pid',99),('call',call('DeleteFileW'))]:
            rows=copy.deepcopy(self.rows);rows[0][field]=value;write_rows(self.path,rows)
            with self.assertRaises(ValueError): project_dynamic(self.report,self.path,DEFAULTS)
    def test_reject_empty_duplicate_and_framework(self):
        for rows in ([],self.rows*2,[dict(self.rows[0],provenance='framework_frida')]):
            write_rows(self.path,rows)
            with self.assertRaises(ValueError): project_dynamic(self.report,self.path,DEFAULTS)
    def test_call_limit_and_missing_input(self):
        with self.assertRaises(ValueError): project_dynamic(self.report,self.base/'missing',DEFAULTS)
        cfg=dict(DEFAULTS,max_clean_bytes=1)
        with self.assertRaises(ValueError): project_dynamic(self.report,self.path,cfg)
    def test_notification_omission_keeps_correct_call_index(self):
        n=call('DllLoadNotification',id=2,category='__notification__')
        d=report([n,self.c]);write_rows(self.path,clean_rows([n,self.c]));p,s=project_dynamic(d,self.path,DEFAULTS)
        self.assertEqual(s['calls']['10:20:0']['call_id'],1);self.assertEqual(s['counts']['notification_records_omitted'],1)
    def test_match_location_links_only_successful_tree_nodes(self):
        _,sources=project_dynamic(self.report,self.path,DEFAULTS)
        doc={'meta':{},'rules':{'socket':{'meta':{'attack':[{'id':'T1071'}]},'matches':[[{'type':'call','value':[9,10,20,0]}, {'success':True,'children':[{'success':False,'locations':[{'type':'call','value':[9,10,20,123]}]}]}]]}}}
        row=summarize_engine(doc,sources)[0]
        self.assertEqual(row['linked_calls'],1);self.assertFalse(row['call_evidence'][0]['status'])
        self.assertEqual(row['attack_ids'],['T1071'])


class QualityAndIntegration(unittest.TestCase):
    def test_rate_caps_degrade_complete_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);write_rows(p/'behavior.filtered.jsonl',clean_rows([call('OpenProcess')]))
            final={'version':'P3.2.3.16','status_axes':{'analyzer':'complete','resultserver':'complete','behavior_integrity':'complete','api_coverage':'degraded'},'telemetry':{'coverage':{'disabled_hooks':['LdrLoadDll']}},'network_observation':{'flows':{'tracked':0},'packet_loss':{'status':'unknown'}}}
            (p/'frida_p3_report.json').write_text(json.dumps(final));q=collect_quality({},p)
            self.assertEqual(q['status'],'degraded');self.assertEqual(q['acquisition_version'],'P3.2.3.16')
            self.assertFalse(q['clean_snapshot_verified']);self.assertIn('pcap_drop_count_unknown',q['limitations'])
    def test_missing_quality_is_unknown_and_score_neutral(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(collect_quality({},tmp)['status'],'unknown')
        data={'mitre_attack':{'mappings':[{'id':'T1055','status':'candidate','confidence':'high','sources':['sigma_rule','capa_dynamic']}]}}
        self.assertEqual(assess_threat(data)['score'],0)
        self.assertEqual(assess_threat(dict(data,capa={'static':{'capabilities':['anything']}}))['score'],0)
    def test_stale_finalizer_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'frida_p3_runtime.json').write_text(json.dumps({'run_id':'new'}));(p/'frida_p3_report.json').write_text(json.dumps({'run':{'run_id':'old'},'status_axes':{'api_coverage':'complete'}}))
            q=collect_quality({},p);self.assertIn('finalizer_run_id_mismatch',q['limitations']);self.assertEqual(q['status'],'unknown')
    def test_registry_script_hygiene_and_file_gap(self):
        for value,applicable in [(r'rundll32.exe javascript:"x";RegRead("HKCU\\x")',False),('#@~^encoded-script',False),(r'C:\Users\u\payload.exe',True)]:
            c=call('NtSetValueKey',{'FullName':r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\x','Buffer':value})
            chains=extract_behavior_chains_from_records(clean_rows([c])); self.assertEqual(len(chains['chains']),1)
            self.assertEqual(chains['chains'][0]['materialization_applicable'],applicable)
            hygiene=build_analysis_hygiene(chains);self.assertEqual(hygiene['persistence_materialization_gaps'],int(applicable));self.assertFalse(hygiene['clean_snapshot_verified'])
    def test_disabled_and_missing_engine_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(analyze_capa({},tmp,overrides={'enabled':False})['status'],'disabled')
            d=analyze_capa({},tmp,overrides={'executable':str(Path(tmp)/'missing-engine')})
            self.assertEqual(d['status'],'engine_unavailable');self.assertTrue((Path(tmp)/'capa_analysis.json').is_file())
    def test_version_mismatch_and_settings_error_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('CAPEsolo.capelib.capa_integration.subprocess.run') as run:
                run.return_value.returncode=0;run.return_value.stdout='capa 8.0.0';run.return_value.stderr=''
                self.assertEqual(analyze_capa({},tmp)['status'],'version_mismatch')
            self.assertEqual(analyze_capa({},tmp,overrides={'max_calls':-1})['status'],'integration_error')
    def test_engine_timeout_invalid_json_and_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);input_path=base/'input.json';input_path.write_text('{}')
            cfg=dict(DEFAULTS,rules_dir=str(DATA/'rules'),dynamic_timeout=1)
            for script,status in [('import time;time.sleep(10)','timeout'),('print("invalid")','error'),('raise SystemExit(3)','error')]:
                path=base/'engine.py';path.write_text(script)
                result=_run_engine([sys.executable,str(path)],input_path,base/'raw.json',cfg,True)
                self.assertEqual(result['status'],status);self.assertNotIn('document',result)
    def test_attack_comparison_preserves_native_status_and_legacy_id(self):
        from CAPEsolo.capelib.capa_integration import correlate_attack
        original={'mitre_attack':{'mappings':[{'id':'T1685','status':'candidate','sources':['behavior_api']}]},'capa':{'dynamic':{'capabilities':[{'name':'patch AMSI','attack_ids':['T1562.001']}]},'static':{'files':[]}}}
        saved=copy.deepcopy(original);result=correlate_attack(original)
        self.assertEqual(result['techniques'][0]['id'],'T1685')
        self.assertEqual(result['techniques'][0]['original_capa_ids'],['T1562.001'])
        self.assertEqual(result['techniques'][0]['p3_status'],'candidate');self.assertEqual(original,saved)

    def test_empty_clean_native_mapper_does_not_reintroduce_api(self):
        from CAPEsolo.capelib.mitre_attack_v12 import AttackMapper
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'behavior.filtered.jsonl').write_text('')
            d=report([call('NtCreateNamedPipeFile',{'PipeName':'\\evil\\pipe\\svc'})])
            mapper=AttackMapper(d,p)
            self.assertEqual(list(mapper._all_calls()),[])
            mapped=mapper.build();self.assertEqual(mapped['coverage']['behavior']['clean_calls'],0)

    def test_static_hash_and_instrumentation_gates(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);binary=base/'fixture.exe';binary.write_bytes(b'MZ-benign-fixture')
            digest=hashlib.sha256(binary.read_bytes()).hexdigest()
            artifact=base/digest;artifact.write_bytes(binary.read_bytes())
            (base/'frida_artifact_classification.json').write_text(json.dumps({'artifacts':[{'path':digest,'is_pe':True,'instrumentation':True}]}))
            with patch('CAPEsolo.capelib.capa_integration.subprocess.run') as preflight, patch('CAPEsolo.capelib.capa_integration._run_engine') as engine:
                preflight.return_value.returncode=0;preflight.return_value.stdout='capa 9.4.0';preflight.return_value.stderr=''
                result=analyze_capa({'target':{'sha256':'0'*64,'path':str(binary)}},base,overrides={'dynamic':False})
                self.assertEqual(len(result['static']['files']),1)
                self.assertEqual(result['static']['files'][0]['status'],'hash_mismatch');engine.assert_not_called()

    def test_cache_checks_input_rules_and_raw_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);counter=base/'counter';engine=base/'engine.py'
            engine.write_text("from pathlib import Path\np=Path("+repr(str(counter))+")\np.write_text(str(int(p.read_text())+1) if p.exists() else '1')\nprint('{\"meta\":{},\"rules\":{}}')\n")
            source=base/'input.json';source.write_text('{}');out=base/'raw.json'
            config=dict(DEFAULTS,rules_dir=str(DATA/'rules'),_rules_sha256='first')
            self.assertEqual(_run_engine([sys.executable,str(engine)],source,out,config,True)['status'],'ok')
            self.assertTrue(_run_engine([sys.executable,str(engine)],source,out,config,True)['cache_hit'])
            self.assertEqual(counter.read_text(),'1')
            source.write_text('{"changed":true}')
            self.assertFalse(_run_engine([sys.executable,str(engine)],source,out,config,True)['cache_hit'])
            config['_rules_sha256']='second'
            self.assertFalse(_run_engine([sys.executable,str(engine)],source,out,config,True)['cache_hit'])
            out.write_text('tampered')
            self.assertFalse(_run_engine([sys.executable,str(engine)],source,out,config,True)['cache_hit'])
            self.assertEqual(counter.read_text(),'4')

    def test_pinned_rule_integrity(self):
        manifest=json.loads((DATA/'rules_manifest.json').read_text())
        self.assertEqual(rule_identity(DATA/'rules')['sha256'],manifest['tree_sha256'])
    def test_html_escapes_untrusted_rule_name(self):
        try:
            from jinja2 import Environment,FileSystemLoader
        except ImportError:
            self.skipTest('jinja2 unavailable')
        env=Environment(loader=FileSystemLoader(str(ROOT/'CAPEsolo/capelib/html')),autoescape=True)
        html=env.get_template('sections/capa_capabilities.html').render(capabilities=[{'name':'<script>alert(1)</script>','attack_ids':[],'locations':[],'call_evidence':[]}])
        self.assertNotIn('<script>alert',html);self.assertIn('&lt;script&gt;',html)


if __name__=='__main__': unittest.main(verbosity=2)
