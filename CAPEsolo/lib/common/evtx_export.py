"""Consistent Windows Event Log exports; no live .evtx file copies."""
from __future__ import annotations
import hashlib
import json
import os
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
MAX_EVENTS = 200000
QUERIES = {
    'Microsoft-Windows-Sysmon/Operational': '*',
    'System': "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045 or EventID=7009 or EventID=7000 or EventID=7030 or EventID=7036 or EventID=7031 or EventID=7034)]]",
    'Security': '*[System[EventID=4697]]',
}

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''): h.update(b)
    return h.hexdigest()

def validate_export(path):
    """Reject dirty/truncated native exports instead of declaring them complete."""
    with Path(path).open('rb') as f:
        h = f.read(4096)
        if len(h) != 4096 or h[:8] != b'ElfFile\0': raise ValueError('invalid_evtx_header')
        chunks = struct.unpack_from('<H', h, 42)[0]
        flags = struct.unpack_from('<I', h, 120)[0]
        if flags & 1: raise ValueError('dirty_evtx_export')
        if Path(path).stat().st_size < 4096 + chunks * 65536: raise ValueError('truncated_evtx_export')
        for _ in range(chunks):
            c = f.read(65536)
            if c[:8] != b'ElfChnk\0': raise ValueError('invalid_evtx_chunk')
    return {'chunks': chunks, 'bytes': Path(path).stat().st_size, 'sha256': digest(path)}

def xml_rows(path, channel):
    """Stream Unicode XML from wevtutil, retaining raw EventData and identity."""
    for _, node in ET.iterparse(path, events=('end',)):
        if node.tag != NS + 'Event': continue
        s = node.find(NS+'System')
        if s is None: raise ValueError('event_without_system')
        provider = s.find(NS+'Provider')
        clock = s.find(NS+'TimeCreated')
        fields = {d.get('Name', 'param'+str(i)): d.text or ''
                  for i, d in enumerate(node.findall(NS+'EventData/'+NS+'Data'))}
        yield {'event_id': int(s.findtext(NS+'EventID')), 'record_id': int(s.findtext(NS+'EventRecordID')),
               'provider': provider.get('Name', '') if provider is not None else '', 'channel': channel,
               'utc_time': clock.get('SystemTime', '') if clock is not None else '',
               'computer': s.findtext(NS+'Computer') or '', 'data': fields}
        node.clear()

def collect_exports(channels, output, run_id=None, startupinfo=None, runner=subprocess.run, max_events=MAX_EVENTS):
    """Export each channel independently. Partial errors remain visible in manifest.

    Returns ZIP, manifest and normalized events, all created in a fresh directory.
    Native tools are called with argument lists, shell=False, and finite timeouts.
    """
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    manifest = {'schema': 'capesolo-evtx-export/1', 'revision': 'p32319-fix1', 'run_id': run_id,
                'method': 'wevtutil_epl', 'started_utc': datetime.now(timezone.utc).isoformat(),
                'channels': [], 'events_limit': max_events}
    events = output/'evtx_events.jsonl'; count = 0; exported = []
    with tempfile.TemporaryDirectory(prefix='p3_evtx_') as temp, events.open('w', encoding='utf-8') as ef:
        for channel in channels:
            name = channel.replace('/', '%4')+'.evtx'
            row = {'channel': channel, 'file': name, 'status': 'failed'}
            manifest['channels'].append(row)
            source = Path(temp)/name
            try:
                rc = runner(['wevtutil.exe', 'epl', channel, str(source), '/ow:true'],
                            startupinfo=startupinfo, capture_output=True, timeout=90, shell=False)
                if rc.returncode: raise ValueError('wevtutil_epl_exit_'+str(rc.returncode))
                row.update(validate_export(source)); row['status'] = 'ok'
                # Preserve raw export even if normalization fails.
                dest = output/name; os.replace(source, dest); exported.append(dest)
                if channel not in QUERIES: continue
                xml_path = Path(temp)/(name+'.xml')
                with xml_path.open('wb') as xf:
                    rc = runner(['wevtutil.exe', 'qe', str(dest), '/lf:true', '/f:xml', '/e:Events',
                                 '/uni:true', '/q:'+QUERIES[channel]], stdout=xf, stderr=subprocess.PIPE,
                                startupinfo=startupinfo, timeout=90, shell=False)
                if rc.returncode: raise ValueError('wevtutil_qe_exit_'+str(rc.returncode))
                # Spool a complete channel before committing rows; malformed XML cannot leak a partial channel.
                staging = Path(temp)/(name+'.jsonl'); n = 0
                with staging.open('w', encoding='utf-8') as sf:
                    for event in xml_rows(xml_path, channel):
                        if count+n >= max_events: raise ValueError('normalized_event_limit')
                        sf.write(json.dumps(event, ensure_ascii=False)+'\n'); n += 1
                with staging.open(encoding='utf-8') as sf:
                    for line in sf: ef.write(line)
                count += n; row['normalized_events'] = n; row['normalization'] = 'ok'
            except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError) as exc:
                row['error'] = str(exc)[:250]
                if row['status'] == 'ok': row['normalization'] = 'failed'
    manifest['events'] = {'file': events.name, 'count': count, 'sha256': digest(events)}
    manifest['status'] = 'complete' if all(r['status']=='ok' and r.get('normalization','ok')=='ok' for r in manifest['channels']) else 'partial'
    manifest['finished_utc'] = datetime.now(timezone.utc).isoformat()
    mp = output/'evtx_collection.json'; mp.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    archive = output/'evtx.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in exported+[mp, events]: z.write(p, p.name)
    for p in exported: p.unlink()
    return archive, mp, events
