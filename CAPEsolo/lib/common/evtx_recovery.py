"""Recover only hash-bound sidecars from the run's already collected ZIP."""
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path


def recover_evtx_sidecars(base, run_id):
    base = Path(base)
    names = ('evtx_collection.json', 'evtx_events.jsonl')
    if all((base / name).is_file() for name in names):
        return {'status': 'not_needed', 'warnings': []}
    archive = base / 'evtx' / 'evtx.zip'
    if not archive.is_file():
        return {'status': 'unavailable', 'warnings': []}
    try:
        with zipfile.ZipFile(archive) as z:
            for name in names:
                if z.namelist().count(name) != 1:
                    raise ValueError('sidecar_missing_or_duplicate')
            if z.getinfo(names[0]).file_size > 1024 * 1024:
                raise ValueError('manifest_size_limit')
            manifest_bytes = z.read(names[0])
            manifest = json.loads(manifest_bytes)
            if not run_id or manifest.get('run_id') != run_id:
                raise ValueError('run_id_mismatch')
            if z.getinfo(names[1]).file_size > 256 * 1024 * 1024:
                raise ValueError('events_size_limit')
            event_bytes = z.read(names[1])
            if hashlib.sha256(event_bytes).hexdigest() != (manifest.get('events') or {}).get('sha256'):
                raise ValueError('events_hash_mismatch')
            # Validate both destinations before any write; never replace conflicting evidence.
            for name, data in zip(names, (manifest_bytes, event_bytes)):
                if (base / name).exists() and (base / name).read_bytes() != data:
                    raise ValueError('existing_sidecar_conflict')
            for name, data in zip(names, (manifest_bytes, event_bytes)):
                destination = base / name
                if destination.exists():
                    continue
                fd, tmp = tempfile.mkstemp(dir=base, prefix='.evtx_recovery_')
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(data)
                    os.replace(tmp, destination)
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
        return {'status': 'recovered_from_bundle', 'warnings': []}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as exc:
        return {'status': 'failed', 'warnings': ['evtx_recovery_failed:' + str(exc)[:160]]}
