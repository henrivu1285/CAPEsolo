#!/usr/bin/env python3
"""Apply the p32318 CAR revision delta (bases p32317-fix1 or original p32318) after checking all hashes, with local rollback data."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def safe_path(base, name):
    path = (base / name).resolve()
    if not path.is_relative_to(base) or path == base:
        raise ValueError("Path outside selected root: " + name)
    return path


def replace_bytes(destination, data):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=str(destination.parent), suffix='.patch.tmp')
    try:
        with os.fdopen(fd,'wb') as f: f.write(data)
        os.replace(temp,destination)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True,type=Path,help='Existing repository root, containing CAPEsolo/ and tools/')
    parser.add_argument('--apply',action='store_true',help='Write after all checks pass; otherwise inspect only')
    parser.add_argument('--rollback',type=Path,help='Backup directory previously printed by this installer')
    args=parser.parse_args();target=args.target.resolve();patch_root=Path(__file__).resolve().parent.parent
    if not (target/'CAPEsolo/analyzer.py').is_file(): parser.error('target is not a CAPEsolo repository root')
    if args.rollback:
        backup=args.rollback.resolve();state=json.loads((backup/'rollback.json').read_text())
        if Path(state['target']).resolve()!=target:parser.error('rollback target differs')
        for item in state['files']:
            if digest(safe_path(target,item['path']))!=item['new_sha256']:parser.error('files changed since patch; inspect manually: '+item['path'])
            if item['old_sha256'] and digest(safe_path(backup,item['path']))!=item['old_sha256']:parser.error('backup hash mismatch: '+item['path'])
        print('Rollback checks passed:',len(state['files']),'files')
        if args.apply:
            for item in reversed(state['files']):
                dest=safe_path(target,item['path'])
                if item['old_sha256']:replace_bytes(dest,safe_path(backup,item['path']).read_bytes())
                else:dest.unlink()
            print('Rollback complete')
        return 0
    manifest=json.loads((patch_root/'P32318_PATCH_MANIFEST.json').read_text())
    changes=[];errors=[]
    for item in manifest['files']:
        source=safe_path(patch_root,item['path']);dest=safe_path(target,item['path'])
        if digest(source)!=item['sha256']:errors.append('Patch hash mismatch: '+item['path']);continue
        current=digest(dest)
        if current==item['sha256']:continue
        if current not in item.get('base_sha256s',[item['base_sha256']]):errors.append('Local changes or wrong base: '+item['path']);continue
        changes.append(dict(path=item['path'],old_sha256=current,new_sha256=item['sha256']))
    if errors:
        for error in errors:print(error)
        return 1
    print('Checks passed:',len(changes),'files to write')
    if not args.apply or not changes:return 0
    backup=target/('p32318_backup_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir()
    for item in changes:
        if item['old_sha256']:
            dest=safe_path(backup,item['path']);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(safe_path(target,item['path']),dest)
    (backup/'rollback.json').write_text(json.dumps({'target':str(target),'files':changes},indent=2),encoding='utf-8')
    written=[]
    try:
        for item in changes:
            dest=safe_path(target,item['path']);replace_bytes(dest,safe_path(patch_root,item['path']).read_bytes());written.append(item)
    except Exception:
        for item in reversed(written):
            dest=safe_path(target,item['path'])
            if item['old_sha256']:replace_bytes(dest,safe_path(backup,item['path']).read_bytes())
            else:dest.unlink()
        raise
    print('Applied P3.2.3.18 / p32318-car1. Backup:',backup)
    return 0


if __name__=='__main__':raise SystemExit(main())
