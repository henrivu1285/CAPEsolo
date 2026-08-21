#!/usr/bin/env python3
"""Prepare a clean CAPEsolo analysis output directory for P3.1.

This is intentionally a manual pre-run tool. It never runs automatically from
FridaMuncher and defaults to dry-run. With --apply it archives the current
contents into a sibling analysis_archive/<timestamp>/ directory, preserving old
evidence while preventing ResultServer duplicate-name collisions such as
aux_/DigiSig.json already exists.
"""
from __future__ import annotations

import argparse
import shutil
import time
from datetime import datetime
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, default=Path(r"C:\Users\Public\CAPEsolo\analysis"))
    ap.add_argument("--archive-root", type=Path)
    ap.add_argument("--apply", action="store_true", help="perform the archive; otherwise print the plan only")
    ap.add_argument("--force", action="store_true", help="allow archiving even if analysis.log was modified in the last 30 seconds")
    args = ap.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    archive_root = (args.archive_root or (analysis_dir.parent / "analysis_archive")).resolve()

    if not analysis_dir.exists():
        print(f"analysis directory does not exist; creating: {analysis_dir}")
        if args.apply:
            analysis_dir.mkdir(parents=True, exist_ok=True)
        return 0

    live_log = analysis_dir / "analysis.log"
    if live_log.exists() and not args.force:
        age = time.time() - live_log.stat().st_mtime
        if age < 30:
            raise SystemExit(
                f"Refusing: {live_log} was modified {age:.1f}s ago. "
                "Stop/wait for CAPEsolo analysis to finish, or use --force if you are certain no run is active."
            )

    items = [p for p in analysis_dir.iterdir()]
    if not items:
        print(f"already clean: {analysis_dir}")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = archive_root / stamp
    print(f"analysis_dir: {analysis_dir}")
    print(f"archive_to:   {destination}")
    print(f"items:        {len(items)}")
    for item in items[:20]:
        print(f"  - {item.name}")
    if len(items) > 20:
        print(f"  ... {len(items)-20} more")

    if not args.apply:
        print("dry-run only; re-run with --apply to archive these files")
        return 0

    destination.mkdir(parents=True, exist_ok=False)
    for item in items:
        shutil.move(str(item), str(destination / item.name))
    print(f"archived {len(items)} item(s)")
    print(f"clean analysis directory ready: {analysis_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
