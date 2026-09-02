#!/usr/bin/env python3
"""Export a compact review bundle or the complete CAPEsolo analysis evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from CAPEsolo.lib.core.result_archive import build_result_archive


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-dir", type=Path, default=Path(r"C:\Users\Public\CAPEsolo\analysis"))
    parser.add_argument("--mode", choices=("review", "full"), default="review")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or Path.cwd() / f"capesolo_{args.mode}_{datetime.now():%Y%m%d_%H%M%S}.zip"
    path, manifest = build_result_archive(args.analysis_dir, output, args.mode)
    print(json.dumps({"archive": str(path), **manifest}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
