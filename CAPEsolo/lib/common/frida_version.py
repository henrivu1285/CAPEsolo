"""Shared CAPEsolo + Frida product-version helpers.

Runtime evidence is the source of truth for the version of the analysis that
produced a report.  ``PRODUCT_VERSION`` identifies the code doing the work.
Keeping both values prevents a P3.2.3.17 post-processor from relabelling an old
P3.2.3.7 run while ensuring every output from a new run agrees on P3.2.3.17.
"""
from __future__ import annotations

import re
from typing import Any

PRODUCT_VERSION = "P3.2.3.17"
PACKAGE_VERSION = "0.5.32-p32317-fix1"
PROCESSOR_REVISION = "p32317-fix1"

_PRODUCT_RE = re.compile(r"^P\d+(?:\.\d+)+$")


def product_version_for_runtime(runtime: Any) -> str:
    """Return the validated run version, falling back to this build version."""
    if isinstance(runtime, dict):
        value = str(runtime.get("version") or "").strip()
        if _PRODUCT_RE.fullmatch(value):
            return value
    return PRODUCT_VERSION
