"""P3 safe Frida profile resolver for CAPEsolo.

The resolver is intentionally conservative.  It only selects a family/profile
when the profile's own ``match`` block reaches its configured minimum score.
Unknown samples fall back to ``generic``.

Supported profile match fields::

    "match": {
      "min_score": 80,
      "names": ["rootkit.exe"],
      "sizes": [76288],
      "sha256": ["..."],
      "byte_patterns": [
        {"offset": 2, "hex": "ebfe1f0100", "score": 55}
      ]
    }

Scoring defaults:
- SHA-256 exact match: 100
- file size exact match: 20
- basename exact match: 10
- byte pattern: profile-provided score, default 50

This module performs read-only matching; it never modifies the sample.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _norm_name(value: Any) -> str:
    return os.path.basename(str(value or "")).strip().lower()


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _sha256(path: Path, cache: dict[Path, str]) -> str:
    if path in cache:
        return cache[path]
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest().lower()
    except OSError:
        digest = ""
    cache[path] = digest
    return digest


def _read_pattern(path: Path, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0:
        return b""
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            return fh.read(size)
    except OSError:
        return b""


def _candidate_files(analysis_dir: str | os.PathLike | None, target_hint: str = "") -> list[Path]:
    if not analysis_dir:
        return []
    root = Path(str(analysis_dir))
    if not root.is_dir():
        return []

    seen: set[str] = set()
    out: list[Path] = []

    hint = _norm_name(target_hint)
    if hint:
        hinted = root / hint
        if hinted.is_file():
            out.append(hinted)
            seen.add(str(hinted).lower())

    # CAPEsolo's current analysis directory is normally shallow. Restrict the
    # resolver to direct files to avoid hashing unrelated nested data.
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return out

    for path in entries:
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        key = str(path).lower()
        if key in seen:
            continue
        out.append(path)
        seen.add(key)
    return out


def _score_profile(profile: dict, candidate: Path, sha_cache: dict[Path, str]) -> tuple[int, list[str]]:
    match = profile.get("match") or {}
    if not isinstance(match, dict) or not match:
        return 0, []

    score = 0
    reasons: list[str] = []
    basename = candidate.name.lower()

    names = {_norm_name(v) for v in _as_list(match.get("names")) if _norm_name(v)}
    if names and basename in names:
        score += int(match.get("name_score", 10) or 10)
        reasons.append(f"name:{basename}")

    sizes = set()
    for value in _as_list(match.get("sizes")):
        try:
            sizes.add(int(value))
        except Exception:
            pass
    if sizes:
        try:
            size = int(candidate.stat().st_size)
        except OSError:
            size = -1
        if size in sizes:
            score += int(match.get("size_score", 20) or 20)
            reasons.append(f"size:{size}")

    hashes = {str(v).strip().lower() for v in _as_list(match.get("sha256")) if str(v).strip()}
    if hashes:
        digest = _sha256(candidate, sha_cache)
        if digest and digest in hashes:
            score += int(match.get("sha256_score", 100) or 100)
            reasons.append(f"sha256:{digest}")

    for pattern in _as_list(match.get("byte_patterns")):
        if not isinstance(pattern, dict):
            continue
        try:
            offset = int(str(pattern.get("offset", 0)), 0)
        except Exception:
            continue
        hex_value = str(pattern.get("hex") or "").replace(" ", "").strip().lower()
        if not hex_value or len(hex_value) % 2:
            continue
        try:
            expected = bytes.fromhex(hex_value)
        except ValueError:
            continue
        observed = _read_pattern(candidate, offset, len(expected))
        if observed == expected:
            pscore = int(pattern.get("score", 50) or 50)
            score += pscore
            reasons.append(f"bytes@0x{offset:x}:{hex_value}")

    return score, reasons


def resolve_profile(
    profile_dir: str | os.PathLike,
    analysis_dir: str | os.PathLike | None,
    requested: str = "auto",
    target_hint: str = "",
    fallback: str = "generic",
) -> dict:
    """Resolve the Frida profile and return a structured selection record.

    An explicit profile request is respected as-is.  ``auto`` performs
    conservative profile matching.  Failure or insufficient evidence always
    returns the generic fallback.
    """

    request = str(requested or "auto").strip()
    if request.lower() not in {"", "auto"}:
        return {
            "requested": request,
            "selected": request,
            "source": "explicit",
            "score": None,
            "candidate": None,
            "reasons": ["explicit_profile"],
        }

    pdir = Path(profile_dir)
    candidates = _candidate_files(analysis_dir, target_hint=target_hint)
    sha_cache: dict[Path, str] = {}
    best: dict | None = None

    try:
        profile_paths = sorted(pdir.glob("*.json"), key=lambda p: p.name.lower())
    except OSError:
        profile_paths = []

    for profile_path in profile_paths:
        profile = _load_json(profile_path)
        name = str(profile.get("name") or profile_path.stem).strip() or profile_path.stem
        if name.lower() == fallback.lower():
            continue
        match = profile.get("match") or {}
        if not isinstance(match, dict) or not match:
            continue
        try:
            minimum = int(match.get("min_score", 80))
        except Exception:
            minimum = 80

        for candidate in candidates:
            score, reasons = _score_profile(profile, candidate, sha_cache)
            if score < minimum:
                continue
            record = {
                "requested": request or "auto",
                "selected": name,
                "source": "auto",
                "score": score,
                "minimum": minimum,
                "candidate": str(candidate),
                "reasons": reasons,
            }
            if best is None or score > int(best.get("score") or 0):
                best = record

    if best is not None:
        return best

    return {
        "requested": request or "auto",
        "selected": fallback,
        "source": "fallback",
        "score": 0,
        "candidate": str(candidates[0]) if candidates else None,
        "reasons": ["no_profile_reached_min_score"],
    }
