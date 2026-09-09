"""Presentation-layer redaction for P3.2.3.16 reports.

Canonical raw evidence files remain lossless.  This module only mutates the
integrated JSON/HTML report after detection and scoring have completed, so
sensitive clipboard contents cannot leak through a shareable report.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from CAPEsolo.lib.common.frida_version import PRODUCT_VERSION


SCHEMA = "capesolo-report-redaction/1.0"
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\bfrida_pcap_agent_token\s*=\s*)[^,\s\"'&<>]+"
)


def _captured_bytes(argument: dict) -> bytes:
    raw = argument.get("raw_value")
    if isinstance(raw, str) and raw and len(raw) % 2 == 0:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    return str(argument.get("value") or "").encode("utf-8", errors="replace")


def _redact_secret_strings(value: Any) -> Any:
    if isinstance(value, dict):
        for key, item in list(value.items()):
            value[key] = _redact_secret_strings(item)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = _redact_secret_strings(item)
    elif isinstance(value, str):
        return _SECRET_ASSIGNMENT.sub(r"\1<redacted>", value)
    return value


def _clipboard_copies(value, secrets):
    """Find payloads in original calls AND already-redacted reports' derived evidence."""
    if isinstance(value, dict):
        if str(value.get("api") or "").lower() == "getclipboarddata":
            for arg in value.get("arguments") or []:
                if isinstance(arg, dict) and str(arg.get("name") or "").lower() in {"data", "text", "buffer", "clipboarddata"} and not arg.get("redacted"):
                    for field in ("value", "raw_value"):
                        item = arg.get(field)
                        if isinstance(item, str) and item and not item.startswith("<redacted"):
                            secrets.add(item)
            details = value.get("details")
            if isinstance(details, dict):
                for key in list(details):
                    if str(key).lower() in {"data", "text", "buffer", "clipboarddata", "raw_value"}:
                        item = details[key]
                        if isinstance(item, str) and item and not item.startswith("<redacted"):
                            secrets.add(item)
                        details[key] = "<redacted clipboard data>"
                if "summary" in value:
                    value["summary"] = "GetClipboardData: clipboard payload redacted; see call identity and status."
        for child in value.values():
            _clipboard_copies(child, secrets)
    elif isinstance(value, list):
        for child in value:
            _clipboard_copies(child, secrets)


def _scrub_copies(value, pattern):
    if isinstance(value, dict):
        for key, child in list(value.items()):
            # Integrity digests are correlation metadata, never clipboard text.
            if key not in {"sha256", "content_sha256", "md5", "sha1"}:
                value[key] = _scrub_copies(child, pattern)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            value[i] = _scrub_copies(child, pattern)
    elif isinstance(value, str):
        return pattern.sub("<redacted clipboard data>", value)
    return value


def redact_report_in_place(results: dict) -> dict:
    """Redact clipboard payloads from a completed integrated report.

    Detection must run before this function. ``behavior.filtered.jsonl`` and
    the CAPEMON logs are deliberately untouched and remain the audit source.
    """
    secrets = set()
    _clipboard_copies(results, secrets)
    redacted = 0
    captured_bytes = 0
    hashes = []
    for process in (results.get("behavior") or {}).get("processes") or []:
        if not isinstance(process, dict):
            continue
        for call in process.get("calls") or []:
            if not isinstance(call, dict) or str(call.get("api") or "").lower() != "getclipboarddata":
                continue
            summaries = []
            for argument in call.get("arguments") or []:
                if not isinstance(argument, dict) or str(argument.get("name") or "").lower() not in {"data", "text", "buffer", "clipboarddata"}:
                    continue
                if argument.get("redacted") is True:
                    continue
                blob = _captured_bytes(argument)
                digest = hashlib.sha256(blob).hexdigest()
                summaries.append({"field": argument.get("name"), "captured_bytes": len(blob), "sha256": digest})
                argument["value"] = "<redacted clipboard data>"
                if "raw_value" in argument:
                    argument["raw_value"] = "<redacted>"
                argument["redacted"] = True
                redacted += 1
                captured_bytes += len(blob)
                hashes.append(digest)
            if summaries:
                call["sensitive_data"] = {
                    "redacted": True,
                    "policy": "clipboard_payload",
                    "fields": summaries,
                }

    # MITRE evidence summaries, signatures or errors can repeat a configured
    # token. Scrub the exact option assignment without rewriting unrelated
    # behavior strings.
    if secrets:
        # Boundaries for very short payloads avoid changing unrelated API names.
        pattern = re.compile("|".join((r"(?<!\w)" + re.escape(v) + r"(?!\w)") if len(v) < 8 else re.escape(v)
                                      for v in sorted(secrets, key=len, reverse=True)))
        _scrub_copies(results, pattern)
    _redact_secret_strings(results)
    previous = results.get("report_redaction") or {}
    results["report_redaction"] = {
        "schema": SCHEMA,
        "processor_version": PRODUCT_VERSION,
        "policy": "shareable_report",
        "clipboard_fields_redacted": int(previous.get("clipboard_fields_redacted") or 0) + redacted,
        "captured_bytes_redacted": int(previous.get("captured_bytes_redacted") or 0) + captured_bytes,
        "content_sha256": sorted(set(list(previous.get("content_sha256") or []) + hashes)),
        "derived_clipboard_evidence_redacted": True,
        "raw_evidence_preserved": ["behavior.filtered.jsonl", "behavior.provenance.jsonl", "analysis.log"],
        "interpretation": "Clipboard payloads are hidden in JSON/HTML. Hashes and lengths support correlation; canonical raw evidence remains lossless.",
    }
    return results


__all__ = ["SCHEMA", "redact_report_in_place"]
