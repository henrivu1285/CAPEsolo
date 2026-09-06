#!/usr/bin/env python3
"""Compile ATT&CK-tagged SigmaHQ Windows rules into P3's offline IR.

This is a build-time tool.  It deliberately uses pySigma for parsing and
modifier/condition expansion; the malware guest only consumes the resulting
gzip JSON and therefore does not need pySigma or YAML at report time.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection


SCHEMA = "capesolo-sigma-pack/1.0"
SOURCE_URL = "https://github.com/SigmaHQ/sigma"
SUPPORTED_CATEGORIES = {
    "create_remote_thread",
    "dns_query",
    "file_access",
    "file_change",
    "file_delete",
    "file_event",
    "file_executable_detected",
    "file_rename",
    "image_load",
    "network_connection",
    "pipe_created",
    "process_access",
    "process_creation",
    "process_tampering",
    "registry_add",
    "registry_delete",
    "registry_event",
    "registry_set",
}
ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
ALLOWED_STATUSES = {"stable", "test", "experimental"}


class UnsupportedIR(ValueError):
    pass


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unknown"


def _string_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _string_regex(value: Any) -> str:
    pieces = []
    for token in getattr(value, "s", []):
        if type(token).__name__ == "SpecialChars":
            if getattr(token, "name", "") == "WILDCARD_MULTI":
                pieces.append(".*")
            elif getattr(token, "name", "") == "WILDCARD_SINGLE":
                pieces.append(".")
            else:
                raise UnsupportedIR(f"unsupported Sigma special character: {token!r}")
        else:
            pieces.append(re.escape(str(token)))
    return "^" + "".join(pieces) + "$"


def _compile_value(value: Any) -> dict:
    name = type(value).__name__
    if name == "SigmaString":
        return {"kind": "regex", "pattern": _string_regex(value), "ignore_case": True}
    if name == "SigmaRegularExpression":
        flags = {str(flag).lower() for flag in getattr(value, "flags", set())}
        return {
            "kind": "regex",
            "pattern": str(getattr(value, "regexp", "")),
            "ignore_case": any("ignorecase" in flag or flag.endswith(".i") for flag in flags),
        }
    if name == "SigmaCIDRExpression":
        return {"kind": "cidr", "network": str(getattr(value, "cidr", ""))}
    if name == "SigmaNumber":
        return {"kind": "number", "value": getattr(value, "number", None)}
    if name == "SigmaBool":
        return {"kind": "bool", "value": bool(getattr(value, "boolean", False))}
    if name == "SigmaNull":
        return {"kind": "null"}
    if name == "SigmaExpansion":
        return {"kind": "any", "values": [_compile_value(item) for item in getattr(value, "values", [])]}
    if name == "SigmaFieldReference":
        return {
            "kind": "fieldref",
            "field": str(getattr(value, "field", "")),
            "starts_with": bool(getattr(value, "starts_with", False)),
            "ends_with": bool(getattr(value, "ends_with", False)),
        }
    raise UnsupportedIR(f"unsupported Sigma value {name}")


def _compile_node(node: Any) -> dict:
    name = type(node).__name__
    if name in {"ConditionAND", "ConditionOR"}:
        return {
            "op": "and" if name == "ConditionAND" else "or",
            "args": [_compile_node(item) for item in (getattr(node, "args", None) or [])],
        }
    if name == "ConditionNOT":
        args = list(getattr(node, "args", None) or [])
        if len(args) != 1:
            raise UnsupportedIR("ConditionNOT must contain exactly one argument")
        return {"op": "not", "arg": _compile_node(args[0])}
    if name == "ConditionFieldEqualsValueExpression":
        return {
            "op": "field",
            "field": str(getattr(node, "field", "")),
            "value": _compile_value(getattr(node, "value", None)),
        }
    raise UnsupportedIR(f"unsupported Sigma condition node {name}")


def _fields(node: dict) -> set[str]:
    op = node.get("op")
    if op == "field":
        value = node.get("value") or {}
        fields = {str(node.get("field") or "")}
        if value.get("kind") == "fieldref":
            fields.add(str(value.get("field") or ""))
        return {field for field in fields if field}
    if op in {"and", "or"}:
        result: set[str] = set()
        for item in node.get("args") or []:
            result.update(_fields(item))
        return result
    if op == "not":
        return _fields(node.get("arg") or {})
    return set()


def _git_commit(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def build_pack(sigma_root: Path) -> dict:
    rules_root = sigma_root / "rules" / "windows"
    if not rules_root.is_dir():
        raise SystemExit(f"Sigma Windows rules not found: {rules_root}")

    source_files = sorted(rules_root.rglob("*.yml"))
    compiled = []
    skipped = Counter()
    categories = Counter()
    tagged = 0

    for path in source_files:
        try:
            collection = SigmaCollection.load_ruleset([path])
        except Exception as exc:
            skipped[f"parse:{type(exc).__name__}"] += 1
            continue
        for rule in collection.rules:
            if not hasattr(rule, "detection"):
                skipped["not_detection_rule"] += 1
                continue
            status = str(rule.status or "unknown").casefold()
            if status not in ALLOWED_STATUSES:
                skipped["unsupported_status"] += 1
                continue
            logsource = rule.logsource
            category = str(logsource.category or "")
            product = str(logsource.product or "")
            if product != "windows" or category not in SUPPORTED_CATEGORIES:
                skipped["unsupported_logsource"] += 1
                continue
            tags = [str(tag) for tag in (rule.tags or [])]
            attack_ids = sorted({match.group(1).upper() for tag in tags if (match := ATTACK_TAG.match(tag))})
            if not attack_ids:
                skipped["no_attack_technique_tag"] += 1
                continue
            tagged += 1
            try:
                parsed = [_compile_node(condition.parsed) for condition in rule.detection.parsed_condition]
            except (UnsupportedIR, re.error) as exc:
                skipped[f"ir:{type(exc).__name__}"] += 1
                continue
            condition = parsed[0] if len(parsed) == 1 else {"op": "or", "args": parsed}
            relative = path.relative_to(sigma_root).as_posix()
            raw = path.read_bytes()
            compiled.append({
                "id": str(rule.id or ""),
                "title": str(rule.title or ""),
                "status": status,
                "level": str(rule.level or "unknown"),
                "description": str(rule.description or ""),
                "authors": _string_list(rule.author),
                "references": _string_list(rule.references),
                "falsepositives": [str(value) for value in (rule.falsepositives or [])],
                "tags": tags,
                "attack_ids": attack_ids,
                "logsource": {"category": category, "product": product, "service": logsource.service},
                "fields": sorted(_fields(condition), key=str.casefold),
                "condition": condition,
                "source_path": relative,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
            })
            categories[category] += 1

    compiled.sort(key=lambda row: (row["logsource"]["category"], row["id"], row["title"]))
    return {
        "schema": SCHEMA,
        "source": {
            "repository": SOURCE_URL,
            "commit": _git_commit(sigma_root),
            "license": "DRL-1.1",
            "builder": "pySigma",
            "builder_version": _package_version("pysigma"),
        },
        "selection": {
            "root": "rules/windows",
            "products": ["windows"],
            "categories": sorted(SUPPORTED_CATEGORIES),
            "statuses": sorted(ALLOWED_STATUSES),
            "requires_attack_technique_tag": True,
        },
        "summary": {
            "source_files": len(source_files),
            "attack_tagged_compatible_rules": tagged,
            "compiled_rules": len(compiled),
            "skipped": dict(sorted(skipped.items())),
            "categories": dict(sorted(categories.items())),
        },
        "rules": compiled,
    }


def write_pack(output: Path, pack: dict) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent))
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                compressed.write(json.dumps(pack, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temp_name, output)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sigma_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    pack = build_pack(args.sigma_root.resolve())
    write_pack(args.output.resolve(), pack)
    print(json.dumps(pack["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
