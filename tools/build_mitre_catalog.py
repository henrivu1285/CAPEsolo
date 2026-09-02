#!/usr/bin/env python3
"""Build and validate the deterministic ATT&CK catalog bundled with P3.2.3.14.

The source directory must be a checkout of mitre-attack/attack-stix-data at the
version printed in the output metadata.  Descriptions are retained for
analytics, while unrelated STIX objects and citations are intentionally left
out so the offline sandbox does not need the full STIX bundles at runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DOMAINS = {
    "enterprise-attack": ("Enterprise", "enterprise-attack/enterprise-attack.json"),
    "mobile-attack": ("Mobile", "mobile-attack/mobile-attack.json"),
    "ics-attack": ("ICS", "ics-attack/ics-attack.json"),
}


def _external_id(item: dict, prefix: str | None = None) -> str | None:
    for reference in item.get("external_references") or []:
        value = str(reference.get("external_id") or "")
        if value and (prefix is None or value.startswith(prefix)):
            return value
    return None


def _active(item: dict) -> bool:
    return not item.get("revoked") and not item.get("x_mitre_deprecated")


def build_domain(path: Path, label: str) -> dict:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objects = [item for item in bundle.get("objects") or [] if isinstance(item, dict)]
    by_id = {item.get("id"): item for item in objects if item.get("id")}
    detects: dict[str, list[str]] = {}
    for item in objects:
        if item.get("type") != "relationship" or item.get("relationship_type") != "detects" or not _active(item):
            continue
        detects.setdefault(str(item.get("target_ref")), []).append(str(item.get("source_ref")))

    active_techniques = {
        _external_id(item, "T") for item in objects
        if item.get("type") == "attack-pattern" and _active(item) and _external_id(item, "T")
    }
    active_strategies = {
        _external_id(item, "DET") for item in objects
        if item.get("type") == "x-mitre-detection-strategy" and _active(item) and _external_id(item, "DET")
    }
    active_analytics = {
        _external_id(item, "AN") for item in objects
        if item.get("type") == "x-mitre-analytic" and _active(item) and _external_id(item, "AN")
    }
    active_components = {
        _external_id(item, "DC") for item in objects
        if item.get("type") == "x-mitre-data-component" and _active(item) and _external_id(item, "DC")
    }

    techniques = {}
    strategy_ids: set[str] = set()
    analytic_ids: set[str] = set()
    component_ids: set[str] = set()
    unresolved = {"strategy_refs": 0, "analytic_refs": 0, "data_component_refs": 0}
    for item in objects:
        if item.get("type") != "attack-pattern" or not _active(item):
            continue
        technique_id = _external_id(item, "T")
        if not technique_id:
            continue
        strategies = []
        for strategy_ref in sorted(set(detects.get(str(item.get("id")), []))):
            strategy = by_id.get(strategy_ref) or {}
            if strategy.get("type") != "x-mitre-detection-strategy" or not _active(strategy):
                unresolved["strategy_refs"] += 1
                continue
            strategy_id = _external_id(strategy, "DET")
            if not strategy_id:
                unresolved["strategy_refs"] += 1
                continue
            strategy_ids.add(strategy_id)
            analytics = []
            for analytic_ref in strategy.get("x_mitre_analytic_refs") or []:
                analytic = by_id.get(analytic_ref) or {}
                if analytic.get("type") != "x-mitre-analytic" or not _active(analytic):
                    unresolved["analytic_refs"] += 1
                    continue
                analytic_id = _external_id(analytic, "AN")
                if not analytic_id:
                    unresolved["analytic_refs"] += 1
                    continue
                analytic_ids.add(analytic_id)
                components = []
                seen_components = set()
                for source in analytic.get("x_mitre_log_source_references") or []:
                    component = by_id.get(source.get("x_mitre_data_component_ref")) or {}
                    component_id = _external_id(component, "DC")
                    if not component_id:
                        unresolved["data_component_refs"] += 1
                        continue
                    component_ids.add(component_id)
                    key = (component_id, str(source.get("name") or ""), str(source.get("channel") or ""))
                    if key in seen_components:
                        continue
                    seen_components.add(key)
                    components.append({
                        "id": component_id,
                        "name": component.get("name") or component_id,
                        "source": source.get("name") or "",
                        "channel": source.get("channel") or "",
                    })
                analytics.append({
                    "id": analytic_id,
                    "name": analytic.get("name") or analytic_id,
                    "description": analytic.get("description") or "",
                    "platforms": sorted(analytic.get("x_mitre_platforms") or []),
                    "data_components": sorted(components, key=lambda row: (row["id"], row["source"], row["channel"])),
                    "mutable_elements": analytic.get("x_mitre_mutable_elements") or [],
                })
            strategies.append({
                "id": strategy_id,
                "name": strategy.get("name") or strategy_id,
                "analytics": sorted(analytics, key=lambda row: row["id"]),
            })
        techniques[technique_id] = {
            "name": item.get("name") or technique_id,
            "tactics": sorted({
                str(phase.get("phase_name")) for phase in item.get("kill_chain_phases") or []
                if phase.get("phase_name")
            }),
            "platforms": sorted(item.get("x_mitre_platforms") or []),
            "strategies": sorted(strategies, key=lambda row: row["id"]),
        }
    complete = (
        set(techniques) == active_techniques
        and strategy_ids == active_strategies
        and not any(unresolved.values())
    )
    return {
        "label": label,
        "summary": {
            "techniques": len(techniques),
            "detection_strategies": len(strategy_ids),
            "analytics": len(analytic_ids),
            "data_components": len(component_ids),
            "linked_analytics": len(analytic_ids),
            "linked_data_components": len(component_ids),
            "active_analytics": len(active_analytics),
            "active_data_components": len(active_components),
            "unlinked_analytics": len(active_analytics - analytic_ids),
            "unlinked_data_components": len(active_components - component_ids),
            "count_semantics": "linked counts are reachable through technique -> detection strategy -> analytic -> data component; active counts include every non-revoked object in the source bundle",
        },
        "validation": {
            "complete": complete,
            "active_techniques": len(active_techniques),
            "emitted_techniques": len(techniques),
            "active_detection_strategies": len(active_strategies),
            "linked_detection_strategies": len(strategy_ids),
            "unresolved_references": unresolved,
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        },
        "techniques": dict(sorted(techniques.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--attack-version", default="19.2")
    parser.add_argument("--source-tag", default="v19.2")
    args = parser.parse_args()
    domains = {}
    for domain, (label, relative) in DOMAINS.items():
        domains[domain] = build_domain(args.source / relative, label)
    result = {
        "schema": "capesolo-attack-catalog/1.1",
        "attack_version": args.attack_version,
        "source": "mitre-attack/attack-stix-data",
        "source_tag": args.source_tag,
        "domains": domains,
        "validation": {
            "complete": all((domain.get("validation") or {}).get("complete") for domain in domains.values()),
            "domains": {name: domain.get("validation") or {} for name, domain in domains.items()},
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
