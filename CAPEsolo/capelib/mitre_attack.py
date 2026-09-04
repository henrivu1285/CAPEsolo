"""Compatibility entry point for the P3.2.3.15 ATT&CK engine."""
from CAPEsolo.capelib.mitre_attack_v12 import (
    ACTIVE_PLATFORM,
    ATTACK_DOMAIN,
    ATTACK_VERSION,
    SCHEMA,
    AttackMapper,
    load_catalog,
    map_mitre_attack,
    normalize_technique_id,
    prepare_clean_behavior,
)

# The implementation atomically writes: path / "mitre_attack.json"

__all__ = [
    "ACTIVE_PLATFORM", "ATTACK_DOMAIN", "ATTACK_VERSION", "SCHEMA",
    "AttackMapper", "load_catalog", "map_mitre_attack",
    "normalize_technique_id", "prepare_clean_behavior",
]
