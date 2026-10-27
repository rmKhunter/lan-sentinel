"""YAML config. The known_devices allowlist is 'inventory as code': versioned, reviewable."""
from __future__ import annotations

from pathlib import Path

import yaml

DEFAULTS = {
    "database": "lan_sentinel.db",
    "output_dir": "reports",
    "interface": None,
    "cidr": None,
    "offline_minutes": 15,
    "alerts": {"min_severity": "high", "ntfy_url": None},
    "known_devices": {},
}


def load(path: str) -> dict:
    p = Path(path)
    raw = yaml.safe_load(p.read_text()) if p.exists() else {}
    cfg = {**DEFAULTS, **(raw or {})}
    cfg["alerts"] = {**DEFAULTS["alerts"], **(cfg.get("alerts") or {})}
    cfg["known_devices"] = {k.lower(): (v or {}) for k, v in (cfg.get("known_devices") or {}).items()}
    return cfg


def approve(path: str, mac: str, name: str, owner: str, criticality: str) -> None:
    p = Path(path)
    raw = (yaml.safe_load(p.read_text()) if p.exists() else None) or {}
    raw.setdefault("known_devices", {})
    if raw["known_devices"] is None:
        raw["known_devices"] = {}
    raw["known_devices"][mac.lower()] = {"name": name, "owner": owner, "criticality": criticality}
    p.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))
