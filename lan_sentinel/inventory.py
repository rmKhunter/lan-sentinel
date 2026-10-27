"""SQLite inventory: assets, events (audit trail), scans (coverage evidence), meta (baselines)."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Callable

from .detectors import Event, is_stale

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(
  mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, hostname TEXT, randomized INTEGER,
  first_seen TEXT, last_seen TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, type TEXT, severity TEXT,
  mac TEXT, ip TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, cidr TEXT, hosts INTEGER);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
"""

Enrich = Callable[[str, str], tuple[str, bool, str]]  # (mac, ip) -> (vendor, randomized, hostname)


class Inventory:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # --- reads
    def assets(self) -> dict[str, dict]:
        return {r["mac"]: dict(r) for r in self.db.execute("SELECT * FROM assets ORDER BY ip")}

    def scans(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM scans ORDER BY id")]

    def events(self, since: str | None = None, limit: int = 1000) -> list[dict]:
        q, args = "SELECT * FROM events", []
        if since:
            q, args = q + " WHERE ts >= ?", [since]
        return [dict(r) for r in self.db.execute(q + " ORDER BY id DESC LIMIT ?", [*args, limit])]

    def get_meta(self, key: str) -> str | None:
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    # --- writes
    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, value))
        self.db.commit()

    def record_scan(self, observations: list[tuple[str, str]], now: datetime, cidr: str,
                    offline_minutes: int, enrich: Enrich) -> None:
        ts = now.isoformat(timespec="seconds")
        seen: dict[str, str] = {}
        for ip, mac in observations:
            seen.setdefault(mac, ip)
        for mac, ip in seen.items():
            row = self.db.execute("SELECT ip FROM assets WHERE mac=?", (mac,)).fetchone()
            if row is None:
                vendor, rnd, host = enrich(mac, ip)
                self.db.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?)",
                                (mac, ip, vendor, host, int(rnd), ts, ts, "online"))
            else:
                host = enrich(mac, ip)[2] if row["ip"] != ip else None
                self.db.execute(
                    "UPDATE assets SET ip=?, last_seen=?, status='online',"
                    " hostname=COALESCE(?, hostname) WHERE mac=?", (ip, ts, host or None, mac))
        for mac, a in self.assets().items():
            if mac not in seen and a["status"] == "online" and is_stale(a["last_seen"], now, offline_minutes):
                self.db.execute("UPDATE assets SET status='offline' WHERE mac=?", (mac,))
        self.db.execute("INSERT INTO scans(ts, cidr, hosts) VALUES(?,?,?)", (ts, cidr, len(seen)))
        self.db.commit()

    def log_events(self, events: list[Event], now: datetime) -> None:
        ts = now.isoformat(timespec="seconds")
        self.db.executemany(
            "INSERT INTO events(ts,type,severity,mac,ip,detail) VALUES(?,?,?,?,?,?)",
            [(ts, e.type, e.severity, e.mac, e.ip, e.detail) for e in events])
        self.db.commit()
