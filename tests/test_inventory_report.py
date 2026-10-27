"""Integration test: simulated scans -> inventory -> evidence outputs (no network, no root)."""
from datetime import datetime, timedelta

from lan_sentinel.detectors import analyze
from lan_sentinel.inventory import Inventory
from lan_sentinel.report import evidence_report, export_csv, render_map

GW_IP, GW_MAC, PC, ROGUE = "192.168.1.1", "00:11:22:33:44:55", "00:aa:bb:cc:dd:01", "00:de:ad:be:ef:00"


def fake_enrich(mac, ip):
    return "TestVendor", False, ""


def test_end_to_end(tmp_path):
    inv = Inventory(str(tmp_path / "t.db"))
    allow = {PC: {"name": "Laptop", "owner": "me", "criticality": "high"}, GW_MAC: {"name": "Router"}}
    t0 = datetime(2026, 10, 27, 20, 0)
    inv.set_meta("gateway_mac", GW_MAC)
    scan1 = [(GW_IP, GW_MAC), ("192.168.1.10", PC)]
    inv.log_events(analyze(scan1, inv.assets(), allow, GW_IP, GW_MAC, t0), t0)
    inv.record_scan(scan1, t0, "192.168.1.0/24", 15, fake_enrich)

    t1 = t0 + timedelta(minutes=30)
    scan2 = [(GW_IP, GW_MAC), ("192.168.1.66", ROGUE)]
    ev = analyze(scan2, inv.assets(), allow, GW_IP, GW_MAC, t1)
    assert {e.type for e in ev} == {"NEW_UNKNOWN_DEVICE", "CRITICAL_ASSET_OFFLINE"}
    inv.log_events(ev, t1)
    inv.record_scan(scan2, t1, "192.168.1.0/24", 15, fake_enrich)

    assets = inv.assets()
    assert assets[PC]["status"] == "offline" and assets[ROGUE]["status"] == "online"
    assert len(inv.scans()) == 2

    csv_text = export_csv(inv, allow, tmp_path / "a.csv").read_text()
    assert ROGUE in csv_text and "Laptop" in csv_text
    md = evidence_report(inv, allow, tmp_path / "r.md", days=36500).read_text()
    assert "Unapproved (open findings) | 1" in md and ROGUE in md and "NIS-2 Art. 21(2)(i)" in md
    html = render_map(inv, allow, GW_IP, "", tmp_path / "m.html").read_text()
    assert ROGUE in html
