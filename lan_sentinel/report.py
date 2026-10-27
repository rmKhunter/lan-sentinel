"""Outputs: CSV asset register, Markdown compliance evidence report, HTML topology map."""
from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from .inventory import Inventory

CSV_FIELDS = ["mac", "ip", "hostname", "vendor", "randomized", "approved", "name", "owner",
              "criticality", "first_seen", "last_seen", "status"]

CONTROL_MAP = [
    ("NIS-2 Art. 21(2)(i)", "Asset management", "Continuously updated asset register (CSV + SQLite), owner and criticality per approved asset"),
    ("NIS-2 Art. 21(2)(b)", "Incident handling", "Detection events with severity, timestamped audit trail, push alerting"),
    ("ISO/IEC 27001:2022 A.5.9", "Inventory of information and other associated assets", "Asset register with owner field; unapproved assets reported as findings"),
    ("ISO/IEC 27001:2022 A.8.16", "Monitoring activities", "Scheduled scans, anomaly detection (gateway MAC drift, IP conflicts, rogue devices)"),
    ("ISO/IEC 27001:2022 A.8.20", "Networks security", "Detection of unauthorized devices and ARP-level MITM indicators on the segment"),
]


def _rows(inv: Inventory, allow: dict) -> list[dict]:
    rows = []
    for mac, a in inv.assets().items():
        k = allow.get(mac, {})
        rows.append({**a, "randomized": bool(a["randomized"]), "approved": mac in allow,
                     "name": k.get("name", ""), "owner": k.get("owner", ""),
                     "criticality": k.get("criticality", "")})
    return rows


def export_csv(inv: Inventory, allow: dict, path: Path) -> Path:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(_rows(inv, allow))
    return path


def evidence_report(inv: Inventory, allow: dict, path: Path, days: int = 30) -> Path:
    now = datetime.now().replace(microsecond=0)
    since = (now - timedelta(days=days)).isoformat()
    rows = _rows(inv, allow)
    scans = inv.scans()
    events = inv.events(since=since)
    unapproved = [r for r in rows if not r["approved"]]
    sev = Counter(e["severity"] for e in events)
    serious = [e for e in events if e["severity"] in ("high", "critical")]

    out = [f"# LAN Asset & Monitoring Evidence Report", "",
           f"- Generated: {now.isoformat()}",
           f"- Scope: {scans[-1]['cidr'] if scans else 'n/a'}",
           f"- Monitoring coverage: {len(scans)} scans, "
           f"{scans[0]['ts'] if scans else '-'} → {scans[-1]['ts'] if scans else '-'}",
           f"- Gateway MAC baseline: `{inv.get_meta('gateway_mac') or 'not set'}`", "",
           "## 1. Asset register summary", "",
           "| Metric | Value |", "|---|---|",
           f"| Assets known | {len(rows)} |",
           f"| Approved (owner assigned) | {len(rows) - len(unapproved)} |",
           f"| Unapproved (open findings) | {len(unapproved)} |",
           f"| Randomized MACs | {sum(r['randomized'] for r in rows)} |",
           f"| Currently online | {sum(r['status'] == 'online' for r in rows)} |", "",
           "## 2. Open findings: unapproved assets", ""]
    if unapproved:
        out += ["| IP | MAC | Vendor | Hostname | First seen | Last seen |", "|---|---|---|---|---|---|"]
        out += [f"| {r['ip']} | `{r['mac']}` | {r['vendor']} | {r['hostname'] or '-'} | "
                f"{r['first_seen']} | {r['last_seen']} |" for r in unapproved]
        out += ["", "Remediation: identify each device, then `lan-sentinel approve <MAC> --name ... "
                "--owner ... --criticality ...` or remove it from the network."]
    else:
        out.append("None. Every observed asset has an owner.")
    out += ["", f"## 3. Detection events (last {days} days)", "",
            "| Severity | Count |", "|---|---|"]
    out += [f"| {s} | {sev.get(s, 0)} |" for s in ("critical", "high", "medium", "low", "info")]
    if serious:
        out += ["", "### High / critical events", "", "| Time | Type | IP | MAC | Detail |", "|---|---|---|---|---|"]
        out += [f"| {e['ts']} | {e['type']} | {e['ip'] or '-'} | `{e['mac'] or '-'}` | {e['detail']} |"
                for e in serious]
    out += ["", "## 4. Control mapping", "", "| Requirement | Topic | Evidence provided |", "|---|---|---|"]
    out += [f"| {a} | {b} | {c} |" for a, b, c in CONTROL_MAP]
    out += ["", "## 5. Known limitations", "",
            "- Visibility is limited to the local L2 segment (ARP does not cross routers or VLANs).",
            "- Devices that ignore ARP while asleep can be missed by a single scan.",
            "- An attacker cloning an approved MAC is not detected by this tool.",
            "- Topology is inferred as a star around the gateway; switch/AP placement needs SNMP/LLDP.", ""]
    path.write_text("\n".join(out))
    return path


def render_map(inv: Inventory, allow: dict, gateway_ip: str, my_ip: str, path: Path,
               refresh: int | None = None) -> Path:
    from pyvis.network import Network
    net = Network(height="95vh", width="100%", bgcolor="#111111", font_color="#eeeeee",
                  cdn_resources="remote")
    net.barnes_hut()
    gw_mac = inv.get_meta("gateway_mac")
    rows = _rows(inv, allow)
    for r in rows:
        if r["mac"] == gw_mac:
            color, size = "#f5a623", 35
        elif r["ip"] == my_ip and r["status"] == "online":
            color, size = "#4a90e2", 25
        elif r["status"] != "online":
            color, size = "#555555", 15
        elif not r["approved"]:
            color, size = "#e74c3c", 22
        else:
            color, size = "#2ecc71", 20
        label = r["name"] or r["hostname"] or r["ip"]
        tip = "\n".join(f"{k}: {r[k]}" for k in CSV_FIELDS if r.get(k) not in ("", None))
        net.add_node(r["mac"], label=label, title=tip, color=color, size=size)
    hub = gw_mac if gw_mac in {r["mac"] for r in rows} else "gateway"
    if hub == "gateway":
        net.add_node(hub, label=f"{gateway_ip} (gateway)", color="#f5a623", size=35)
    for r in rows:
        if r["mac"] != hub:
            net.add_edge(hub, r["mac"])
    net.save_graph(str(path))
    if refresh:
        html = path.read_text().replace("<head>", f'<head><meta http-equiv="refresh" content="{refresh}">', 1)
        path.write_text(html)
    return path
