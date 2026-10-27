"""lan-sentinel CLI.

  lan-sentinel scan                 one detection cycle (use with a systemd timer)
  lan-sentinel watch --interval 60  continuous mode
  lan-sentinel pending              unapproved assets + ready-to-run approve commands
  lan-sentinel approve MAC --name N --owner O --criticality high
  lan-sentinel report               CSV register + Markdown evidence report + HTML map
  lan-sentinel events               last events
  lan-sentinel reset-gateway        re-baseline gateway MAC (after a legit router swap)

Only run against networks you own or are explicitly authorized in writing to monitor.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from . import config as config_mod
from .alerting import dispatch
from .detectors import Event, analyze, is_randomized
from .inventory import Inventory


def _enrich(mac: str, ip: str):
    from .scanner import lookup_vendor, reverse_dns
    return lookup_vendor(mac), is_randomized(mac), reverse_dns(ip)


def cycle(cfg: dict, inv: Inventory, net, refresh: int | None = None) -> list[Event]:
    from .report import render_map
    from .scanner import arp_scan, lookup_vendor
    now = datetime.now().replace(microsecond=0)
    obs = sorted(set(arp_scan(net.iface, net.cidr)) | {(net.my_ip, net.my_mac)})
    allow = cfg["known_devices"]
    baseline_run = not inv.scans()
    gw_baseline = inv.get_meta("gateway_mac")

    events = analyze(obs, inv.assets(), allow, net.gateway, gw_baseline, now,
                     cfg["offline_minutes"], vendor_fn=lookup_vendor)
    if baseline_run:  # first run = baseline inventory, not an incident flood
        for e in events:
            if e.type == "NEW_UNKNOWN_DEVICE":
                e.type, e.severity = "BASELINE_ASSET", "info"
    if not gw_baseline:
        gw = {m for ip, m in obs if ip == net.gateway}
        if len(gw) == 1:
            inv.set_meta("gateway_mac", gw.pop())
            events.append(Event("GATEWAY_BASELINE_SET", "info", inv.get_meta("gateway_mac"),
                                net.gateway, "Gateway MAC baseline recorded"))

    inv.record_scan(obs, now, net.cidr, cfg["offline_minutes"], _enrich)
    inv.log_events(events, now)
    dispatch(events, cfg["alerts"])
    out = Path(cfg["output_dir"])
    out.mkdir(parents=True, exist_ok=True)
    render_map(inv, allow, net.gateway, net.my_ip, out / "map.html", refresh)
    assets = inv.assets()
    pending = sum(1 for m in assets if m not in allow)
    print(f"[{now:%H:%M:%S}] {len({m for _, m in obs})} online | {len(assets)} known | "
          f"{pending} unapproved | {len(events)} events")
    if baseline_run:
        print("Baseline recorded. Next: `lan-sentinel pending` and approve your devices.")
    return events


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="lan-sentinel", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default="config.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan")
    w = sub.add_parser("watch")
    w.add_argument("--interval", type=int, default=60)
    sub.add_parser("pending")
    a = sub.add_parser("approve")
    a.add_argument("mac")
    a.add_argument("--name", required=True)
    a.add_argument("--owner", required=True)
    a.add_argument("--criticality", choices=["low", "medium", "high"], default="low")
    r = sub.add_parser("report")
    r.add_argument("--days", type=int, default=30)
    e = sub.add_parser("events")
    e.add_argument("--limit", type=int, default=30)
    sub.add_parser("reset-gateway")
    args = ap.parse_args(argv)

    cfg = config_mod.load(args.config)
    inv = Inventory(cfg["database"])

    if args.cmd in ("scan", "watch"):
        from .netinfo import detect
        net = detect(cfg["interface"], cfg["cidr"])
        print(f"Interface {net.iface} | scope {net.cidr} | gateway {net.gateway}")
        refresh = args.interval if args.cmd == "watch" else None
        while True:
            cycle(cfg, inv, net, refresh)
            if args.cmd == "scan":
                break
            time.sleep(args.interval)
            cfg = config_mod.load(args.config)  # pick up approvals without restart

    elif args.cmd == "pending":
        rows = [a for m, a in inv.assets().items() if m not in cfg["known_devices"]]
        if not rows:
            print("No unapproved assets.")
        for a in rows:
            print(f"{a['ip']:15} {a['mac']}  {a['vendor']:25} {a['hostname'] or '-':25} last {a['last_seen']}")
            print(f"    lan-sentinel approve {a['mac']} --name '?' --owner '?' --criticality low")

    elif args.cmd == "approve":
        config_mod.approve(args.config, args.mac, args.name, args.owner, args.criticality)
        print(f"Approved {args.mac.lower()} as '{args.name}' ({args.criticality}) in {args.config}")

    elif args.cmd == "report":
        from .report import evidence_report, export_csv, render_map
        out = Path(cfg["output_dir"])
        out.mkdir(parents=True, exist_ok=True)
        allow = cfg["known_devices"]
        print(export_csv(inv, allow, out / "asset_register.csv"))
        print(evidence_report(inv, allow, out / "evidence_report.md", args.days))
        scans = inv.scans()
        gw_ip = next((a["ip"] for m, a in inv.assets().items() if m == inv.get_meta("gateway_mac")), "?")
        print(render_map(inv, allow, gw_ip, "", out / "map.html"))
        if not scans:
            print("[!] No scans recorded yet.")

    elif args.cmd == "events":
        for ev in inv.events(limit=args.limit):
            print(f"{ev['ts']} [{ev['severity'].upper():8}] {ev['type']:26} {ev['ip'] or '-':15} {ev['detail']}")

    elif args.cmd == "reset-gateway":
        inv.db.execute("DELETE FROM meta WHERE key='gateway_mac'")
        inv.db.commit()
        print("Gateway baseline cleared; it will be re-learned on the next scan.")


if __name__ == "__main__":
    main()
