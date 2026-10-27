"""Pure detection logic: no I/O, no root, fully unit-testable.

Input = one scan's ARP observations + previous inventory state.
Output = list of security events.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Event:
    type: str
    severity: str
    mac: str | None
    ip: str | None
    detail: str


def is_stale(last_seen: str, now: datetime, minutes: int) -> bool:
    return now - datetime.fromisoformat(last_seen) > timedelta(minutes=minutes)


def is_randomized(mac: str) -> bool:
    """Locally-administered bit set -> typical of phone/laptop MAC privacy features."""
    return bool(int(mac.split(":")[0], 16) & 0b10)


def analyze(
    observations: list[tuple[str, str]],
    assets: dict[str, dict],
    allowlist: dict[str, dict],
    gateway_ip: str,
    gateway_mac_baseline: str | None,
    now: datetime,
    offline_minutes: int = 15,
    multi_ip_threshold: int = 3,
    vendor_fn: Callable[[str], str] = lambda mac: "",
) -> list[Event]:
    events: list[Event] = []
    by_ip: dict[str, set[str]] = defaultdict(set)
    by_mac: dict[str, set[str]] = defaultdict(set)
    for ip, mac in observations:
        by_ip[ip].add(mac)
        by_mac[mac].add(ip)

    # 1. Gateway MAC drift: strongest ARP-spoofing / MITM signal on a home/SMB LAN.
    gw_macs = by_ip.get(gateway_ip, set())
    if gateway_mac_baseline and gw_macs and gw_macs != {gateway_mac_baseline}:
        events.append(Event(
            "GATEWAY_MAC_CHANGED", "critical", ",".join(sorted(gw_macs)), gateway_ip,
            f"Gateway {gateway_ip} answered from {sorted(gw_macs)}, baseline is "
            f"{gateway_mac_baseline}. Possible ARP spoofing/MITM, or router replaced "
            f"(then reset the baseline)."))

    # 2. IP conflict: two MACs claim the same IP in one scan.
    for ip, macs in sorted(by_ip.items()):
        if len(macs) > 1 and not (ip == gateway_ip and gateway_mac_baseline):
            events.append(Event(
                "IP_CONFLICT", "high", ",".join(sorted(macs)), ip,
                f"{len(macs)} MACs answered for {ip}: {sorted(macs)}. Spoofing or misconfiguration."))

    # 3. One MAC answering for many IPs (ARP poisoning tools, proxy ARP).
    for mac, ips in sorted(by_mac.items()):
        if len(ips) >= multi_ip_threshold and mac != gateway_mac_baseline:
            events.append(Event(
                "MAC_MULTI_IP", "medium", mac, ",".join(sorted(ips)),
                f"{mac} answered for {len(ips)} IPs. Check for ARP poisoning or proxy ARP."))

    # 4. New devices / IP changes.
    for mac, ips in sorted(by_mac.items()):
        ip = sorted(ips)[0]
        if mac not in assets:
            approved = mac in allowlist
            rnd = " (randomized MAC)" if is_randomized(mac) else ""
            vendor = vendor_fn(mac) or "unknown vendor"
            if approved:
                events.append(Event("APPROVED_DEVICE_FIRST_SEEN", "info", mac, ip,
                                    f"{allowlist[mac].get('name', mac)} first seen at {ip}"))
            else:
                events.append(Event("NEW_UNKNOWN_DEVICE", "high", mac, ip,
                                    f"Unapproved device {mac} ({vendor}){rnd} at {ip}"))
        elif assets[mac].get("ip") not in ips:
            events.append(Event("IP_CHANGED", "info", mac, ip,
                                f"{mac} moved {assets[mac].get('ip')} -> {ip}"))

    # 5. Critical approved asset went offline (alerted once, at the online->offline transition).
    for mac, a in sorted(assets.items()):
        if (mac not in by_mac and a.get("status") == "online"
                and allowlist.get(mac, {}).get("criticality") == "high"
                and is_stale(a["last_seen"], now, offline_minutes)):
            events.append(Event(
                "CRITICAL_ASSET_OFFLINE", "medium", mac, a.get("ip"),
                f"{allowlist[mac].get('name', mac)} not seen for >{offline_minutes} min "
                f"(last {a['last_seen']})"))
    return events
