"""Active ARP sweep + enrichment. Needs CAP_NET_RAW (root or systemd capability)."""
from __future__ import annotations

import socket

from .detectors import is_randomized


def arp_scan(iface: str, cidr: str, timeout: float = 2, retry: int = 1) -> list[tuple[str, str]]:
    from scapy.all import ARP, Ether, srp  # lazy: tests don't need scapy loaded
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                 iface=iface, timeout=timeout, retry=retry, verbose=False)
    # Keep every (ip, mac) pair: duplicates are signal (IP conflicts), not noise.
    return sorted({(r.psrc, r.hwsrc.lower()) for _, r in ans})


def lookup_vendor(mac: str) -> str:
    if is_randomized(mac):
        return "randomized"
    try:
        from scapy.all import conf
        v = conf.manufdb._get_manuf(mac)
        return v if v and v.lower() != mac.lower() else "unknown"
    except Exception:
        return "unknown"


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
