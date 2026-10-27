"""Auto-detect interface, subnet and gateway from the default route (Linux, iproute2)."""
from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class NetInfo:
    iface: str
    gateway: str
    cidr: str
    my_ip: str
    my_mac: str


def _run(args: list[str]) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=False).stdout.strip()


def detect(iface: str | None = None, cidr: str | None = None) -> NetInfo:
    route = _run(["ip", "-4", "route", "show", "default"]).split()
    if "via" not in route:
        raise SystemExit("No default route: are you connected?")
    gateway = route[route.index("via") + 1]
    iface = iface or route[route.index("dev") + 1]
    addr = _run(["ip", "-o", "-4", "addr", "show", "dev", iface]).split()
    if "inet" not in addr:
        raise SystemExit(f"No IPv4 address on {iface}")
    host_cidr = addr[addr.index("inet") + 1]
    my_ip = host_cidr.split("/")[0]
    net = ipaddress.ip_network(cidr or host_cidr, strict=False)
    if net.prefixlen < 22:
        raise SystemExit(f"{net} is larger than /22: set 'cidr' explicitly in the config.")
    my_mac = Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
    return NetInfo(iface, gateway, str(net), my_ip, my_mac)
