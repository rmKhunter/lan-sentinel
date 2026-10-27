"""Console + optional ntfy.sh push (stdlib only, no extra dependency)."""
from __future__ import annotations

import urllib.request

from .detectors import Event, sev_rank

NTFY_PRIORITY = {"critical": "5", "high": "4", "medium": "3", "low": "2", "info": "1"}


def dispatch(events: list[Event], alerts_cfg: dict) -> None:
    for e in events:
        print(f"[{e.severity.upper():8}] {e.type:26} {e.ip or '-':15} {e.mac or '-'}  {e.detail}")
    url = alerts_cfg.get("ntfy_url")
    if not url:
        return
    threshold = sev_rank(alerts_cfg.get("min_severity", "high"))
    for e in events:
        if sev_rank(e.severity) < threshold:
            continue
        req = urllib.request.Request(url, data=e.detail.encode(), method="POST", headers={
            "Title": f"lan-sentinel: {e.type}",
            "Priority": NTFY_PRIORITY[e.severity],
            "Tags": "rotating_light" if e.severity == "critical" else "warning",
        })
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:  # alerting must never kill the scan loop
            print(f"[!] ntfy delivery failed: {exc}")
