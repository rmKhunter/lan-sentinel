# lan-sentinel

LAN asset inventory with rogue-device and ARP-spoofing detection, producing audit-ready evidence mapped to **NIS-2 Art. 21** and **ISO/IEC 27001:2022 Annex A**.

> Only run this on networks you own or are authorized in writing to monitor.

## Why

You cannot protect assets you do not know about. Asset management is an explicit NIS-2 risk-management measure (Art. 21(2)(i)) and ISO 27001 control (A.5.9), yet in small environments the "inventory" is usually a stale spreadsheet. lan-sentinel turns it into a continuously verified register: what *should* be on the network (`known_devices`, reviewed in Git) is compared with what *is* on the network (ARP sweep), and every gap becomes a finding or an alert.

## Threat model

| Threat | Detection | Severity |
|---|---|---|
| Unauthorized device joins the LAN | `NEW_UNKNOWN_DEVICE` (not in approved register) | high |
| ARP spoofing / MITM on the gateway | `GATEWAY_MAC_CHANGED` (drift from learned baseline) | critical |
| IP hijack or misconfiguration | `IP_CONFLICT` (≥2 MACs for one IP in one sweep) | high |
| Host answering for many IPs (poisoning tool, proxy ARP) | `MAC_MULTI_IP` | medium |
| Critical asset disappears (NAS, camera, router) | `CRITICAL_ASSET_OFFLINE` (fired once per outage) | medium |
| Asset moves address | `IP_CHANGED` | info |

**Not covered (by design, stated in every report):** MAC cloning of an approved device, other VLANs/subnets, passive or sleeping devices that ignore ARP, true L2 topology (needs SNMP/LLDP).

## Architecture

```
ARP sweep (scapy) ──► detectors.analyze()  ──► events ──► console / ntfy push
      │               pure function, unit-tested      └──► SQLite audit trail
      └──────────────► inventory (SQLite: assets, scans, events, baselines)
                                   │
config.yaml (approved register) ───┴──► reports: asset_register.csv
                                                 evidence_report.md (control mapping)
                                                 map.html (interactive topology)
```

Design decisions:
- **Detection logic is a pure function** (`detectors.analyze`): no network, no root, deterministic → testable in CI.
- **First run is a baseline**, not an incident flood: existing devices are recorded as `BASELINE_ASSET`, then reviewed with `pending` / `approve`.
- **Approved register is YAML in Git**: each approval is a dated, attributable change (change-management evidence).
- **Least privilege deployment**: systemd unit runs as a dedicated user with only `CAP_NET_RAW` and a read-only filesystem.

## Quickstart

```bash
git clone <repo> && cd lan-sentinel
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp config.example.yaml config.yaml
.venv/bin/pytest -q                                   # logic tests, no root needed

sudo .venv/bin/lan-sentinel scan                      # 1st run = baseline
.venv/bin/lan-sentinel pending                        # review unknown devices
.venv/bin/lan-sentinel approve aa:bb:cc:dd:ee:ff --name "Router" --owner admin --criticality high
sudo .venv/bin/lan-sentinel watch --interval 60       # live mode, reports/map.html auto-refreshes
.venv/bin/lan-sentinel report                         # CSV + evidence report + map
```

Push alerts: set `alerts.ntfy_url` to `https://ntfy.sh/<long-random-topic>` and subscribe in the ntfy app.

## Hardened deployment (Raspberry Pi / home server)

```bash
sudo useradd --system --home /var/lib/lan-sentinel --shell /usr/sbin/nologin lan-sentinel
sudo mkdir -p /opt/lan-sentinel /var/lib/lan-sentinel /etc/lan-sentinel
sudo cp -r . /opt/lan-sentinel && cd /opt/lan-sentinel
sudo python3 -m venv .venv && sudo .venv/bin/pip install .
sudo cp config.example.yaml /etc/lan-sentinel/config.yaml
# in /etc/lan-sentinel/config.yaml: database: /var/lib/lan-sentinel/lan_sentinel.db
#                                    output_dir: /var/lib/lan-sentinel/reports
sudo chown -R lan-sentinel: /var/lib/lan-sentinel
sudo cp deploy/lan-sentinel.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now lan-sentinel.timer
journalctl -u lan-sentinel -f
```

## Validation (own lab only)

| Test | Expected |
|---|---|
| Connect a new phone/guest device | `NEW_UNKNOWN_DEVICE` + push |
| Unplug a device marked `criticality: high` for > `offline_minutes` | one `CRITICAL_ASSET_OFFLINE` |
| From a second machine you own, ARP-spoof the gateway towards your scanner host | `GATEWAY_MAC_CHANGED` (critical) |
| `lan-sentinel report` | `evidence_report.md` lists open findings and control mapping |

## Control mapping

| Requirement | Evidence |
|---|---|
| NIS-2 Art. 21(2)(i) asset management | Continuously updated register with owner and criticality |
| NIS-2 Art. 21(2)(b) incident handling | Severity-rated detections, timestamped audit trail, alerting |
| ISO/IEC 27001:2022 A.5.9 inventory of assets | `asset_register.csv`, unapproved assets as findings |
| ISO/IEC 27001:2022 A.8.16 monitoring activities | Scheduled scans, coverage stats in report |
| ISO/IEC 27001:2022 A.8.20 networks security | Rogue device and ARP-MITM indicators |

## Roadmap

1. **Service exposure**: `nmap -sV` on new assets, flag risky open ports (Telnet, SMB, UPnP).
2. **Vulnerability context**: map detected services/vendors to CVEs (NVD API).
3. **Passive mode**: sniff ARP/DHCP instead of sweeping; detects devices between scans.
4. **LLM triage agent with guardrails**: read-only tools over the event store, evaluated against labeled scenarios (agentic AI assurance: tool scoping, prompt-injection via hostnames, eval harness).

## License

MIT
