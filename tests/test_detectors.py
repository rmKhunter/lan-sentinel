from datetime import datetime, timedelta

from lan_sentinel.detectors import analyze, is_randomized, is_stale

NOW = datetime(2026, 10, 27, 21, 0, 0)
GW_IP, GW_MAC = "192.168.1.1", "00:11:22:33:44:55"
PC = "00:aa:bb:cc:dd:01"


def asset(ip, minutes_ago=0, status="online"):
    return {"ip": ip, "last_seen": (NOW - timedelta(minutes=minutes_ago)).isoformat(), "status": status}


def types(events):
    return sorted(e.type for e in events)


def run(obs, assets=None, allow=None, baseline=GW_MAC, **kw):
    return analyze(obs, assets or {}, allow or {}, GW_IP, baseline, NOW, **kw)


def test_clean_scan_has_no_events():
    assets = {GW_MAC: asset(GW_IP), PC: asset("192.168.1.10")}
    assert run([(GW_IP, GW_MAC), ("192.168.1.10", PC)], assets) == []


def test_unknown_device_is_high():
    ev = run([("192.168.1.50", "00:de:ad:be:ef:00")], {GW_MAC: asset(GW_IP)})
    assert types(ev) == ["NEW_UNKNOWN_DEVICE"] and ev[0].severity == "high"


def test_allowlisted_first_sight_is_info():
    ev = run([("192.168.1.10", PC)], allow={PC: {"name": "laptop"}})
    assert types(ev) == ["APPROVED_DEVICE_FIRST_SEEN"] and ev[0].severity == "info"


def test_gateway_mac_change_is_critical_and_not_double_reported():
    attacker = "00:66:66:66:66:66"
    ev = run([(GW_IP, attacker)], {GW_MAC: asset(GW_IP), attacker: asset("192.168.1.66")})
    assert "GATEWAY_MAC_CHANGED" in types(ev)
    assert [e for e in ev if e.type == "GATEWAY_MAC_CHANGED"][0].severity == "critical"
    ev2 = run([(GW_IP, GW_MAC), (GW_IP, attacker)], {GW_MAC: asset(GW_IP), attacker: asset("192.168.1.66")})
    assert "GATEWAY_MAC_CHANGED" in types(ev2) and "IP_CONFLICT" not in types(ev2)


def test_no_gateway_alert_without_baseline():
    assert "GATEWAY_MAC_CHANGED" not in types(run([(GW_IP, GW_MAC)], baseline=None))


def test_ip_conflict():
    a, b = "00:00:00:00:00:0a", "00:00:00:00:00:0b"
    ev = run([("192.168.1.20", a), ("192.168.1.20", b)], {a: asset("192.168.1.20"), b: asset("192.168.1.21")})
    assert "IP_CONFLICT" in types(ev)


def test_mac_multi_ip():
    m = "00:00:00:00:00:0c"
    obs = [(f"192.168.1.{i}", m) for i in (30, 31, 32)]
    assert "MAC_MULTI_IP" in types(run(obs, {m: asset("192.168.1.30")}))


def test_ip_change_is_info():
    ev = run([("192.168.1.11", PC)], {PC: asset("192.168.1.10")})
    assert types(ev) == ["IP_CHANGED"] and ev[0].severity == "info"


def test_critical_offline_fires_once_after_threshold():
    allow = {PC: {"name": "NAS", "criticality": "high"}}
    assert run([], {PC: asset("192.168.1.10", minutes_ago=5)}, allow) == []
    assert types(run([], {PC: asset("192.168.1.10", minutes_ago=20)}, allow)) == ["CRITICAL_ASSET_OFFLINE"]
    assert run([], {PC: asset("192.168.1.10", 20, status="offline")}, allow) == []


def test_non_critical_offline_is_silent():
    assert run([], {PC: asset("192.168.1.10", 60)}, {PC: {"criticality": "low"}}) == []


def test_helpers():
    assert is_randomized("da:a1:19:00:00:01") and not is_randomized("00:1a:2b:3c:4d:5e")
    assert is_stale((NOW - timedelta(minutes=16)).isoformat(), NOW, 15)
    assert not is_stale((NOW - timedelta(minutes=14)).isoformat(), NOW, 15)
