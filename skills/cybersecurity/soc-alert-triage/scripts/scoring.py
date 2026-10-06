"""scoring.py - pure scoring logic (no network, no files) so it can be unit tested."""

LEVELS = ["Low", "Medium", "High", "Critical"]
HIGH_RISK_TYPES = {
    "Privilege Escalation Attempt",
    "Known C2 Beacon Pattern",
    "Unusual Data Exfiltration Volume",
    "Malware Signature Match",
}
NOISY_INBOUND_TYPES = {"Port Scan Detected", "Brute Force Attack", "Failed Login Attempts"}


def direction(alert, ip_results):
    """'outbound', 'inbound' or 'other'. ip_results only holds EXTERNAL IPs,
    so an endpoint present in it is external and one missing from it is internal."""
    src_ext = alert.get("src_ip") in ip_results
    dst_ext = alert.get("dest_ip") in ip_results
    if dst_ext and not src_ext:
        return "outbound"
    if src_ext and not dst_ext:
        return "inbound"
    return "other"


def _ip_level(r):
    if "error" in r:
        return 0
    s = r["score"]
    return 3 if s > 75 else 2 if s >= 25 else 0


def _hash_level(r):
    if "error" in r or r.get("not_found"):
        return 0
    m = r["malicious"]
    return 3 if m >= 10 else 2 if m >= 1 else 0


def score_alert(alert, ip_results, hash_results):
    """Returns (severity, reasons)."""
    atype = alert["alert_type"]
    way = direction(alert, ip_results)
    reasons = []

    ip_level = 0
    for ip, r in ip_results.items():
        lvl = _ip_level(r)
        if lvl:
            reasons.append(f"IP {ip} has abuse confidence {r['score']}%")
            ip_level = max(ip_level, lvl)
    if ip_level:
        if way == "outbound":
            ip_level = min(ip_level + 1, 3)
            reasons.append("internal host is communicating outbound with a flagged IP "
                           "(possible compromised host)")
        elif way == "inbound" and atype in NOISY_INBOUND_TYPES:
            ip_level -= 1
            reasons.append(f"inbound {atype.lower()} from a flagged IP is common internet "
                           "background noise (downgraded one level)")

    hash_level = 0
    for h, r in hash_results.items():
        lvl = _hash_level(r)
        if lvl:
            reasons.append(f"hash {h[:12]}... flagged malicious by {r['malicious']}/{r['total']} vendors")
            hash_level = max(hash_level, lvl)

    level = max(ip_level, hash_level)
    if ip_level >= 2 and hash_level >= 2:
        level = 3
        reasons.append("IP and file hash evidence agree")
    if level < 1 and atype in HIGH_RISK_TYPES:
        level = 1
        reasons.append(f"alert type '{atype}' is inherently higher-risk")
    if not reasons:
        reasons.append("no malicious enrichment hits and a routine alert type")
    return LEVELS[level], reasons
