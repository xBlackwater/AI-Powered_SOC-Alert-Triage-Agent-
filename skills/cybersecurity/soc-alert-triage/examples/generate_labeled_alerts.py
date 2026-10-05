#!/usr/bin/env python3
"""
generate_labeled_alerts.py - reproducible synthetic alerts with ground-truth labels.

Labels describe the scenario each alert was BUILT from, not what the triage
pipeline outputs, so evaluation is not circular.

Usage: python3 generate_labeled_alerts.py [count] [seed]
"""
import json
import random
import sys
from collections import Counter
from datetime import datetime, timedelta

# Verify every indicator with check_ip.py / check_hash.py before relying on it.
BAD_IPS = ["185.220.101.45"]  # TODO: add 3-5 more IPs you have verified score >75
CLEAN_PUBLIC_IPS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
INTERNAL_IPS = ["10.0.0.22", "10.0.0.31", "192.168.1.15", "192.168.1.40"]
BAD_HASHES = ["44d88612fea8a8f36de82e1278abb02f"]  # EICAR test file
CLEAN_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file (MD5)
]
HOSTS = ["WORKSTATION-07", "WORKSTATION-12", "SERVER-DB01", "SERVER-WEB02", "LAPTOP-USER23"]

# scenario: (weight, ground_truth)
SCENARIOS = {
    "tp_bad_ip_attack": (0.25, "malicious"),
    "tp_malware_bad_hash": (0.15, "malicious"),
    "tp_intel_blind_high_risk": (0.10, "malicious"),
    "fp_internal_failed_logins": (0.20, "benign"),
    "fp_clean_outbound": (0.15, "benign"),
    "fp_signature_clean_hash": (0.10, "benign"),
    "fp_internal_scanner": (0.05, "benign"),
}


def build(scenario, rng):
    c = rng.choice
    extra = {}
    if scenario == "tp_bad_ip_attack":
        atype = c(["Unusual Data Exfiltration Volume", "Known C2 Beacon Pattern",
                   "Brute Force Attack", "Port Scan Detected", "Suspicious Outbound Connection"])
        bad, inside = c(BAD_IPS), c(INTERNAL_IPS)
        src, dst = (inside, bad) if rng.random() < 0.5 else (bad, inside)
        reported = c(["medium", "high"])
    elif scenario == "tp_malware_bad_hash":
        atype, src, dst = "Malware Signature Match", c(INTERNAL_IPS), c(INTERNAL_IPS)
        extra["file_hash"] = c(BAD_HASHES)
        reported = c(["medium", "high"])
    elif scenario == "tp_intel_blind_high_risk":
        atype = c(["Privilege Escalation Attempt", "Known C2 Beacon Pattern"])
        src, dst = c(INTERNAL_IPS), c(CLEAN_PUBLIC_IPS)
        reported = c(["low", "medium", "high"])
    elif scenario == "fp_internal_failed_logins":
        atype, src, dst = "Failed Login Attempts", c(INTERNAL_IPS), c(INTERNAL_IPS)
        reported = c(["low", "medium"])
    elif scenario == "fp_clean_outbound":
        atype, src, dst = "Suspicious Outbound Connection", c(INTERNAL_IPS), c(CLEAN_PUBLIC_IPS)
        reported = c(["medium", "high"])
    elif scenario == "fp_signature_clean_hash":
        atype, src, dst = "Malware Signature Match", c(INTERNAL_IPS), c(INTERNAL_IPS)
        extra["file_hash"] = c(CLEAN_HASHES)
        reported = "high"
    else:  # fp_internal_scanner
        atype, src, dst = "Port Scan Detected", c(INTERNAL_IPS), c(INTERNAL_IPS)
        reported = "medium"
    return atype, src, dst, reported, extra


def main(count=60, seed=42):
    rng = random.Random(seed)
    names = list(SCENARIOS)
    weights = [SCENARIOS[n][0] for n in names]
    base = datetime(2026, 10, 1, 0, 0, 0)
    alerts = []
    for i in range(1, count + 1):
        scenario = rng.choices(names, weights)[0]
        atype, src, dst, reported, extra = build(scenario, rng)
        host = rng.choice(HOSTS)
        alert = {
            "alert_id": f"ALERT-{i:04d}",
            "timestamp": (base + timedelta(minutes=i * rng.randint(3, 20))).isoformat(),
            "alert_type": atype,
            "severity_reported": reported,
            "src_ip": src,
            "dest_ip": dst,
            "internal_host": host,
            "raw_log": f"{atype} detected from {host}",
            "ground_truth": SCENARIOS[scenario][1],
            "scenario": scenario,
        }
        alert.update(extra)
        alerts.append(alert)

    with open("sample_alerts_labeled.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Wrote {count} labeled alerts (seed={seed}) -> sample_alerts_labeled.json")
    for name, n in sorted(Counter(a["scenario"] for a in alerts).items()):
        print(f"  {name:<28} {n:>3}  [{SCENARIOS[name][1]}]")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    s = int(sys.argv[2]) if len(sys.argv) > 2 else 42
    main(n, s)
