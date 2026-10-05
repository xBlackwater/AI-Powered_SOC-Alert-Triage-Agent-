#!/usr/bin/env python3
"""
triage.py - SOC alert triage: deterministic enrichment + scoring,
with LLM-written justifications.

Usage:
    python3 triage.py <alerts.json> [--no-llm] [--limit N] [--out report.md]
"""
import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_PATH = SCRIPT_DIR / ".enrichment_cache.json"

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("TRIAGE_MODEL", "llama3.1:8b")

LEVELS = ["Low", "Medium", "High", "Critical"]
HIGH_RISK_TYPES = {
    "Privilege Escalation Attempt",
    "Known C2 Beacon Pattern",
    "Unusual Data Exfiltration Volume",
    "Malware Signature Match",
}

VT_MIN_INTERVAL = 16  # seconds; VirusTotal free tier allows ~4 requests/minute
_last_vt_call = 0.0


# ---------- caching ----------
def load_cache():
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def save_cache(cache):
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


# ---------- enrichment ----------
def is_external(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
    return not any(a in ipaddress.ip_network(n) for n in nets)


def lookup_ip(ip):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"error": "ABUSEIPDB_API_KEY not set"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=20,
        )
    except requests.RequestException as e:
        return {"error": str(e)}
    if r.status_code != 200:
        return {"error": f"AbuseIPDB HTTP {r.status_code}"}
    d = r.json()["data"]
    return {
        "score": d["abuseConfidenceScore"],
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "reports": d["totalReports"],
        "whitelisted": bool(d.get("isWhitelisted")),
    }


def lookup_hash(file_hash):
    global _last_vt_call
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"error": "VT_API_KEY not set"}
    wait = VT_MIN_INTERVAL - (time.time() - _last_vt_call)
    if wait > 0:
        print(f"      (VirusTotal free tier: pausing {wait:.0f}s)")
        time.sleep(wait)
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": key},
            timeout=20,
        )
    except requests.RequestException as e:
        _last_vt_call = time.time()
        return {"error": str(e)}
    _last_vt_call = time.time()
    if r.status_code == 404:
        return {"not_found": True, "malicious": 0, "suspicious": 0, "total": 0}
    if r.status_code != 200:
        return {"error": f"VirusTotal HTTP {r.status_code}"}
    attrs = r.json()["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "type": attrs.get("type_description", "Unknown"),
    }


def enrich(kind, value, cache):
    key = f"{kind}:{value}"
    if key in cache:
        return cache[key]
    result = lookup_ip(value) if kind == "ip" else lookup_hash(value)
    if "error" not in result:  # never cache failures
        cache[key] = result
        save_cache(cache)
    return result


# ---------- scoring ----------
def score_alert(alert, ip_results, hash_results):
    level = 0
    reasons = []
    for ip, r in ip_results.items():
        if "error" in r:
            continue
        s = r["score"]
        if s > 75:
            level = max(level, 3)
            reasons.append(f"IP {ip} has abuse confidence {s}% (above 75%)")
        elif s >= 25:
            level = max(level, 2)
            reasons.append(f"IP {ip} has abuse confidence {s}% (25-75%)")
    for h, r in hash_results.items():
        if "error" in r or r.get("not_found"):
            continue
        m = r["malicious"]
        if m >= 10:
            level = max(level, 3)
            reasons.append(f"hash {h[:12]}... flagged malicious by {m}/{r['total']} vendors")
        elif m >= 1:
            level = max(level, 2)
            reasons.append(f"hash {h[:12]}... flagged malicious by {m}/{r['total']} vendors")
    if level < 1 and alert["alert_type"] in HIGH_RISK_TYPES:
        level = 1
        reasons.append(f"alert type '{alert['alert_type']}' is inherently higher-risk")
    if not reasons:
        reasons.append("no malicious enrichment hits and a routine alert type")
    return LEVELS[level], reasons


def process_alert(alert, cache):
    ip_results, hash_results, skipped = {}, {}, []
    seen = set()
    for field in ("src_ip", "dest_ip"):
        ip = alert.get(field)
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if is_external(ip):
            ip_results[ip] = enrich("ip", ip, cache)
        else:
            skipped.append(ip)
    h = alert.get("file_hash")
    if h:
        hash_results[h] = enrich("hash", h, cache)
    severity, reasons = score_alert(alert, ip_results, hash_results)
    return {
        "alert": alert,
        "severity": severity,
        "reasons": reasons,
        "ip_results": ip_results,
        "hash_results": hash_results,
        "skipped_internal": skipped,
    }


# ---------- LLM justification ----------
def llm_justification(res):
    facts = {
        "alert_id": res["alert"]["alert_id"],
        "alert_type": res["alert"]["alert_type"],
        "reported_severity": res["alert"].get("severity_reported"),
        "assigned_severity": res["severity"],
        "rule_findings": res["reasons"],
        "ip_enrichment": res["ip_results"],
        "hash_enrichment": res["hash_results"],
        "internal_ips_not_enriched": res["skipped_internal"],
    }
    system = (
        "You are a SOC analyst assistant. Write 2-3 sentences justifying the "
        "assigned severity for the alert. Use ONLY the facts provided. Do not "
        "mention threat actors, nation-states, or what a country is known for. "
        "A file hash listed on an alert was merely observed on that record; "
        "do not claim it was used in or caused the alert activity. State the "
        "assigned severity exactly as given. End with one recommended next "
        "step for a human analyst. Never recommend automated containment."
    )
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": MODEL,
                "stream": False,
                "options": {"temperature": 0.2},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(facts, indent=2)},
                ],
            },
            timeout=300,
        )
        r.raise_for_status()
        return r.json()["message"]["content"].strip() or None
    except (requests.RequestException, KeyError, ValueError):
        return None


# ---------- report ----------
def write_report(results, path, used_llm):
    counts = {lvl: 0 for lvl in LEVELS}
    for r in results:
        counts[r["severity"]] += 1
    lines = [
        "# SOC Alert Triage Report",
        "",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}",
        f"Alerts triaged: {len(results)}",
        "Severity counts: " + ", ".join(f"{k}: {counts[k]}" for k in reversed(LEVELS)),
        f"Justifications: {'LLM (' + MODEL + ')' if used_llm else 'rule-based only'}",
        "",
        "| Rank | Alert | Type | Reported | Triaged |",
        "|---|---|---|---|---|",
    ]
    for i, r in enumerate(results, 1):
        a = r["alert"]
        lines.append(f"| {i} | {a['alert_id']} | {a['alert_type']} | "
                     f"{a.get('severity_reported', '-')} | **{r['severity']}** |")
    lines.append("")
    for i, r in enumerate(results, 1):
        a = r["alert"]
        lines += [
            f"## {i}. {a['alert_id']} - {r['severity']}",
            f"- Type: {a['alert_type']} (reported: {a.get('severity_reported', '-')})",
            f"- Host: {a.get('internal_host', '-')}, {a.get('src_ip')} -> {a.get('dest_ip')}",
            f"- Findings: {'; '.join(r['reasons'])}",
            "",
            r["justification"],
            "",
        ]
    Path(path).write_text("\n".join(lines))


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Triage SOC alerts from a JSON file.")
    ap.add_argument("alerts_file")
    ap.add_argument("--no-llm", action="store_true", help="skip LLM justifications")
    ap.add_argument("--limit", type=int, help="only process the first N alerts")
    ap.add_argument("--out", default="triage_report.md")
    args = ap.parse_args()

    path = Path(args.alerts_file)
    if not path.exists():
        sys.exit(f"File not found: {path}")
    alerts = json.loads(path.read_text())
    if args.limit:
        alerts = alerts[: args.limit]

    for var in ("ABUSEIPDB_API_KEY", "VT_API_KEY"):
        if not os.environ.get(var):
            print(f"WARNING: {var} is not set; those lookups will fail.")

    cache = load_cache()
    results = []
    llm_failed = False
    for i, alert in enumerate(alerts, 1):
        print(f"[{i}/{len(alerts)}] {alert['alert_id']} - {alert['alert_type']}")
        res = process_alert(alert, cache)
        print(f"      -> {res['severity']}")
        text = None
        if not args.no_llm and not llm_failed:
            text = llm_justification(res)
            if text is None:
                llm_failed = True
                print("      WARNING: Ollama did not respond; using rule-based text.")
        res["justification"] = text or ("Rule findings: " + "; ".join(res["reasons"]) + ".")
        results.append(res)

    results.sort(key=lambda r: (-LEVELS.index(r["severity"]),
                                -len(r["reasons"]),
                                r["alert"]["alert_id"]))
    write_report(results, args.out, used_llm=not args.no_llm and not llm_failed)

    print("\n=== Ranked triage queue ===")
    for i, r in enumerate(results, 1):
        print(f"{i:>2}. {r['alert']['alert_id']}  {r['severity']:<8}  {r['alert']['alert_type']}")
    print(f"\nFull report written to {args.out}")


if __name__ == "__main__":
    main()
