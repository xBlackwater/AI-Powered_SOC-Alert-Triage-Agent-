#!/usr/bin/env python3
"""
evaluate_triage.py - evaluate the triage pipeline against ground-truth labels.

Usage:
    python3 evaluate_triage.py <labeled_alerts.json> [--manual-seconds N] [--out FILE]

Runs enrichment + scoring twice: a cold-cache pass (real API calls, free-tier
throttling included) and a warm-cache pass. A temporary cache is used, so the
real enrichment cache is untouched. Makes a handful of real API calls.
LLM justifications are NOT evaluated here.
"""
import argparse
import json
import os
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import triage
from scoring import LEVELS

REPORTED_ORDER = {"low": 0, "medium": 1, "high": 2}
THRESHOLDS = {"Medium+": 1, "High+": 2}


def confusion(truth, pred):
    """Returns tp, fp, fn, tn, precision, recall, f1 (None where undefined)."""
    tp = sum(1 for t, p in zip(truth, pred) if t and p)
    fp = sum(1 for t, p in zip(truth, pred) if not t and p)
    fn = sum(1 for t, p in zip(truth, pred) if t and not p)
    tn = sum(1 for t, p in zip(truth, pred) if not t and not p)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    if prec is None or rec is None:
        f1 = None
    elif prec + rec == 0:
        f1 = 0.0
    else:
        f1 = 2 * prec * rec / (prec + rec)
    return tp, fp, fn, tn, prec, rec, f1


def fmt(x):
    return "n/a" if x is None else f"{x:.2f}"


def run_pass(alerts, cache):
    results = []
    for i, alert in enumerate(alerts, 1):
        results.append(triage.process_alert(alert, cache))
        if i % 10 == 0 or i == len(alerts):
            print(f"  processed {i}/{len(alerts)}")
    return results


def main():
    ap = argparse.ArgumentParser(description="Evaluate triage against ground truth.")
    ap.add_argument("alerts_file")
    ap.add_argument("--manual-seconds", type=float,
                    help="your measured manual triage time per alert, in seconds")
    ap.add_argument("--out", default="evaluation_results.md")
    args = ap.parse_args()

    for var in ("ABUSEIPDB_API_KEY", "VT_API_KEY"):
        if not os.environ.get(var):
            sys.exit(f"{var} is not set; lookups would fail and skew every metric.")

    alerts = json.loads(Path(args.alerts_file).read_text())
    missing = [a["alert_id"] for a in alerts if "ground_truth" not in a]
    if missing:
        sys.exit(f"{len(missing)} alerts have no ground_truth label (first: {missing[0]})")

    # Count real API calls by wrapping the lookup functions.
    calls = Counter()
    orig_ip, orig_hash = triage.lookup_ip, triage.lookup_hash

    def counted_ip(ip):
        calls["ip"] += 1
        return orig_ip(ip)

    def counted_hash(h):
        calls["hash"] += 1
        return orig_hash(h)

    triage.lookup_ip, triage.lookup_hash = counted_ip, counted_hash

    # Temporary cache => genuine cold start, real cache untouched.
    triage.CACHE_PATH = Path(tempfile.mkdtemp()) / "eval_cache.json"
    cache = triage.load_cache()

    print("Pass 1: cold cache (real API calls; VirusTotal throttling included)...")
    t0 = time.perf_counter()
    results = run_pass(alerts, cache)
    cold = time.perf_counter() - t0
    ip_calls, hash_calls = calls["ip"], calls["hash"]
    api_calls = ip_calls + hash_calls

    print("Pass 2: warm cache...")
    t0 = time.perf_counter()
    run_pass(alerts, cache)
    warm = time.perf_counter() - t0

    errors = sum(1 for r in results for d in (r["ip_results"], r["hash_results"])
                 for v in d.values() if "error" in v)

    truth = [a["ground_truth"] == "malicious" for a in alerts]
    idx = {lvl: i for i, lvl in enumerate(LEVELS)}
    new = [r["severity"] for r in results]
    legacy = [triage._legacy_score_alert(r["alert"], r["ip_results"], r["hash_results"])[0]
              for r in results]
    methods = {
        "Pipeline (new scoring)": [idx[s] for s in new],
        "Pipeline (old scoring)": [idx[s] for s in legacy],
        "SIEM-reported severity": [REPORTED_ORDER[a["severity_reported"]] for a in alerts],
    }

    by_scn, label = defaultdict(Counter), {}
    for a, s in zip(alerts, new):
        scn = a.get("scenario", "unknown")
        by_scn[scn][s] += 1
        label[scn] = a["ground_truth"]
    wrong = [(a["alert_id"], a.get("scenario", "unknown"), s, a["ground_truth"])
             for a, s, t in zip(alerts, new, truth) if (idx[s] >= 1) != t]

    naive = internal = 0
    for a in alerts:
        for f in ("src_ip", "dest_ip"):
            ip = a.get(f)
            if ip:
                naive += 1
                if not triage.is_external(ip):
                    internal += 1
        if a.get("file_hash"):
            naive += 1
    remaining = naive - internal

    n, n_mal = len(alerts), sum(truth)
    lines = []

    def out(s=""):
        lines.append(s)
        print(s)

    print()
    out("# Triage Pipeline Evaluation")
    out()
    out(f"Run: {datetime.now():%Y-%m-%d %H:%M} | Data: {args.alerts_file}")
    out(f"Alerts: {n} ({n_mal} malicious, {n - n_mal} benign)")
    out("Reputation data is live, so these results are a snapshot of the run date.")
    if errors:
        out()
        out(f"WARNING: {errors} lookups failed; the metrics below are unreliable. Re-run.")
    out()
    out("## Classification (positive class = malicious)")
    out()
    out("| Method | Threshold | TP | FP | FN | TN | Precision | Recall | F1 |")
    out("|---|---|---|---|---|---|---|---|---|")
    for name, levels in methods.items():
        for tname, cut in THRESHOLDS.items():
            tp, fp, fn, tn, p, r, f = confusion(truth, [lv >= cut for lv in levels])
            out(f"| {name} | {tname} | {tp} | {fp} | {fn} | {tn} | {fmt(p)} | {fmt(r)} | {fmt(f)} |")
    out()
    out("## New-scoring severity by scenario")
    out()
    out("| Scenario | Truth | n | Low | Medium | High | Critical |")
    out("|---|---|---|---|---|---|---|")
    for scn in sorted(by_scn):
        c = by_scn[scn]
        out(f"| {scn} | {label[scn]} | {sum(c.values())} | "
            + " | ".join(str(c[lv]) for lv in LEVELS) + " |")
    out()
    out("## Misclassified at Medium+ (new scoring)")
    out()
    if wrong:
        for aid, scn, sev, t in wrong[:20]:
            out(f"- {aid} ({scn}): triaged {sev}, truth {t}")
        if len(wrong) > 20:
            out(f"- ... and {len(wrong) - 20} more")
    else:
        out("- none")
    out()
    out("## Enrichment efficiency")
    out()
    out(f"- Naive baseline (look up every IP field and hash): {naive}")
    out(f"- Skipped as internal/private IPs: {internal} ({internal / naive:.0%})")
    out(f"- Left after skipping: {remaining}")
    out(f"- Actual API calls on a cold cache: {api_calls} ({ip_calls} IP, {hash_calls} hash)")
    out(f"- Saved by de-duplication and caching: {remaining - api_calls}")
    out(f"- Total reduction vs naive: {1 - api_calls / naive:.0%}")
    out()
    out("## Time-to-triage")
    out()
    out(f"- Cold cache: {cold:.1f}s total, {cold / n:.2f}s per alert "
        "(includes VirusTotal free-tier throttling)")
    out(f"- Warm cache: {warm:.2f}s total, {warm / n:.3f}s per alert")
    if args.manual_seconds:
        manual = args.manual_seconds * n
        out(f"- Manual baseline: {args.manual_seconds:.0f}s per alert, ~{manual:.0f}s for {n} alerts")
        out(f"- Speed-up vs manual: {manual / cold:.1f}x cold, {manual / warm:.0f}x warm")
    else:
        out("- Manual baseline: not provided (rerun with --manual-seconds N)")
    out()
    out("## Caveats")
    out()
    out("- Labels describe the scenarios the generator built; the scoring rules were written "
        "by the same author, so this measures agreement with those scenarios, not real-world accuracy.")
    out("- severity_reported was assigned by the generator, so the SIEM baseline reflects "
        "assumptions about SIEM noise, not a measured SIEM.")
    out("- Reported severity uses the same thresholds on its own low/medium/high scale.")
    out("- LLM justifications are not evaluated in this report.")

    Path(args.out).write_text("\n".join(lines) + "\n")
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()
