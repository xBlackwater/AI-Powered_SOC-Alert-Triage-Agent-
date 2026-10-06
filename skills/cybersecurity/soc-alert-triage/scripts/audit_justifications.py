#!/usr/bin/env python3
"""
audit_justifications.py - audit LLM-written justifications against the facts the
model was given, one model at a time.

Usage:
    python3 audit_justifications.py <labeled_alerts.json> --model llama3.1:8b [--limit N]

Results are saved per alert, so an interrupted run resumes where it stopped
(use --fresh to start over). Enrichment uses the real cache, so repeat runs make
few or no API calls. The checks are regex heuristics, so they give a LOWER BOUND
on overreach; review the manual sample in the report to calibrate.
"""
import argparse
import json
import random
import re
import statistics
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import requests
import triage

SEV_RE = re.compile(
    r'(?<!reported )severity (?:is |of |as |level of )?["\u201c]?(low|medium|high|critical)\b', re.I)
ATTRIB_RE = re.compile(
    r"state[- ]sponsored|nation[- ]state|(?-i:\bAPT ?\d+\b)|threat actors?|attribut", re.I)
COUNTRY_RE = re.compile(
    r"\b(russia|russian|china|chinese|iran|iranian|north korea|north korean)\b", re.I)
CAUSAL_RE = re.compile(
    r"\b(hash|file|script|powershell|malware|binary)\b[^.]{0,80}"
    r"\b(used in|used during|used for|used to|being used|responsible for|caused|behind)\b", re.I)
CONTAIN_RE = re.compile(
    r"\b(block|isolate|quarantine|disable|shut ?down|terminate|blacklist|wipe|reimage)\b", re.I)
NUM_RE = re.compile(r"\d+")
LIST_MARK_RE = re.compile(r"(?m)^\s*\d+[.)]\s+")
ADJ_SEV_RE = re.compile(r"\b(low|medium|high|critical)[ -]severity\b", re.I)
HASH_RE = re.compile(r"\bhash(?:es)?\b|\bsha-?256\b|\bmd5\b", re.I)


def has_hash_data(facts):
    """True if the facts contain hash enrichment (or if that cannot be determined)."""
    try:
        return bool(json.loads(facts).get("hash_enrichment"))
    except ValueError:
        return True

CHECK_INFO = {
    "hash_without_data": "Text mentions a hash although the alert has none",
    "missing_severity": "Assigned severity word never appears in the text",
    "severity_contradiction": "Text states a different severity than the one assigned",
    "unsupported_attribution": "Nation-state, threat-actor or country claims not in the data",
    "hash_overreach": "A hash/file is credited with causing or being used in the activity, "
                      "or described generically",
    "invented_number": "A number appears that is not in the facts the model was given",
    "containment_language": "Recommends blocking/isolating/disabling "
                            "(the prompt forbids automated containment)",
}


def audit(text, assigned, facts):
    """Return (flags, details). `facts` is the exact JSON text the model was given."""
    if not text:
        return ["empty_response"], {}
    flags, details = [], {}
    if assigned.lower() not in text.lower():
        flags.append("missing_severity")
    wrong = {m.lower() for m in SEV_RE.findall(text)} - {assigned.lower()}
    for m in ADJ_SEV_RE.finditer(text):
        before = text[max(0, m.start() - 30):m.start()].lower()
        if m.group(1).lower() != assigned.lower() and "report" not in before:
            wrong.add(m.group(1).lower())
    if wrong:
        flags.append("severity_contradiction")
        details["severity_contradiction"] = sorted(wrong)
    hits = [m.group(0) for m in ATTRIB_RE.finditer(text)]
    hits += [m.group(0) for m in COUNTRY_RE.finditer(text)
             if m.group(0).lower() not in facts.lower()]
    if hits:
        flags.append("unsupported_attribution")
        details["unsupported_attribution"] = hits
    m = CAUSAL_RE.search(text)
    if m:
        flags.append("hash_overreach")
        details["hash_overreach"] = m.group(0)
    if not has_hash_data(facts) and HASH_RE.search(text):
        flags.append("hash_without_data")
        details["hash_without_data"] = HASH_RE.search(text).group(0)
    allowed = set(NUM_RE.findall(facts))
    invented = [n for n in NUM_RE.findall(LIST_MARK_RE.sub("", text)) if n not in allowed]
    if invented:
        flags.append("invented_number")
        details["invented_number"] = sorted(set(invented))
    contain = CONTAIN_RE.findall(text)
    if contain:
        flags.append("containment_language")
        details["containment_language"] = sorted({c.lower() for c in contain})
    return flags, details


def load_done(path):
    done = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                done[r["alert_id"]] = r
    return done


def pct(a, b):
    return f"{a / b:.0%}" if b else "n/a"


def write_report(recs, model, path):
    n = len(recs)
    empty = [r for r in recs if "empty_response" in r["flags"]]
    valid = [r for r in recs if "empty_response" not in r["flags"]]
    counts = Counter(f for r in valid for f in r["flags"])
    flagged = [r for r in valid if r["flags"]]
    secs = [r["seconds"] for r in valid]
    prompt = recs[0].get("prompt", "") if recs else ""

    L = [f"# LLM Justification Audit: {model}", "",
         f"Run: {datetime.now():%Y-%m-%d %H:%M}",
         f"Alerts audited: {n} ({len(empty)} empty responses)", "",
         "## System prompt used", "", "> " + prompt.replace("\n", " "), ""]
    if secs:
        L += ["## Latency (justification step only)", "",
              f"- Mean: {statistics.mean(secs):.1f}s per alert",
              f"- Median: {statistics.median(secs):.1f}s per alert",
              f"- Slowest: {max(secs):.1f}s",
              f"- Total: {sum(secs) / 60:.1f} min for {len(secs)} alerts", ""]
    L += ["## Automated checks", "",
          "| Check | Flagged | Rate | What it catches |", "|---|---|---|---|"]
    for key, desc in CHECK_INFO.items():
        L.append(f"| {key} | {counts[key]} | {pct(counts[key], len(valid))} | {desc} |")
    L += ["",
          f"- Alerts with at least one flag: {len(flagged)} of {len(valid)} "
          f"({pct(len(flagged), len(valid))})",
          f"- Alerts with no flags: {len(valid) - len(flagged)} "
          f"({pct(len(valid) - len(flagged), len(valid))})", "",
          "## Flagged alerts", ""]
    if flagged:
        for r in flagged[:15]:
            L.append(f"- {r['alert_id']} ({r['scenario']}): {', '.join(r['flags'])} {r['details']}")
        if len(flagged) > 15:
            L.append(f"- ... and {len(flagged) - 15} more (see the .jsonl file)")
    else:
        L.append("- none")
    L += ["", "## Manual review sample", "",
          "Read each justification against its facts and write a verdict: "
          "faithful / minor overreach / fabrication. This calibrates the automated flags.", ""]
    for r in random.Random(7).sample(valid, min(10, len(valid))):
        try:
            facts = json.dumps(json.loads(r["facts"]))
        except ValueError:
            facts = r["facts"]
        L += [f"### {r['alert_id']} ({r['scenario']}, assigned {r['severity']})", "",
              "Facts given to the model:", "", "```", facts, "```", "",
              "Justification:", "", "> " + r["text"].replace("\n", "\n> "), "",
              f"Automated flags: {r['flags'] or 'none'}", "",
              "Verdict: ____", ""]
    L += ["## Caveats", "",
          "- The checks are regex heuristics: they miss subtle fabrication and can flag "
          "legitimate phrasing. Treat the flag rate as a lower bound and use the manual "
          "verdicts for the real overreach rate.",
          "- Results come from one prompt and one seed per alert at temperature 0.2; "
          "rerunning can change individual outcomes.",
          "- Latency depends on this machine, other loads, and whether the model was "
          "already loaded in memory."]
    Path(path).write_text("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Audit LLM justifications against their facts.")
    ap.add_argument("alerts_file")
    ap.add_argument("--model", required=True)
    ap.add_argument("--limit", type=int, help="only audit the first N alerts")
    ap.add_argument("--out-dir", default="docs")
    ap.add_argument("--fresh", action="store_true", help="discard saved results and start over")
    args = ap.parse_args()

    try:
        tags = requests.get(f"{triage.OLLAMA_URL}/api/tags", timeout=10).json()["models"]
        installed = {m["name"] for m in tags}
    except (requests.RequestException, KeyError, ValueError) as e:
        sys.exit(f"Cannot reach Ollama at {triage.OLLAMA_URL}: {e}")
    if args.model not in installed and f"{args.model}:latest" not in installed:
        sys.exit(f"Model {args.model} is not installed. Installed: {', '.join(sorted(installed))}")

    triage.MODEL = args.model
    alerts = json.loads(Path(args.alerts_file).read_text())
    if args.limit:
        alerts = alerts[: args.limit]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = re.sub(r"[^A-Za-z0-9.]+", "_", args.model)
    jsonl, report = out_dir / f"llm_audit_{tag}.jsonl", out_dir / f"llm_audit_{tag}.md"
    if args.fresh and jsonl.exists():
        jsonl.unlink()
    done = load_done(jsonl)

    # Capture the exact prompt and facts the model sees, so the audit cannot drift
    # from what triage.py actually sends.
    captured = {}
    orig_post = triage.requests.post

    def spy(url, **kw):
        msgs = kw["json"]["messages"]
        captured["system"], captured["facts"] = msgs[0]["content"], msgs[1]["content"]
        return orig_post(url, **kw)

    triage.requests.post = spy
    cache = triage.load_cache()
    consecutive_empty = 0
    for i, alert in enumerate(alerts, 1):
        aid = alert["alert_id"]
        if aid in done:
            continue
        res = triage.process_alert(alert, cache)
        captured.clear()
        t0 = time.perf_counter()
        text = triage.llm_justification(res)
        secs = time.perf_counter() - t0
        facts = captured.get("facts", "")
        flags, details = audit(text, res["severity"], facts)
        rec = {"alert_id": aid, "scenario": alert.get("scenario", "unknown"),
               "severity": res["severity"], "text": text or "", "facts": facts,
               "prompt": captured.get("system", ""), "flags": flags,
               "details": details, "seconds": round(secs, 2), "model": args.model}
        with jsonl.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        done[aid] = rec
        print(f"[{i}/{len(alerts)}] {aid} {secs:.1f}s flags={flags or 'none'}")
        consecutive_empty = consecutive_empty + 1 if not text else 0
        if consecutive_empty >= 3:
            print("3 empty responses in a row; stopping. Is Ollama healthy? "
                  "Progress is saved; rerun to resume.")
            break
    triage.requests.post = orig_post

    recs = [done[a["alert_id"]] for a in alerts if a["alert_id"] in done]
    write_report(recs, args.model, report)
    print(f"\nReport: {report}\nPer-alert data: {jsonl}")


if __name__ == "__main__":
    main()
