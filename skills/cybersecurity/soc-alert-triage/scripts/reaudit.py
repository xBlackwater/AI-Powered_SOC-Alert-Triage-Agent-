#!/usr/bin/env python3
"""reaudit.py - re-run the CURRENT automated checks on saved audit results, offline.
Usage: python3 reaudit.py docs/llm_audit_v1_llama3.1_8b.jsonl
Writes <name>_reaudit.md next to the input; the .jsonl is not modified."""
import json
import sys
from pathlib import Path

import audit_justifications as aj

if len(sys.argv) != 2:
    sys.exit(__doc__)
src = Path(sys.argv[1])
recs = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]
for r in recs:
    r["flags"], r["details"] = aj.audit(r["text"], r["severity"], r["facts"])
out = src.with_name(src.stem + "_reaudit.md")
aj.write_report(recs, recs[0]["model"], out)
flagged = [r for r in recs if r["flags"]]
print(f"{len(flagged)} of {len(recs)} alerts flagged -> {out}")
for r in flagged:
    print(f"  {r['alert_id']}: {r['flags']}")
