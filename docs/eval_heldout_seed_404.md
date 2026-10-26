# Triage Pipeline Evaluation

Run: 2026-10-25 20:24 | Data: skills/cybersecurity/soc-alert-triage/examples/heldout/seed_404.json
Alerts: 60 (30 malicious, 30 benign)
Reputation data is live, so these results are a snapshot of the run date.

## Classification (positive class = malicious)

| Method | Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| Pipeline (new scoring) | Medium+ | 30 | 4 | 0 | 26 | 0.88 | 1.00 | 0.94 |
| Pipeline (new scoring) | High+ | 22 | 0 | 8 | 30 | 1.00 | 0.73 | 0.85 |
| Pipeline (old scoring) | Medium+ | 30 | 4 | 0 | 26 | 0.88 | 1.00 | 0.94 |
| Pipeline (old scoring) | High+ | 22 | 0 | 8 | 30 | 1.00 | 0.73 | 0.85 |
| SIEM-reported severity | Medium+ | 28 | 27 | 2 | 3 | 0.51 | 0.93 | 0.66 |
| SIEM-reported severity | High+ | 15 | 12 | 15 | 18 | 0.56 | 0.50 | 0.53 |

## New-scoring severity by scenario

| Scenario | Truth | n | Low | Medium | High | Critical |
|---|---|---|---|---|---|---|
| fp_clean_outbound | benign | 12 | 12 | 0 | 0 | 0 |
| fp_internal_failed_logins | benign | 11 | 11 | 0 | 0 | 0 |
| fp_internal_scanner | benign | 3 | 3 | 0 | 0 | 0 |
| fp_signature_clean_hash | benign | 4 | 0 | 4 | 0 | 0 |
| tp_bad_ip_attack | malicious | 14 | 0 | 0 | 6 | 8 |
| tp_intel_blind_high_risk | malicious | 8 | 0 | 8 | 0 | 0 |
| tp_malware_bad_hash | malicious | 8 | 0 | 0 | 0 | 8 |

## Misclassified at Medium+ (new scoring)

- ALERT-0018 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0032 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0047 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0049 (fp_signature_clean_hash): triaged Medium, truth benign

## Enrichment efficiency

- Naive baseline (look up every IP field and hash): 132
- Skipped as internal/private IPs: 86 (65%)
- Left after skipping: 46
- Actual API calls on a cold cache: 7 (4 IP, 3 hash)
- Saved by de-duplication and caching: 39
- Total reduction vs naive: 95%

## Time-to-triage

- Cold cache: 33.9s total, 0.56s per alert (includes VirusTotal free-tier throttling)
- Warm cache: 0.00s total, 0.000s per alert
- Manual baseline: not provided (rerun with --manual-seconds N)

## Caveats

- Labels describe the scenarios the generator built; the scoring rules were written by the same author, so this measures agreement with those scenarios, not real-world accuracy.
- severity_reported was assigned by the generator, so the SIEM baseline reflects assumptions about SIEM noise, not a measured SIEM.
- Reported severity uses the same thresholds on its own low/medium/high scale.
- LLM justifications are not evaluated in this report.
