# Triage Pipeline Evaluation

Run: 2026-10-25 20:24 | Data: skills/cybersecurity/soc-alert-triage/examples/heldout/seed_505.json
Alerts: 60 (36 malicious, 24 benign)
Reputation data is live, so these results are a snapshot of the run date.

## Classification (positive class = malicious)

| Method | Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| Pipeline (new scoring) | Medium+ | 36 | 6 | 0 | 18 | 0.86 | 1.00 | 0.92 |
| Pipeline (new scoring) | High+ | 31 | 0 | 5 | 24 | 1.00 | 0.86 | 0.93 |
| Pipeline (old scoring) | Medium+ | 36 | 6 | 0 | 18 | 0.86 | 1.00 | 0.92 |
| Pipeline (old scoring) | High+ | 31 | 0 | 5 | 24 | 1.00 | 0.86 | 0.93 |
| SIEM-reported severity | Medium+ | 34 | 22 | 2 | 2 | 0.61 | 0.94 | 0.74 |
| SIEM-reported severity | High+ | 17 | 11 | 19 | 13 | 0.61 | 0.47 | 0.53 |

## New-scoring severity by scenario

| Scenario | Truth | n | Low | Medium | High | Critical |
|---|---|---|---|---|---|---|
| fp_clean_outbound | benign | 6 | 6 | 0 | 0 | 0 |
| fp_internal_failed_logins | benign | 8 | 8 | 0 | 0 | 0 |
| fp_internal_scanner | benign | 4 | 4 | 0 | 0 | 0 |
| fp_signature_clean_hash | benign | 6 | 0 | 6 | 0 | 0 |
| tp_bad_ip_attack | malicious | 19 | 0 | 0 | 5 | 14 |
| tp_intel_blind_high_risk | malicious | 5 | 0 | 5 | 0 | 0 |
| tp_malware_bad_hash | malicious | 12 | 0 | 0 | 0 | 12 |

## Misclassified at Medium+ (new scoring)

- ALERT-0016 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0017 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0018 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0025 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0034 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0051 (fp_signature_clean_hash): triaged Medium, truth benign

## Enrichment efficiency

- Naive baseline (look up every IP field and hash): 138
- Skipped as internal/private IPs: 90 (65%)
- Left after skipping: 48
- Actual API calls on a cold cache: 7 (4 IP, 3 hash)
- Saved by de-duplication and caching: 41
- Total reduction vs naive: 95%

## Time-to-triage

- Cold cache: 33.7s total, 0.56s per alert (includes VirusTotal free-tier throttling)
- Warm cache: 0.00s total, 0.000s per alert
- Manual baseline: not provided (rerun with --manual-seconds N)

## Caveats

- Labels describe the scenarios the generator built; the scoring rules were written by the same author, so this measures agreement with those scenarios, not real-world accuracy.
- severity_reported was assigned by the generator, so the SIEM baseline reflects assumptions about SIEM noise, not a measured SIEM.
- Reported severity uses the same thresholds on its own low/medium/high scale.
- LLM justifications are not evaluated in this report.
