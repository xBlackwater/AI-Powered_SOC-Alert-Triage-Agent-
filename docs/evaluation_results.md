# Triage Pipeline Evaluation

Run: 2026-10-06 19:03 | Data: skills/cybersecurity/soc-alert-triage/examples/sample_alerts_labeled.json
Alerts: 60 (27 malicious, 33 benign)
Reputation data is live, so these results are a snapshot of the run date.

## Classification (positive class = malicious)

| Method | Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| Pipeline (new scoring) | Medium+ | 27 | 4 | 0 | 29 | 0.87 | 1.00 | 0.93 |
| Pipeline (new scoring) | High+ | 21 | 0 | 6 | 33 | 1.00 | 0.78 | 0.88 |
| Pipeline (old scoring) | Medium+ | 27 | 4 | 0 | 29 | 0.87 | 1.00 | 0.93 |
| Pipeline (old scoring) | High+ | 21 | 0 | 6 | 33 | 1.00 | 0.78 | 0.88 |
| SIEM-reported severity | Medium+ | 24 | 22 | 3 | 11 | 0.52 | 0.89 | 0.66 |
| SIEM-reported severity | High+ | 12 | 8 | 15 | 25 | 0.60 | 0.44 | 0.51 |

## New-scoring severity by scenario

| Scenario | Truth | n | Low | Medium | High | Critical |
|---|---|---|---|---|---|---|
| fp_clean_outbound | benign | 13 | 13 | 0 | 0 | 0 |
| fp_internal_failed_logins | benign | 15 | 15 | 0 | 0 | 0 |
| fp_internal_scanner | benign | 1 | 1 | 0 | 0 | 0 |
| fp_signature_clean_hash | benign | 4 | 0 | 4 | 0 | 0 |
| tp_bad_ip_attack | malicious | 12 | 0 | 0 | 3 | 9 |
| tp_intel_blind_high_risk | malicious | 6 | 0 | 6 | 0 | 0 |
| tp_malware_bad_hash | malicious | 9 | 0 | 0 | 0 | 9 |

## Misclassified at Medium+ (new scoring)

- ALERT-0021 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0022 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0027 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0033 (fp_signature_clean_hash): triaged Medium, truth benign

## Enrichment efficiency

- Naive baseline (look up every IP field and hash): 133
- Skipped as internal/private IPs: 89 (67%)
- Left after skipping: 44
- Actual API calls on a cold cache: 7 (4 IP, 3 hash)
- Saved by de-duplication and caching: 37
- Total reduction vs naive: 95%

## Time-to-triage

- Cold cache: 34.4s total, 0.57s per alert (includes VirusTotal free-tier throttling)
- Warm cache: 0.00s total, 0.000s per alert
- Manual baseline: not provided (rerun with --manual-seconds N)

## Caveats

- Labels describe the scenarios the generator built; the scoring rules were written by the same author, so this measures agreement with those scenarios, not real-world accuracy.
- severity_reported was assigned by the generator, so the SIEM baseline reflects assumptions about SIEM noise, not a measured SIEM.
- Reported severity uses the same thresholds on its own low/medium/high scale.
- LLM justifications are not evaluated in this report.
