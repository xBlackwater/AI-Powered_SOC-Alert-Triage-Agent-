# Triage Pipeline Evaluation

Run: 2026-10-25 20:22 | Data: skills/cybersecurity/soc-alert-triage/examples/heldout/seed_101.json
Alerts: 60 (23 malicious, 37 benign)
Reputation data is live, so these results are a snapshot of the run date.

## Classification (positive class = malicious)

| Method | Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| Pipeline (new scoring) | Medium+ | 23 | 11 | 0 | 26 | 0.68 | 1.00 | 0.81 |
| Pipeline (new scoring) | High+ | 19 | 0 | 4 | 37 | 1.00 | 0.83 | 0.90 |
| Pipeline (old scoring) | Medium+ | 23 | 11 | 0 | 26 | 0.68 | 1.00 | 0.81 |
| Pipeline (old scoring) | High+ | 19 | 0 | 4 | 37 | 1.00 | 0.83 | 0.90 |
| SIEM-reported severity | Medium+ | 21 | 28 | 2 | 9 | 0.43 | 0.91 | 0.58 |
| SIEM-reported severity | High+ | 12 | 15 | 11 | 22 | 0.44 | 0.52 | 0.48 |

## New-scoring severity by scenario

| Scenario | Truth | n | Low | Medium | High | Critical |
|---|---|---|---|---|---|---|
| fp_clean_outbound | benign | 10 | 10 | 0 | 0 | 0 |
| fp_internal_failed_logins | benign | 15 | 15 | 0 | 0 | 0 |
| fp_internal_scanner | benign | 1 | 1 | 0 | 0 | 0 |
| fp_signature_clean_hash | benign | 11 | 0 | 11 | 0 | 0 |
| tp_bad_ip_attack | malicious | 13 | 0 | 0 | 3 | 10 |
| tp_intel_blind_high_risk | malicious | 4 | 0 | 4 | 0 | 0 |
| tp_malware_bad_hash | malicious | 6 | 0 | 0 | 0 | 6 |

## Misclassified at Medium+ (new scoring)

- ALERT-0010 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0012 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0013 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0022 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0024 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0027 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0032 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0033 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0043 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0046 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0052 (fp_signature_clean_hash): triaged Medium, truth benign

## Enrichment efficiency

- Naive baseline (look up every IP field and hash): 137
- Skipped as internal/private IPs: 93 (68%)
- Left after skipping: 44
- Actual API calls on a cold cache: 7 (4 IP, 3 hash)
- Saved by de-duplication and caching: 37
- Total reduction vs naive: 95%

## Time-to-triage

- Cold cache: 34.1s total, 0.57s per alert (includes VirusTotal free-tier throttling)
- Warm cache: 0.00s total, 0.000s per alert
- Manual baseline: not provided (rerun with --manual-seconds N)

## Caveats

- Labels describe the scenarios the generator built; the scoring rules were written by the same author, so this measures agreement with those scenarios, not real-world accuracy.
- severity_reported was assigned by the generator, so the SIEM baseline reflects assumptions about SIEM noise, not a measured SIEM.
- Reported severity uses the same thresholds on its own low/medium/high scale.
- LLM justifications are not evaluated in this report.
