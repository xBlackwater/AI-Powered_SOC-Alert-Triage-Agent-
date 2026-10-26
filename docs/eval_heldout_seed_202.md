# Triage Pipeline Evaluation

Run: 2026-10-25 20:23 | Data: skills/cybersecurity/soc-alert-triage/examples/heldout/seed_202.json
Alerts: 60 (33 malicious, 27 benign)
Reputation data is live, so these results are a snapshot of the run date.

## Classification (positive class = malicious)

| Method | Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| Pipeline (new scoring) | Medium+ | 33 | 7 | 0 | 20 | 0.82 | 1.00 | 0.90 |
| Pipeline (new scoring) | High+ | 29 | 0 | 4 | 27 | 1.00 | 0.88 | 0.94 |
| Pipeline (old scoring) | Medium+ | 33 | 7 | 0 | 20 | 0.82 | 1.00 | 0.90 |
| Pipeline (old scoring) | High+ | 29 | 0 | 4 | 27 | 1.00 | 0.88 | 0.94 |
| SIEM-reported severity | Medium+ | 32 | 22 | 1 | 5 | 0.59 | 0.97 | 0.74 |
| SIEM-reported severity | High+ | 12 | 14 | 21 | 13 | 0.46 | 0.36 | 0.41 |

## New-scoring severity by scenario

| Scenario | Truth | n | Low | Medium | High | Critical |
|---|---|---|---|---|---|---|
| fp_clean_outbound | benign | 9 | 9 | 0 | 0 | 0 |
| fp_internal_failed_logins | benign | 8 | 8 | 0 | 0 | 0 |
| fp_internal_scanner | benign | 3 | 3 | 0 | 0 | 0 |
| fp_signature_clean_hash | benign | 7 | 0 | 7 | 0 | 0 |
| tp_bad_ip_attack | malicious | 20 | 0 | 0 | 4 | 16 |
| tp_intel_blind_high_risk | malicious | 4 | 0 | 4 | 0 | 0 |
| tp_malware_bad_hash | malicious | 9 | 0 | 0 | 0 | 9 |

## Misclassified at Medium+ (new scoring)

- ALERT-0003 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0006 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0027 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0045 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0051 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0054 (fp_signature_clean_hash): triaged Medium, truth benign
- ALERT-0060 (fp_signature_clean_hash): triaged Medium, truth benign

## Enrichment efficiency

- Naive baseline (look up every IP field and hash): 136
- Skipped as internal/private IPs: 87 (64%)
- Left after skipping: 49
- Actual API calls on a cold cache: 7 (4 IP, 3 hash)
- Saved by de-duplication and caching: 42
- Total reduction vs naive: 95%

## Time-to-triage

- Cold cache: 33.2s total, 0.55s per alert (includes VirusTotal free-tier throttling)
- Warm cache: 0.00s total, 0.000s per alert
- Manual baseline: not provided (rerun with --manual-seconds N)

## Caveats

- Labels describe the scenarios the generator built; the scoring rules were written by the same author, so this measures agreement with those scenarios, not real-world accuracy.
- severity_reported was assigned by the generator, so the SIEM baseline reflects assumptions about SIEM noise, not a measured SIEM.
- Reported severity uses the same thresholds on its own low/medium/high scale.
- LLM justifications are not evaluated in this report.
