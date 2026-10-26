# Held-out Evaluation (October 25, 2026)

Five new labeled batches (60 alerts each, seeds 101, 202, 303, 404, 505) were generated after the scoring rules were finalized on seed 42. They use the same generator, scenario types, and IP/hash pools as the original data, so this checks for overfitting to specific alerts, not real-world accuracy. No lookups failed.

## New scoring, per seed
| Seed | Medium+ precision | Medium+ recall | Medium+ F1 | High+ precision | High+ recall | High+ F1 |
|---|---|---|---|---|---|---|
| 42 (original) | 0.87 | 1.00 | 0.93 | 1.00 | 0.78 | 0.88 |
| 101 | 0.68 | 1.00 | 0.81 | 1.00 | 0.83 | 0.90 |
| 202 | 0.82 | 1.00 | 0.90 | 1.00 | 0.88 | 0.94 |
| 303 | 0.82 | 1.00 | 0.90 | 1.00 | 0.64 | 0.78 |
| 404 | 0.88 | 1.00 | 0.94 | 1.00 | 0.73 | 0.85 |
| 505 | 0.86 | 1.00 | 0.92 | 1.00 | 0.86 | 0.93 |
| Pooled, 5 held-out seeds (300 alerts) | 0.82 | 1.00 | 0.90 | 1.00 | 0.79 | 0.88 |

Pooled counts: Medium+ TP 155, FP 35, FN 0, TN 110. High+ TP 122, FP 0, FN 33, TN 145.

## Findings
- On every held-out batch, no malicious alert scored below Medium (Medium+ recall 1.00) and no benign alert reached High (High+ precision 1.00).
- Every error therefore sits in the Medium tier: benign alerts sent for review, and attacks that were not auto-escalated. A policy of auto-escalating High and Critical, reviewing Medium, and deprioritizing Low produced no false escalations and no attacks scored Low on these 300 alerts.
- The number of errors in the Medium tier varies with each batch's scenario mix: Medium+ precision ranged from 0.68 to 0.88, and High+ recall from 0.64 to 0.88.
- Seed 42's results fall inside these ranges, so they were not unusually favorable.
