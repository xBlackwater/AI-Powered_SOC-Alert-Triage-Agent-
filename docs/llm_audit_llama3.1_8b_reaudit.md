# LLM Justification Audit: llama3.1:8b

Run: 2026-10-06 19:41
Alerts audited: 10 (0 empty responses)

## System prompt used

> You are a SOC analyst assistant. Write 2-3 sentences justifying the assigned severity for the alert. Use ONLY the facts provided. Do not mention threat actors, nation-states, or what a country is known for. A file hash listed on an alert was merely observed on that record; do not claim it was used in or caused the alert activity. State the assigned severity exactly as given. End with one recommended next step for a human analyst. Never recommend automated containment. Only discuss evidence that appears in the facts. If a category such as file hashes is absent, do not mention it and do not treat missing data as a clean result. Do not call a number high or low unless the facts say so.

## Latency (justification step only)

- Mean: 16.9s per alert
- Median: 15.3s per alert
- Slowest: 30.6s
- Total: 2.8 min for 10 alerts

## Automated checks

| Check | Flagged | Rate | What it catches |
|---|---|---|---|
| hash_without_data | 0 | 0% | Text mentions a hash although the alert has none |
| missing_severity | 0 | 0% | Assigned severity word never appears in the text |
| severity_contradiction | 0 | 0% | Text states a different severity than the one assigned |
| unsupported_attribution | 0 | 0% | Nation-state, threat-actor or country claims not in the data |
| hash_overreach | 0 | 0% | A hash/file is credited with causing or being used in the activity, or described generically |
| invented_number | 0 | 0% | A number appears that is not in the facts the model was given |
| containment_language | 0 | 0% | Recommends blocking/isolating/disabling (the prompt forbids automated containment) |

- Alerts with at least one flag: 0 of 10 (0%)
- Alerts with no flags: 10 (100%)

## Flagged alerts

- none

## Manual review sample

Read each justification against its facts and write a verdict: faithful / minor overreach / fabrication. This calibrates the automated flags.

### ALERT-0006 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0006", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "internal_ips_not_enriched": ["192.168.1.40"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is a routine type and there are no malicious enrichment hits. Additionally, the IP address 9.9.9.9 has a score of 0, indicating no suspicious activity, and is whitelisted. The reported severity is "medium", but the assigned severity is lower due to the lack of malicious indicators.
> 
> Recommended next step: Investigate the internal IP address 192.168.1.40 to determine if it is a legitimate source of the suspicious outbound connection.

Automated flags: none

Verdict: ____

### ALERT-0003 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0003", "alert_type": "Known C2 Beacon Pattern", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "internal_ips_not_enriched": ["10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified due to the high confidence level of the IP address 185.220.101.45, as indicated by the abuse confidence score of 100%. Additionally, the IP address is associated with a country code "DE" and has been reported 219 times. 
> 
> Recommended next step: Investigate the internal IP address 10.0.0.31 to determine if it is connected to the suspicious activity.

Automated flags: none

Verdict: ____

### ALERT-0007 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0007", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["192.168.1.15", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is a routine type and there are no malicious enrichment hits. The alert type is also not indicative of a high-severity issue. The presence of internal IPs that were not enriched does not contribute to a higher severity.
> 
> Recommended next step: Review the login attempts to determine if they were legitimate user errors or potential misconfigurations.

Automated flags: none

Verdict: ____

### ALERT-0010 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0010", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is a routine type and there are no malicious enrichment hits. Additionally, the IP address 9.9.9.9, which is associated with the alert, has a score of 0 and is whitelisted. 
> 
> Recommended next step: Investigate the internal IP address 10.0.0.22 to determine if it is the source of the suspicious outbound connection.

Automated flags: none

Verdict: ____

### ALERT-0001 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0001", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.22", "192.168.1.15"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is of a routine type and there are no malicious enrichment hits. The presence of failed login attempts is not uncommon and does not indicate a high-level threat. The assigned severity is consistent with the reported severity of "low".
> 
> Recommended next step: Review the login attempt logs to determine if the failed attempts are due to a legitimate user issue or a potential misconfiguration.

Automated flags: none

Verdict: ____

### ALERT-0008 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0008", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"8.8.8.8": {"score": 0, "country": "US", "isp": "Google LLC", "reports": 224, "whitelisted": true}}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert type is routine and there are no malicious enrichment hits. Additionally, the IP address 8.8.8.8, which is associated with the alert, has a score of 0 and is whitelisted. 
> 
> Recommended next step: Investigate the internal IP address 10.0.0.22 to determine its role in the suspicious outbound connection.

Automated flags: none

Verdict: ____

### ALERT-0005 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0005", "alert_type": "Brute Force Attack", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%", "internal host is communicating outbound with a flagged IP (possible compromised host)"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Critical" is justified because the alert indicates a high level of confidence in the abuse of the IP address 185.220.101.45, and an internal host is communicating with this IP, suggesting a potential compromise. The IP address is flagged as possibly compromised, and the abuse confidence is 100%. The severity is also elevated due to the internal host's outbound communication with a flagged IP. 
> 
> Recommended next step: Investigate the internal host 10.0.0.22 to determine if it is indeed compromised and what potential impact this may have on the network.

Automated flags: none

Verdict: ____

### ALERT-0002 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0002", "alert_type": "Suspicious Outbound Connection", "reported_severity": "high", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is of a routine type and there are no malicious enrichment hits. Additionally, the IP address 9.9.9.9, which is associated with the alert, has a score of 0 and is whitelisted. 
> 
> Recommended next step: Investigate the internal IP address 10.0.0.22 to gather more information about the activity that triggered the alert.

Automated flags: none

Verdict: ____

### ALERT-0004 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0004", "alert_type": "Failed Login Attempts", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.22", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert type is routine and there are no malicious enrichment hits. The alert type is also not indicative of a high-severity issue, such as a data breach or system compromise. The reported severity of "medium" is lower than the assigned severity, suggesting that the system has downgraded the severity based on additional information.
> 
> Recommended next step: Review the login attempts made from internal IPs 10.0.0.22 and 10.0.0.31 to determine if they are legitimate or unauthorized.

Automated flags: none

Verdict: ____

### ALERT-0009 (tp_intel_blind_high_risk, assigned Medium)

Facts given to the model:

```
{"alert_id": "ALERT-0009", "alert_type": "Known C2 Beacon Pattern", "reported_severity": "medium", "assigned_severity": "Medium", "rule_findings": ["alert type 'Known C2 Beacon Pattern' is inherently higher-risk"], "ip_enrichment": {"1.1.1.1": {"score": 0, "country": "AU", "isp": "APNIC and Cloudflare DNS Resolver project", "reports": 92, "whitelisted": true}}, "internal_ips_not_enriched": ["10.0.0.31"]}
```

Justification:

> The assigned severity of "Medium" is justified because the alert type "Known C2 Beacon Pattern" is inherently higher-risk, as indicated by the rule findings. Additionally, the IP address 1.1.1.1 has a high number of reports (92) and is located in a country (AU) with no additional context provided. 
> 
> Recommended next step: Investigate the internal IP address 10.0.0.31 to determine its involvement in the alert activity.

Automated flags: none

Verdict: ____

## Caveats

- The checks are regex heuristics: they miss subtle fabrication and can flag legitimate phrasing. Treat the flag rate as a lower bound and use the manual verdicts for the real overreach rate.
- Results come from one prompt and one seed per alert at temperature 0.2; rerunning can change individual outcomes.
- Latency depends on this machine, other loads, and whether the model was already loaded in memory.
