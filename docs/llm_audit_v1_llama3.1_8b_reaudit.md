# LLM Justification Audit: llama3.1:8b

Run: 2026-10-06 19:22
Alerts audited: 10 (0 empty responses)

## System prompt used

> You are a SOC analyst assistant. Write 2-3 sentences justifying the assigned severity for the alert. Use ONLY the facts provided. Do not mention threat actors, nation-states, or what a country is known for. A file hash listed on an alert was merely observed on that record; do not claim it was used in or caused the alert activity. State the assigned severity exactly as given. End with one recommended next step for a human analyst. Never recommend automated containment.

## Latency (justification step only)

- Mean: 18.8s per alert
- Median: 17.9s per alert
- Slowest: 32.5s
- Total: 3.1 min for 10 alerts

## Automated checks

| Check | Flagged | Rate | What it catches |
|---|---|---|---|
| hash_without_data | 3 | 30% | Text mentions a hash although the alert has none |
| missing_severity | 0 | 0% | Assigned severity word never appears in the text |
| severity_contradiction | 1 | 10% | Text states a different severity than the one assigned |
| unsupported_attribution | 0 | 0% | Nation-state, threat-actor or country claims not in the data |
| hash_overreach | 0 | 0% | A hash/file is credited with causing or being used in the activity, or described generically |
| invented_number | 0 | 0% | A number appears that is not in the facts the model was given |
| containment_language | 0 | 0% | Recommends blocking/isolating/disabling (the prompt forbids automated containment) |

- Alerts with at least one flag: 4 of 10 (40%)
- Alerts with no flags: 6 (60%)

## Flagged alerts

- ALERT-0003 (tp_bad_ip_attack): severity_contradiction {'severity_contradiction': ['high']}
- ALERT-0008 (fp_clean_outbound): hash_without_data {'hash_without_data': 'hash'}
- ALERT-0009 (tp_intel_blind_high_risk): hash_without_data {'hash_without_data': 'hash'}
- ALERT-0010 (fp_clean_outbound): hash_without_data {'hash_without_data': 'hash'}

## Manual review sample

Read each justification against its facts and write a verdict: faithful / minor overreach / fabrication. This calibrates the automated flags.

### ALERT-0006 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0006", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["192.168.1.40"]}
```

Justification:

> The assigned severity of "Low" is justified due to the lack of malicious enrichment hits and the routine nature of the alert type. The IP address 9.9.9.9 has a score of 0, indicating no suspicious activity, and is associated with the US and Quad9 ISP. The whitelisted status of the IP address also supports the low severity rating.
> 
> Recommended next step: Review the network logs to determine the context of the suspicious outbound connection and verify that it is not a false positive.

Automated flags: none

Verdict: ____

### ALERT-0003 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0003", "alert_type": "Known C2 Beacon Pattern", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified because the IP address 185.220.101.45 has a high abuse confidence score of 100%, indicating a potential malicious activity. Additionally, the IP is associated with a Tor-exit traffic ISP, which may be indicative of a malicious communication channel. The high severity is also consistent with the alert type being a "Known C2 Beacon Pattern", which suggests a potential command and control communication.
> 
> Recommended next step: Investigate the internal IP address 10.0.0.31 to determine if it is involved in the potential malicious activity.

Automated flags: ['severity_contradiction']

Verdict: ____

### ALERT-0007 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0007", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {}, "hash_enrichment": {}, "internal_ips_not_enriched": ["192.168.1.15", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Low" is justified due to the lack of malicious enrichment hits and the routine nature of the alert type. The alert is a result of failed login attempts, which is a common occurrence in a network. The absence of any malicious indicators suggests that the activity is likely benign.
> 
> Recommended next step: Review the login attempt logs to identify the source of the failed attempts and verify that the affected internal IPs are legitimate users.

Automated flags: none

Verdict: ____

### ALERT-0010 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0010", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified due to the absence of malicious enrichment hits and the routine nature of the alert type. The IP address 9.9.9.9 has a score of 0, indicating no suspicious activity, and is associated with the US, Quad9 ISP, and has a high number of reports. The file hash enrichment is empty, indicating no known malicious activity associated with the observed hash.
> 
> Recommended next step: Investigate the internal IP address 10.0.0.22 to determine if it is a legitimate system or a potential source of the suspicious outbound connection.

Automated flags: ['hash_without_data']

Verdict: ____

### ALERT-0001 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0001", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.22", "192.168.1.15"]}
```

Justification:

> The assigned severity of "Low" is justified due to the lack of malicious enrichment hits and the routine nature of the alert type, which suggests a common and non-critical security event. The absence of any notable indicators of compromise or suspicious activity also supports this severity level. The assigned severity aligns with the reported severity of "low".
> 
> Recommended next step: Investigate the internal IP addresses 10.0.0.22 and 192.168.1.15 to determine the source of the failed login attempts and ensure they are not indicative of a larger security issue.

Automated flags: none

Verdict: ____

### ALERT-0008 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0008", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"8.8.8.8": {"score": 0, "country": "US", "isp": "Google LLC", "reports": 224, "whitelisted": true}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is a routine type with no malicious enrichment hits, and the IP address 8.8.8.8 is whitelisted. The IP address is also located in the US and is associated with Google LLC, a reputable internet service provider. The file hash enrichment is empty, indicating no known malicious activity associated with the hash.
> 
> Recommended next step: Review the internal IP address 10.0.0.22 to determine if it is a legitimate system or a potential source of the suspicious outbound connection.

Automated flags: ['hash_without_data']

Verdict: ____

### ALERT-0005 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0005", "alert_type": "Brute Force Attack", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%", "internal host is communicating outbound with a flagged IP (possible compromised host)"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Critical" is justified due to the high confidence level of the IP address (185.220.101.45) being used for malicious activity, as indicated by its 100% abuse confidence score. Additionally, the internal host is communicating with a flagged IP, suggesting a possible compromise. This combination of indicators warrants a critical severity level.
> 
> Recommended next step: Investigate the internal host (10.0.0.22) to determine the extent of the potential compromise and assess the risk to the organization's assets.

Automated flags: none

Verdict: ____

### ALERT-0002 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0002", "alert_type": "Suspicious Outbound Connection", "reported_severity": "high", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is a routine type and there are no malicious enrichment hits. Additionally, the IP address 9.9.9.9 has a low score and is whitelisted, indicating it is likely a legitimate connection. The reported severity of "high" is not supported by the available data.
> 
> Recommended next step: Review the network activity associated with the internal IP address 10.0.0.22 to determine the context of the suspicious outbound connection.

Automated flags: none

Verdict: ____

### ALERT-0004 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0004", "alert_type": "Failed Login Attempts", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.22", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert is a routine type, indicating a common occurrence, and there are no malicious enrichment hits associated with the alert. The lack of malicious activity suggests that the alert is likely a false positive or a minor issue. The reported severity of "medium" is lower than the assigned severity, indicating that the system has downgraded the severity based on additional information. 
> 
> Recommended next step: Review the internal IPs listed (10.0.0.22 and 10.0.0.31) to determine if they are legitimate or if there are any other issues associated with them.

Automated flags: none

Verdict: ____

### ALERT-0009 (tp_intel_blind_high_risk, assigned Medium)

Facts given to the model:

```
{"alert_id": "ALERT-0009", "alert_type": "Known C2 Beacon Pattern", "reported_severity": "medium", "assigned_severity": "Medium", "rule_findings": ["alert type 'Known C2 Beacon Pattern' is inherently higher-risk"], "ip_enrichment": {"1.1.1.1": {"score": 0, "country": "AU", "isp": "APNIC and Cloudflare DNS Resolver project", "reports": 92, "whitelisted": true}}, "hash_enrichment": {}, "internal_ips_not_enriched": ["10.0.0.31"]}
```

Justification:

> The assigned severity of "Medium" is justified because the alert type "Known C2 Beacon Pattern" is inherently higher-risk, as indicated by the rule findings. The IP address 1.1.1.1 is whitelisted, which suggests that it is a legitimate IP address and may not be directly related to the alert activity. The file hash enrichment is empty, indicating that no malicious file hashes were detected.
> 
> Recommended next step: Investigate the internal IP address 10.0.0.31 to determine if it is involved in the alert activity.

Automated flags: ['hash_without_data']

Verdict: ____

## Caveats

- The checks are regex heuristics: they miss subtle fabrication and can flag legitimate phrasing. Treat the flag rate as a lower bound and use the manual verdicts for the real overreach rate.
- Results come from one prompt and one seed per alert at temperature 0.2; rerunning can change individual outcomes.
- Latency depends on this machine, other loads, and whether the model was already loaded in memory.
