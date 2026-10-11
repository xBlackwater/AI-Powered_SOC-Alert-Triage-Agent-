# LLM Justification Audit: llama3.1:8b

Run: 2026-10-10 19:44
Alerts audited: 60 (0 empty responses)

## System prompt used

> You are a SOC analyst assistant. Write 2-3 sentences justifying the assigned severity for the alert. Use ONLY the facts provided. Do not mention threat actors, nation-states, or what a country is known for. A file hash listed on an alert was merely observed on that record; do not claim it was used in or caused the alert activity. State the assigned severity exactly as given. End with one recommended next step for a human analyst. Never recommend automated containment. Only discuss evidence that appears in the facts. If a category such as file hashes is absent, do not mention it and do not treat missing data as a clean result. Do not call a number high or low unless the facts say so.

## Latency (justification step only)

- Mean: 17.1s per alert
- Median: 15.3s per alert
- Slowest: 57.6s
- Total: 17.1 min for 60 alerts

## Automated checks

| Check | Flagged | Rate | What it catches |
|---|---|---|---|
| hash_without_data | 0 | 0% | Text mentions a hash although the alert has none |
| missing_severity | 0 | 0% | Assigned severity word never appears in the text |
| severity_contradiction | 3 | 5% | Text states a different severity than the one assigned |
| unsupported_attribution | 0 | 0% | Nation-state, threat-actor or country claims not in the data |
| hash_overreach | 4 | 7% | A hash/file is credited with causing or being used in the activity, or described generically |
| invented_number | 1 | 2% | A number appears that is not in the facts the model was given |
| containment_language | 0 | 0% | Recommends blocking/isolating/disabling (the prompt forbids automated containment) |

- Alerts with at least one flag: 7 of 60 (12%)
- Alerts with no flags: 53 (88%)

## Flagged alerts

- ALERT-0004 (fp_internal_failed_logins): severity_contradiction {'severity_contradiction': ['high']}
- ALERT-0007 (fp_internal_failed_logins): severity_contradiction {'severity_contradiction': ['high']}
- ALERT-0035 (tp_malware_bad_hash): hash_overreach {'hash_overreach': 'hash is associated with a PowerShell type, which is often used in'}
- ALERT-0040 (tp_malware_bad_hash): hash_overreach {'hash_overreach': 'hash is associated with a PowerShell type, which is often used for'}
- ALERT-0045 (tp_malware_bad_hash): hash_overreach {'hash_overreach': 'malware is identified as a Powershell script, which is often used for'}
- ALERT-0051 (tp_malware_bad_hash): hash_overreach {'hash_overreach': 'file type is identified as "Powershell", which is often used for'}
- ALERT-0060 (tp_malware_bad_hash): severity_contradiction, invented_number {'severity_contradiction': ['high'], 'invented_number': ['9']}

## Manual review sample

Read each justification against its facts and write a verdict: faithful / minor overreach / fabrication. This calibrates the automated flags.

### ALERT-0021 (fp_signature_clean_hash, assigned Medium)

Facts given to the model:

```
{"alert_id": "ALERT-0021", "alert_type": "Malware Signature Match", "reported_severity": "high", "assigned_severity": "Medium", "rule_findings": ["alert type 'Malware Signature Match' is inherently higher-risk"], "hash_enrichment": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"malicious": 0, "suspicious": 0, "total": 75, "type": "unknown"}}, "internal_ips_not_enriched": ["192.168.1.15", "192.168.1.40"]}
```

Justification:

> The assigned severity of "Medium" is justified because the alert is a Malware Signature Match, which is inherently higher-risk, but the hash enrichment data shows that the file hash in question has only been observed 75 times, with no clear indication of malicious or suspicious activity. This suggests that the alert may not be a high-priority issue. 
> 
> Recommended next step: Review the network traffic and system logs associated with the internal IP addresses 192.168.1.15 and 192.168.1.40 to gather more context about the potential malware activity.

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

### ALERT-0026 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0026", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%", "internal host is communicating outbound with a flagged IP (possible compromised host)"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "internal_ips_not_enriched": ["10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified because the internal host is communicating outbound with a flagged IP, indicating a possible compromise. The IP 185.220.101.45 has a high abuse confidence score of 100%, suggesting a high likelihood of malicious activity. The internal host's communication with this IP is a significant concern.
> 
> Recommended next step: Investigate the internal host 10.0.0.31 to determine its status and potential involvement in the suspicious communication.

Automated flags: none

Verdict: ____

### ALERT-0042 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0042", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert type is routine and there are no malicious enrichment hits. The presence of a single internal IP address (10.0.0.22) without any further context or evidence of malicious activity also supports this severity. 
> 
> Recommended next step: Investigate the internal IP address 10.0.0.22 to determine the cause of the failed login attempts.

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

Automated flags: ['severity_contradiction']

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

### ALERT-0053 (fp_internal_scanner, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0053", "alert_type": "Port Scan Detected", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.31", "192.168.1.40"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert type is routine and there are no malicious enrichment hits. The presence of a port scan detection is not indicative of a high-severity threat. The reported severity of "medium" is lower than the assigned severity.
> 
> Recommended next step: Investigate the internal IP addresses 10.0.0.31 and 192.168.1.40 to determine if they are legitimate or if there are any other relevant findings associated with these IP addresses.

Automated flags: none

Verdict: ____

### ALERT-0035 (tp_malware_bad_hash, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0035", "alert_type": "Malware Signature Match", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["hash 44d88612fea8... flagged malicious by 66/75 vendors"], "hash_enrichment": {"44d88612fea8a8f36de82e1278abb02f": {"malicious": 66, "suspicious": 0, "total": 75, "type": "Powershell"}}, "internal_ips_not_enriched": ["192.168.1.40", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified because the file hash 44d88612fea8... was flagged as malicious by 66 out of 75 vendors, indicating a high likelihood of malicious activity. Additionally, the hash is associated with a PowerShell type, which is often used in malware. The severity is also consistent with the reported severity of "high".
> 
> Next step for a human analyst: Investigate the internal IPs 192.168.1.40 and 10.0.0.31 to determine if they are related to the malicious activity.

Automated flags: ['hash_overreach']

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

Automated flags: ['severity_contradiction']

Verdict: ____

### ALERT-0024 (tp_malware_bad_hash, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0024", "alert_type": "Malware Signature Match", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["hash 44d88612fea8... flagged malicious by 66/75 vendors"], "hash_enrichment": {"44d88612fea8a8f36de82e1278abb02f": {"malicious": 66, "suspicious": 0, "total": 75, "type": "Powershell"}}, "internal_ips_not_enriched": ["192.168.1.40", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified because the file hash 44d88612fea8... was flagged as malicious by 66 out of 75 vendors, indicating a high likelihood of malicious activity. The fact that 66 vendors flagged the hash as malicious, rather than just a few, suggests a more significant threat. The assigned severity is also consistent with the alert type being a "Malware Signature Match".
> 
> Recommended next step: Investigate the internal IP addresses 192.168.1.40 and 10.0.0.31 to determine if they are associated with the malicious activity.

Automated flags: none

Verdict: ____

## Caveats

- The checks are regex heuristics: they miss subtle fabrication and can flag legitimate phrasing. Treat the flag rate as a lower bound and use the manual verdicts for the real overreach rate.
- Results come from one prompt and one seed per alert at temperature 0.2; rerunning can change individual outcomes.
- Latency depends on this machine, other loads, and whether the model was already loaded in memory.
