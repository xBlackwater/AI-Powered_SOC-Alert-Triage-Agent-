# LLM Justification Audit: qwen2.5:7b

Run: 2026-10-10 20:06
Alerts audited: 60 (0 empty responses)

## System prompt used

> You are a SOC analyst assistant. Write 2-3 sentences justifying the assigned severity for the alert. Use ONLY the facts provided. Do not mention threat actors, nation-states, or what a country is known for. A file hash listed on an alert was merely observed on that record; do not claim it was used in or caused the alert activity. State the assigned severity exactly as given. End with one recommended next step for a human analyst. Never recommend automated containment. Only discuss evidence that appears in the facts. If a category such as file hashes is absent, do not mention it and do not treat missing data as a clean result. Do not call a number high or low unless the facts say so.

## Latency (justification step only)

- Mean: 12.4s per alert
- Median: 12.1s per alert
- Slowest: 27.3s
- Total: 12.4 min for 60 alerts

## Automated checks

| Check | Flagged | Rate | What it catches |
|---|---|---|---|
| hash_without_data | 1 | 2% | Text mentions a hash although the alert has none |
| missing_severity | 2 | 3% | Assigned severity word never appears in the text |
| severity_contradiction | 0 | 0% | Text states a different severity than the one assigned |
| unsupported_attribution | 1 | 2% | Nation-state, threat-actor or country claims not in the data |
| hash_overreach | 4 | 7% | A hash/file is credited with causing or being used in the activity, or described generically |
| invented_number | 0 | 0% | A number appears that is not in the facts the model was given |
| containment_language | 5 | 8% | Recommends blocking/isolating/disabling (the prompt forbids automated containment) |

- Alerts with at least one flag: 11 of 60 (18%)
- Alerts with no flags: 49 (82%)

## Flagged alerts

- ALERT-0003 (tp_bad_ip_attack): unsupported_attribution {'unsupported_attribution': ['threat actors']}
- ALERT-0009 (tp_intel_blind_high_risk): missing_severity {}
- ALERT-0013 (tp_bad_ip_attack): containment_language {'containment_language': ['isolate']}
- ALERT-0029 (tp_bad_ip_attack): containment_language {'containment_language': ['isolate']}
- ALERT-0032 (tp_intel_blind_high_risk): missing_severity {}
- ALERT-0035 (tp_malware_bad_hash): hash_overreach {'hash_overreach': 'malware has spread or is actively being used'}
- ALERT-0040 (tp_malware_bad_hash): hash_overreach, containment_language {'hash_overreach': 'file type is PowerShell, which is commonly used in', 'containment_language': ['isolate']}
- ALERT-0043 (tp_bad_ip_attack): containment_language {'containment_language': ['isolate']}
- ALERT-0053 (fp_internal_scanner): hash_without_data {'hash_without_data': 'hashes'}
- ALERT-0058 (tp_malware_bad_hash): hash_overreach {'hash_overreach': 'PowerShell script, which can be executed with elevated privileges and is commonly used for'}
- ALERT-0060 (tp_malware_bad_hash): hash_overreach, containment_language {'hash_overreach': 'file type is PowerShell, which is commonly used in', 'containment_language': ['isolate']}

## Manual review sample

Read each justification against its facts and write a verdict: faithful / minor overreach / fabrication. This calibrates the automated flags.

### ALERT-0021 (fp_signature_clean_hash, assigned Medium)

Facts given to the model:

```
{"alert_id": "ALERT-0021", "alert_type": "Malware Signature Match", "reported_severity": "high", "assigned_severity": "Medium", "rule_findings": ["alert type 'Malware Signature Match' is inherently higher-risk"], "hash_enrichment": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"malicious": 0, "suspicious": 0, "total": 75, "type": "unknown"}}, "internal_ips_not_enriched": ["192.168.1.15", "192.168.1.40"]}
```

Justification:

> The assigned severity of "Medium" is justified by the fact that while the alert type "Malware Signature Match" is inherently higher-risk, the specific file hash in question has no known malicious or suspicious associations, and the internal IPs involved do not provide additional context to elevate the severity. The next step recommended is to investigate the network activities associated with these internal IPs to gather more context.

Automated flags: none

Verdict: ____

### ALERT-0010 (fp_clean_outbound, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0010", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "ip_enrichment": {"9.9.9.9": {"score": 0, "country": "US", "isp": "Quad9", "reports": 45, "whitelisted": true}}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Low" is justified by the lack of malicious enrichment hits and the routine nature of the alert type, coupled with the whitelisted status of the IP address involved. The IP is associated with a known, reputable ISP and has no reported malicious activity, further supporting this classification. The next step recommended is to review the internal IP address for any recent changes or activities that might warrant further investigation.

Automated flags: none

Verdict: ____

### ALERT-0026 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0026", "alert_type": "Suspicious Outbound Connection", "reported_severity": "medium", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%", "internal host is communicating outbound with a flagged IP (possible compromised host)"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "internal_ips_not_enriched": ["10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified by the high abuse confidence score of 100% for the external IP address 185.220.101.45, indicating a strong likelihood of malicious activity. Additionally, the internal host is communicating with a flagged IP address, which suggests potential compromise. Immediate investigation and isolation of the internal host are recommended.

Automated flags: none

Verdict: ____

### ALERT-0042 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0042", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The alert indicates no malicious enrichment hits and is categorized as a routine failed login attempt, which aligns with the assigned severity of Low. The absence of any suspicious activity or enrichment hits supports this classification. The next step is to monitor the internal IP address 10.0.0.22 for any subsequent unusual activity.

Automated flags: none

Verdict: ____

### ALERT-0004 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0004", "alert_type": "Failed Login Attempts", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.22", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Low" is justified by the lack of malicious enrichment hits and the fact that this is a routine alert type. The internal IPs involved are not enriched, suggesting no suspicious activity from these sources. The next step is to monitor these IPs for any unusual activity.

Automated flags: none

Verdict: ____

### ALERT-0005 (tp_bad_ip_attack, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0005", "alert_type": "Brute Force Attack", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["IP 185.220.101.45 has abuse confidence 100%", "internal host is communicating outbound with a flagged IP (possible compromised host)"], "ip_enrichment": {"185.220.101.45": {"score": 100, "country": "DE", "isp": "Network for Tor-Exit traffic.", "reports": 219, "whitelisted": false}}, "internal_ips_not_enriched": ["10.0.0.22"]}
```

Justification:

> The assigned severity of "Critical" is justified by the high abuse confidence score of 100% for the IP address 185.220.101.45, indicating a strong likelihood of malicious activity. Additionally, the internal host is communicating with this flagged IP, suggesting a possible compromise. Immediate investigation and isolation of the internal host are recommended.

Automated flags: none

Verdict: ____

### ALERT-0053 (fp_internal_scanner, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0053", "alert_type": "Port Scan Detected", "reported_severity": "medium", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["10.0.0.31", "192.168.1.40"]}
```

Justification:

> The assigned severity of "Low" is justified because the alert type is routine and there are no malicious enrichment hits associated with the file hashes observed. The lack of additional enrichment and the nature of the port scan detected suggest this is likely a benign activity. The next step recommended is to monitor the internal IPs for any unusual activity.

Automated flags: ['hash_without_data']

Verdict: ____

### ALERT-0035 (tp_malware_bad_hash, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0035", "alert_type": "Malware Signature Match", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["hash 44d88612fea8... flagged malicious by 66/75 vendors"], "hash_enrichment": {"44d88612fea8a8f36de82e1278abb02f": {"malicious": 66, "suspicious": 0, "total": 75, "type": "Powershell"}}, "internal_ips_not_enriched": ["192.168.1.40", "10.0.0.31"]}
```

Justification:

> The assigned severity of "Critical" is justified by the high number of vendors (66 out of 75) flagging the file hash 44d88612fea8... as malicious, and the file being identified as a PowerShell script, which can be indicative of sophisticated malware. The critical severity also reflects the potential high risk associated with such a widespread detection. The next step should be to investigate the internal IPs 192.168.1.40 and 10.0.0.31 to determine if the malware has spread or is actively being used within the network.

Automated flags: ['hash_overreach']

Verdict: ____

### ALERT-0007 (fp_internal_failed_logins, assigned Low)

Facts given to the model:

```
{"alert_id": "ALERT-0007", "alert_type": "Failed Login Attempts", "reported_severity": "low", "assigned_severity": "Low", "rule_findings": ["no malicious enrichment hits and a routine alert type"], "internal_ips_not_enriched": ["192.168.1.15", "10.0.0.31"]}
```

Justification:

> The alert is for failed login attempts with no malicious enrichment hits, indicating routine activity. The absence of any suspicious or malicious indicators supports the assigned severity of Low. The next step is to monitor these IP addresses for any subsequent unusual activity.

Automated flags: none

Verdict: ____

### ALERT-0024 (tp_malware_bad_hash, assigned Critical)

Facts given to the model:

```
{"alert_id": "ALERT-0024", "alert_type": "Malware Signature Match", "reported_severity": "high", "assigned_severity": "Critical", "rule_findings": ["hash 44d88612fea8... flagged malicious by 66/75 vendors"], "hash_enrichment": {"44d88612fea8a8f36de82e1278abb02f": {"malicious": 66, "suspicious": 0, "total": 75, "type": "Powershell"}}, "internal_ips_not_enriched": ["192.168.1.40", "10.0.0.31"]}
```

Justification:

> The assigned severity of Critical is justified by the high number of vendors (66 out of 75) flagging the file hash 44d88612fea8... as malicious, and the file being identified as a PowerShell script, which can be indicative of malicious activity due to its common use in executing remote commands. The high consensus among vendors in identifying this file as malicious warrants the critical severity level.
> 
> The next recommended step is to investigate the internal IPs associated with this activity to determine the scope and potential impact of the malware.

Automated flags: none

Verdict: ____

## Caveats

- The checks are regex heuristics: they miss subtle fabrication and can flag legitimate phrasing. Treat the flag rate as a lower bound and use the manual verdicts for the real overreach rate.
- Results come from one prompt and one seed per alert at temperature 0.2; rerunning can change individual outcomes.
- Latency depends on this machine, other loads, and whether the model was already loaded in memory.
