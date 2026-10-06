"""attack_map.py - static mapping from alert type to MITRE ATT&CK technique.

This is a mapping at the ALERT TYPE level, not evidence-based: it records which
ATT&CK behavior an alert type most plausibly indicates, not that the behavior
was confirmed. 'confidence' reflects how well the alert type pins down a single
technique. Verify IDs against https://attack.mitre.org before citing them.
"""

ATTACK_MAP = {
    "Port Scan Detected": {
        "id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
        "confidence": "high",
        "rationale": "Port scanning is the canonical way to enumerate network services.",
    },
    "Brute Force Attack": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "confidence": "high",
        "rationale": "Repeated automated authentication attempts match T1110 directly.",
    },
    "Failed Login Attempts": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "confidence": "low",
        "rationale": "Failed logins are often routine (typos, expired passwords); only a "
                     "pattern of them suggests brute force.",
    },
    "Known C2 Beacon Pattern": {
        "id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
        "confidence": "high",
        "rationale": "Beaconing over standard application protocols is the core of T1071; "
                     "the sub-technique depends on the protocol, which the alert does not give.",
    },
    "Unusual Data Exfiltration Volume": {
        "id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
        "confidence": "medium",
        "rationale": "A volume anomaly does not reveal the channel; T1041 (exfiltration over "
                     "the C2 channel) is equally plausible.",
    },
    "Suspicious Outbound Connection": {
        "id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
        "confidence": "low",
        "rationale": "Too generic to pin down: could be benign, C2, or exfiltration.",
    },
    "Malware Signature Match": {
        "id": "T1204.002", "name": "User Execution: Malicious File", "tactic": "Execution",
        "confidence": "low",
        "rationale": "A signature match shows malware is present, not how it ran; this "
                     "assumes a user-launched file.",
    },
    "Privilege Escalation Attempt": {
        "id": "T1068", "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "confidence": "low",
        "rationale": "The tactic is certain, but the alert type does not say how; T1548 "
                     "(abuse elevation control mechanism) is also plausible.",
    },
}

UNMAPPED = {
    "id": "-", "name": "Unmapped", "tactic": "-", "confidence": "none",
    "rationale": "No mapping defined for this alert type.",
}


def map_alert(alert):
    """Return the ATT&CK mapping dict for an alert (UNMAPPED if the type is unknown)."""
    return ATTACK_MAP.get(alert.get("alert_type"), UNMAPPED)
