import json
import random
from datetime import datetime, timedelta

ALERT_TYPES = [
    "Suspicious Outbound Connection",
    "Failed Login Attempts",
    "Malware Signature Match",
    "Unusual Data Exfiltration Volume",
    "Port Scan Detected",
    "Brute Force Attack",
    "Known C2 Beacon Pattern",
    "Privilege Escalation Attempt",
]

# Mix of known-safe, known-test, and realistic-looking IPs
SAMPLE_IPS = [
    "8.8.8.8",           # Google DNS - safe, real
    "1.1.1.1",           # Cloudflare DNS - safe, real
    "185.220.101.45",    # realistic-looking external IP
    "45.155.205.233",    # realistic-looking external IP
    "192.168.1.15",      # internal IP
    "10.0.0.22",         # internal IP
    "203.0.113.77",      # TEST-NET-3 (reserved for documentation, safe)
]

# Mix of real test hashes (EICAR + empty file) and fake-looking ones
SAMPLE_HASHES = [
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file MD5 - real, safe
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file SHA-256
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file MD5
]

INTERNAL_HOSTS = ["WORKSTATION-07", "WORKSTATION-12", "SERVER-DB01", "SERVER-WEB02", "LAPTOP-USER23"]

def generate_alert(alert_id):
    alert_type = random.choice(ALERT_TYPES)
    timestamp = (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat()

    alert = {
        "alert_id": f"ALERT-{alert_id:04d}",
        "timestamp": timestamp,
        "alert_type": alert_type,
        "severity_reported": random.choice(["low", "medium", "high"]),
        "src_ip": random.choice(SAMPLE_IPS),
        "dest_ip": random.choice(SAMPLE_IPS),
        "internal_host": random.choice(INTERNAL_HOSTS),
        "raw_log": f"{alert_type} detected from {random.choice(INTERNAL_HOSTS)}"
    }

    # Only some alerts have a file hash (e.g. malware-related ones)
    if "Malware" in alert_type or random.random() < 0.3:
        alert["file_hash"] = random.choice(SAMPLE_HASHES)

    return alert

def main(count=20):
    alerts = [generate_alert(i + 1) for i in range(count)]

    with open("sample_alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"Generated {count} synthetic alerts -> sample_alerts.json")

if __name__ == "__main__":
    main(20)
