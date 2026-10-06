import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
from attack_map import ATTACK_MAP, UNMAPPED, map_alert  # noqa: E402

ALERT_TYPES = [
    "Suspicious Outbound Connection", "Failed Login Attempts", "Malware Signature Match",
    "Unusual Data Exfiltration Volume", "Port Scan Detected", "Brute Force Attack",
    "Known C2 Beacon Pattern", "Privilege Escalation Attempt",
]
TACTICS = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
}


class TestAttackMap(unittest.TestCase):
    def test_all_known_types_mapped(self):
        for t in ALERT_TYPES:
            self.assertIn(t, ATTACK_MAP, t)

    def test_ids_well_formed(self):
        for t, m in ATTACK_MAP.items():
            self.assertRegex(m["id"], r"^T\d{4}(\.\d{3})?$", t)

    def test_confidence_values(self):
        for t, m in ATTACK_MAP.items():
            self.assertIn(m["confidence"], {"high", "medium", "low"}, t)

    def test_tactics_valid(self):
        for t, m in ATTACK_MAP.items():
            self.assertIn(m["tactic"], TACTICS, t)

    def test_every_entry_has_rationale(self):
        for t, m in ATTACK_MAP.items():
            self.assertTrue(m["rationale"].strip(), t)

    def test_unknown_type_is_unmapped(self):
        self.assertEqual(map_alert({"alert_type": "Nonsense"}), UNMAPPED)

    def test_labeled_data_types_mapped(self):
        path = HERE.parent / "examples" / "sample_alerts_labeled.json"
        if not path.exists():
            self.skipTest("labeled data not generated")
        for a in json.loads(path.read_text()):
            self.assertNotEqual(map_alert(a), UNMAPPED, a["alert_type"])


if __name__ == "__main__":
    unittest.main()
