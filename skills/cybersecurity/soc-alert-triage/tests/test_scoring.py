import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from scoring import direction, score_alert  # noqa: E402

INTERNAL = "10.0.0.5"
EXTERNAL = "203.0.113.9"
OTHER_EXT = "198.51.100.7"


def alert(atype, src, dst):
    return {"alert_id": "T-1", "alert_type": atype, "src_ip": src, "dest_ip": dst}


def ip(score):
    return {"score": score, "country": "XX", "isp": "test", "reports": 1, "whitelisted": False}


def vt(malicious, total=70):
    return {"malicious": malicious, "suspicious": 0, "total": total, "type": "test"}


class TestDirection(unittest.TestCase):
    def test_outbound(self):
        self.assertEqual(direction(alert("X", INTERNAL, EXTERNAL), {EXTERNAL: ip(0)}), "outbound")

    def test_inbound(self):
        self.assertEqual(direction(alert("X", EXTERNAL, INTERNAL), {EXTERNAL: ip(0)}), "inbound")

    def test_internal_to_internal(self):
        self.assertEqual(direction(alert("X", INTERNAL, "10.0.0.6"), {}), "other")

    def test_external_to_external(self):
        res = {EXTERNAL: ip(0), OTHER_EXT: ip(0)}
        self.assertEqual(direction(alert("X", EXTERNAL, OTHER_EXT), res), "other")


class TestScoring(unittest.TestCase):
    def sev(self, atype, src, dst, ips=None, hashes=None):
        return score_alert(alert(atype, src, dst), ips or {}, hashes or {})[0]

    def test_clean_routine_is_low(self):
        self.assertEqual(self.sev("Failed Login Attempts", INTERNAL, "10.0.0.6"), "Low")

    def test_high_risk_type_alone_is_medium(self):
        self.assertEqual(self.sev("Privilege Escalation Attempt", INTERNAL, "10.0.0.6"), "Medium")

    def test_clean_enrichment_stays_low(self):
        self.assertEqual(
            self.sev("Suspicious Outbound Connection", INTERNAL, EXTERNAL, {EXTERNAL: ip(0)}), "Low")

    def test_ip_boundaries(self):
        # external -> external has no direction adjustment, which isolates the thresholds
        def s(score):
            return self.sev("Known C2 Beacon Pattern", EXTERNAL, OTHER_EXT,
                            {EXTERNAL: ip(score), OTHER_EXT: ip(0)})
        self.assertEqual(s(24), "Medium")    # below 25: only the high-risk-type floor applies
        self.assertEqual(s(25), "High")
        self.assertEqual(s(75), "High")
        self.assertEqual(s(76), "Critical")

    def test_outbound_to_flagged_ip_is_escalated(self):
        # a 50% IP alone would be High; an internal host talking out to it becomes Critical
        self.assertEqual(
            self.sev("Suspicious Outbound Connection", INTERNAL, EXTERNAL, {EXTERNAL: ip(50)}), "Critical")

    def test_inbound_noise_is_downgraded(self):
        self.assertEqual(self.sev("Brute Force Attack", EXTERNAL, INTERNAL, {EXTERNAL: ip(100)}), "High")
        self.assertEqual(self.sev("Brute Force Attack", EXTERNAL, INTERNAL, {EXTERNAL: ip(50)}), "Medium")

    def test_inbound_non_noisy_type_is_not_downgraded(self):
        self.assertEqual(
            self.sev("Unusual Data Exfiltration Volume", EXTERNAL, INTERNAL, {EXTERNAL: ip(100)}), "Critical")

    def test_hash_tiers(self):
        def s(n):
            return self.sev("Malware Signature Match", INTERNAL, "10.0.0.6", hashes={"h": vt(n)})
        self.assertEqual(s(66), "Critical")
        self.assertEqual(s(10), "Critical")
        self.assertEqual(s(9), "High")
        self.assertEqual(s(5), "High")

    def test_clean_hash_on_malware_alert_is_medium(self):
        self.assertEqual(
            self.sev("Malware Signature Match", INTERNAL, "10.0.0.6", hashes={"h": vt(0)}), "Medium")

    def test_hash_not_found_is_ignored(self):
        nf = {"not_found": True, "malicious": 0, "suspicious": 0, "total": 0}
        self.assertEqual(self.sev("Failed Login Attempts", INTERNAL, "10.0.0.6", hashes={"h": nf}), "Low")

    def test_lookup_errors_are_ignored(self):
        self.assertEqual(
            self.sev("Failed Login Attempts", INTERNAL, EXTERNAL,
                     {EXTERNAL: {"error": "AbuseIPDB HTTP 429"}}, {"h": {"error": "x"}}), "Low")

    def test_ip_and_hash_agreement_is_critical(self):
        self.assertEqual(
            self.sev("Malware Signature Match", EXTERNAL, OTHER_EXT,
                     {EXTERNAL: ip(30), OTHER_EXT: ip(0)}, {"h": vt(3)}), "Critical")

    def test_reasons_are_reported(self):
        _, reasons = score_alert(alert("Brute Force Attack", EXTERNAL, INTERNAL), {EXTERNAL: ip(100)}, {})
        self.assertTrue(any("abuse confidence 100%" in r for r in reasons))
        self.assertTrue(any("background noise" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
