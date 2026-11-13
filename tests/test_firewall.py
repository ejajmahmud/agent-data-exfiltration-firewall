"""Unit tests for agent-data-exfiltration-firewall."""
import unittest
from agent_data_exfiltration_firewall.firewall import DataExfiltrationFirewall

class TestDataExfiltrationFirewall(unittest.TestCase):
    def setUp(self):
        self.fw = DataExfiltrationFirewall(["trusted.org"])

    def test_allowed_request(self):
        v = self.fw.inspect_request("trusted.org", "/search", "q=python")
        self.assertTrue(v.allowed)

    def test_untrusted_domain(self):
        v = self.fw.inspect_request("evil.com", "/steal", "data=1")
        self.assertFalse(v.allowed)
        self.assertIn("not in allowed egress", v.reason)

    def test_secret_detection(self):
        v = self.fw.inspect_request("trusted.org", "/submit", "key is AKIA1234567890123456")
        self.assertFalse(v.allowed)
        self.assertIn("AWS_ACCESS_KEY", v.detected_leaks)

if __name__ == "__main__":
    unittest.main()
