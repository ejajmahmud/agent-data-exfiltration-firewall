"""Egress firewall scanning agent outbound traffic for sensitive leaks."""
import re
from typing import Dict, List, Set, Optional, Tuple, Any

# Common secret regexes
PATTERNS = {
    "OPENAI_KEY": re.compile(r"sk-[a-zA-Z0-9]{32,64}"),
    "GITHUB_TOKEN": re.compile(r"gh[pousr]-[a-zA-Z0-9]{36,40}"),
    "AWS_ACCESS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GENERIC_BEARER": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.~+/]{20,}"),
    "EMAIL_PII": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
}

class EgressVerdict:
    def __init__(self, allowed: bool, reason: str, detected_leaks: List[str]):
        self.allowed = allowed
        self.reason = reason
        self.detected_leaks = detected_leaks

class DataExfiltrationFirewall:
    """Inspects outbound URLs and payload bodies for exfiltration risks."""

    def __init__(self, allowed_domains: Optional[List[str]] = None):
        self.allowed_domains = set(allowed_domains or ["api.github.com", "api.openai.com", "huggingface.co"])

    def inspect_request(self, domain: str, path: str, body: str) -> EgressVerdict:
        if domain not in self.allowed_domains:
            return EgressVerdict(False, f"Domain '{domain}' not in allowed egress whitelist", [])

        detected = []
        full_content = f"{path} {body}"
        for name, pattern in PATTERNS.items():
            if pattern.search(full_content):
                detected.append(name)

        if detected:
            return EgressVerdict(False, f"Blocked: detected secrets/PII: {', '.join(detected)}", detected)

        return EgressVerdict(True, "Clean outbound request", [])
