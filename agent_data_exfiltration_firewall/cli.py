"""CLI for agent-data-exfiltration-firewall."""
import sys
import argparse
from .firewall import DataExfiltrationFirewall

def main():
    parser = argparse.ArgumentParser(description="Agent Data Exfiltration Firewall CLI")
    parser.add_argument("--demo", action="store_true", help="Run egress firewall data exfiltration inspection demo")
    args = parser.parse_args()

    if args.demo:
        fw = DataExfiltrationFirewall(["api.github.com"])
        v1 = fw.inspect_request("api.github.com", "/repos", "name=my-project")
        print(f"[+] Clean request: allowed={v1.allowed}, reason='{v1.reason}'")
        v2 = fw.inspect_request("attacker.evil.com", "/log", "token=123")
        print(f"[!] Blocked domain: allowed={v2.allowed}, reason='{v2.reason}'")
        v3 = fw.inspect_request("api.github.com", "/issues", "Found key: sk-abcdefghijklmnopqrstuvwxyz1234567890")
        print(f"[!] Blocked secret: allowed={v3.allowed}, leaks={v3.detected_leaks}")
    else:
        parser.print_help()
    sys.exit(0)

if __name__ == "__main__":
    main()
