#!/usr/bin/env python3
"""
TAVARDT Certificate Sentinel (Python CLI & Daemon)
Description: Automated TLS/SSL certificate & chain integrity inspector
Website: https://ag.tavardt.com/
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
import urllib.request


def inspect_domain(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    result = {
        "domain": hostname,
        "port": port,
        "status": "UNKNOWN",
        "days_remaining": None,
        "valid_from": None,
        "valid_to": None,
        "issuer": None,
        "subject": None,
        "san": [],
        "tls_version": None,
        "cipher": None,
        "warnings": [],
        "errors": []
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["tls_version"] = ssock.version()
                result["cipher"] = cipher[0] if cipher else None

                # Dates
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["valid_to"] = not_after.isoformat()
                    now = datetime.now(timezone.utc)
                    delta = not_after - now
                    result["days_remaining"] = delta.days

                if not_before_str:
                    not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["valid_from"] = not_before.isoformat()

                # Issuer & Subject
                result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                result["subject"] = dict(x[0] for x in cert.get("subject", ()))

                # SANs
                result["san"] = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]

                # Health Assessment
                days = result["days_remaining"]
                if days is None:
                    result["status"] = "ERROR"
                    result["errors"].append("Unable to parse expiration date")
                elif days <= 0:
                    result["status"] = "EXPIRED"
                    result["errors"].append(f"Certificate expired {abs(days)} days ago")
                elif days <= 15:
                    result["status"] = "CRITICAL"
                    result["warnings"].append(f"Certificate expires in {days} days (< 15 days)")
                elif days <= 30:
                    result["status"] = "WARNING"
                    result["warnings"].append(f"Certificate expires in {days} days (< 30 days)")
                else:
                    result["status"] = "HEALTHY"

                # Check CA reputation
                issuer_org = result["issuer"].get("organizationName", "")
                if "emudhra" in issuer_org.lower():
                    result["warnings"].append("Flagged CA: Certificate issued by eMudhra (Incident eMudhra PKI)")

    except ssl.SSLCertVerificationError as e:
        result["status"] = "UNTRUSTED"
        result["errors"].append(f"SSL Verification Error: {str(e)}")
    except socket.timeout:
        result["status"] = "TIMEOUT"
        result["errors"].append(f"Connection timed out after {timeout} seconds")
    except Exception as e:
        result["status"] = "ERROR"
        result["errors"].append(str(e))

    return result


def dispatch_webhook(webhook_url: str, report: dict):
    try:
        data = json.dumps(report).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "TAVARDT-Cert-Sentinel/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass
    except Exception as e:
        sys.stderr.write(f"Failed to dispatch webhook: {e}\n")


def main():
    parser = argparse.ArgumentParser(description="TAVARDT Certificate Sentinel Watchdog")
    parser.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("-f", "--file", help="File containing list of domains to audit")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Socket timeout in seconds")
    parser.add_argument("-w", "--webhook", help="Webhook URL for alert dispatch")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    domains = []
    if args.file:
        with open(args.file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    elif args.domain:
        domains.append(args.domain)
    else:
        parser.print_help()
        sys.exit(1)

    reports = []
    for d in domains:
        rep = inspect_domain(d, port=args.port, timeout=args.timeout)
        reports.append(rep)
        if args.webhook and rep["status"] in ("CRITICAL", "EXPIRED", "UNTRUSTED", "WARNING"):
            dispatch_webhook(args.webhook, rep)

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
    else:
        for r in reports:
            status_icon = "✅" if r["status"] == "HEALTHY" else ("⚠️" if r["status"] == "WARNING" else "🚨")
            print(f"[{status_icon} {r['status']}] {r['domain']}:{r['port']}")
            if r["days_remaining"] is not None:
                print(f"   Days Remaining: {r['days_remaining']} days (Expires: {r['valid_to']})")
            if r["issuer"]:
                print(f"   Issuer: {r['issuer'].get('commonName') or r['issuer'].get('organizationName')}")
            if r["tls_version"]:
                print(f"   TLS: {r['tls_version']} | Cipher: {r['cipher']}")
            if r["errors"]:
                print(f"   Errors: {', '.join(r['errors'])}")
            if r["warnings"]:
                print(f"   Warnings: {', '.join(r['warnings'])}")
            print()


if __name__ == "__main__":
    main()
