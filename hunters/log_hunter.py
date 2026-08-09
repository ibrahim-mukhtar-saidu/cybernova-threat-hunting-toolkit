from pathlib import Path
from datetime import datetime, UTC
from collections import defaultdict
import json
import re

LOG_FILE = "samples/threat_hunting.log"
REPORT_DIR = "reports/generated"

TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
ACTION_PATTERN = re.compile(r"ACTION=([A-Z_]+)")
USER_PATTERN = re.compile(r"USER=([A-Za-z0-9_]+)")
DST_PATTERN = re.compile(r"DST=([A-Za-z0-9._-]+)")
FILE_PATTERN = re.compile(r"FILE=([A-Za-z0-9._-]+)")

SUSPICIOUS_DOMAINS = {
    "malicious-domain.com",
    "evil-update.net",
    "bad-domain.org",
}

def parse_line(line: str):
    return {
        "timestamp": TIMESTAMP_PATTERN.search(line).group(1)
        if TIMESTAMP_PATTERN.search(line)
        else "UNKNOWN",
        "action": ACTION_PATTERN.search(line).group(1)
        if ACTION_PATTERN.search(line)
        else "UNKNOWN",
        "user": USER_PATTERN.search(line).group(1)
        if USER_PATTERN.search(line)
        else "UNKNOWN",
        "destination": DST_PATTERN.search(line).group(1)
        if DST_PATTERN.search(line)
        else "UNKNOWN",
        "file": FILE_PATTERN.search(line).group(1)
        if FILE_PATTERN.search(line)
        else "UNKNOWN",
    }

def hunt_logs(log_file: str):
    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(log_file)

    findings = []
    failed_logins = defaultdict(int)
    successful_logins = set()

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            event = parse_line(line)
            action = event["action"]
            destination = event["destination"]

            if action == "FAILED_LOGIN":
                failed_logins[destination] += 1

            if action == "SUCCESSFUL_LOGIN":
                successful_logins.add(destination)

            if action == "POWERSHELL_EXECUTION":
                findings.append(
                    {
                        "severity": "HIGH",
                        "type": "PowerShell Execution",
                        "timestamp": event["timestamp"],
                        "user": event["user"],
                        "destination": destination,
                        "file": event["file"],
                        "description": "Suspicious PowerShell execution detected.",
                    }
                )

            if action == "DNS_QUERY" and destination in SUSPICIOUS_DOMAINS:
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "type": "Suspicious DNS Query",
                        "timestamp": event["timestamp"],
                        "user": event["user"],
                        "destination": destination,
                        "file": event["file"],
                        "description": "DNS query to a suspicious domain detected.",
                    }
                )

            if action == "FILE_DOWNLOAD":
                findings.append(
                    {
                        "severity": "LOW",
                        "type": "File Download",
                        "timestamp": event["timestamp"],
                        "user": event["user"],
                        "destination": destination,
                        "file": event["file"],
                        "description": "File download activity observed.",
                    }
                )

    for destination, count in failed_logins.items():
        if count >= 3:
            severity = "CRITICAL" if destination in successful_logins else "HIGH"
            description = (
                "Successful login after multiple failed login attempts."
                if destination in successful_logins
                else "Multiple failed login attempts detected."
            )

            findings.append(
                {
                    "severity": severity,
                    "type": "Authentication Anomaly",
                    "timestamp": "MULTIPLE_EVENTS",
                    "user": "admin",
                    "destination": destination,
                    "file": "ssh.log",
                    "description": description,
                }
            )

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda x: severity_order[x["severity"]], reverse=True)

    return findings

def generate_report(findings):
    Path(REPORT_DIR).mkdir(exist_ok=True)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        },
    }

    output = Path(REPORT_DIR) / "threat_hunting_report.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return output

if __name__ == "__main__":
    findings = hunt_logs(LOG_FILE)

    print("\n=== Threat Hunting Findings ===")

    if not findings:
        print("No suspicious activity detected.")
    else:
        for finding in findings:
            print(f"[{finding['severity']}] {finding['type']}")
            print(f"User: {finding['user']}")
            print(f"Destination: {finding['destination']}")
            print(f"File: {finding['file']}")
            print(f"Description: {finding['description']}")
            print()

        print(f"Findings: {len(findings)}")

        report_path = generate_report(findings)

        print("\nThreat hunting report saved:")
        print(report_path)
