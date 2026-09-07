# FILE: hunters/log_hunter.py

import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

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

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _extract_group(pattern: re.Pattern[str], line: str) -> str:
    match = pattern.search(line)
    return match.group(1) if match else "UNKNOWN"


def parse_line(line: str) -> dict[str, str]:
    return {
        "timestamp": _extract_group(TIMESTAMP_PATTERN, line),
        "action": _extract_group(ACTION_PATTERN, line),
        "user": _extract_group(USER_PATTERN, line),
        "destination": _extract_group(DST_PATTERN, line),
        "file": _extract_group(FILE_PATTERN, line),
    }


def hunt_logs(log_file: str) -> list[dict]:
    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    if not path.is_file():
        raise ValueError(f"Log path is not a file: {log_file}")

    findings = []
    failed_logins: dict[str, list[dict[str, str]]] = defaultdict(list)
    successful_logins: dict[str, list[dict[str, str]]] = defaultdict(list)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            action = event["action"]
            destination = event["destination"]

            if action == "FAILED_LOGIN":
                failed_logins[destination].append(event)

            if action == "SUCCESSFUL_LOGIN":
                successful_logins[destination].append(event)

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

    for destination, failures in failed_logins.items():
        if len(failures) < 3:
            continue

        known_timestamps = [
            f["timestamp"] for f in failures if f["timestamp"] != "UNKNOWN"
        ]
        last_failure_timestamp = max(known_timestamps) if known_timestamps else None

        later_successes = []
        if last_failure_timestamp is not None:
            later_successes = [
                s
                for s in successful_logins.get(destination, [])
                if s["timestamp"] != "UNKNOWN" and s["timestamp"] > last_failure_timestamp
            ]

        if later_successes:
            evidence_event = later_successes[0]
            severity = "CRITICAL"
            description = "Successful login after multiple failed login attempts."
        else:
            evidence_event = failures[-1]
            severity = "HIGH"
            description = "Multiple failed login attempts detected."

        findings.append(
            {
                "severity": severity,
                "type": "Authentication Anomaly",
                "timestamp": "MULTIPLE_EVENTS",
                "user": evidence_event["user"],
                "destination": destination,
                "file": evidence_event["file"],
                "description": description,
            }
        )

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    return findings


def generate_report(findings: list[dict]) -> Path:
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

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
