# FILE: hunters/timeline_builder.py

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from hunters.matching import ioc_appears_in_line, validate_ioc

LOG_FILE = "samples/threat_hunting.log"
REPORT_DIR = "reports/generated"

TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
ACTION_PATTERN = re.compile(r"ACTION=([A-Z_]+)")
USER_PATTERN = re.compile(r"USER=([A-Za-z0-9_]+)")
SRC_PATTERN = re.compile(r"SRC=([0-9.]+)")
DST_PATTERN = re.compile(r"DST=([A-Za-z0-9._-]+)")
FILE_PATTERN = re.compile(r"FILE=([A-Za-z0-9._-]+)")


def build_timeline(log_file: str, ioc: str) -> list[dict[str, str]]:
    indicator = validate_ioc(ioc)
    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    if not path.is_file():
        raise ValueError(f"Log path is not a file: {log_file}")

    timeline = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not ioc_appears_in_line(indicator, line):
                continue

            timestamp_match = TIMESTAMP_PATTERN.search(line)
            action_match = ACTION_PATTERN.search(line)
            user_match = USER_PATTERN.search(line)
            src_match = SRC_PATTERN.search(line)
            dst_match = DST_PATTERN.search(line)
            file_match = FILE_PATTERN.search(line)

            timeline.append(
                {
                    "timestamp": timestamp_match.group(1) if timestamp_match else "UNKNOWN",
                    "action": action_match.group(1) if action_match else "UNKNOWN",
                    "user": user_match.group(1) if user_match else "UNKNOWN",
                    "source_ip": src_match.group(1) if src_match else "UNKNOWN",
                    "destination": dst_match.group(1) if dst_match else "UNKNOWN",
                    "file": file_match.group(1) if file_match else "UNKNOWN",
                }
            )

    timeline.sort(key=lambda entry: entry["timestamp"])

    return timeline


def assess_timeline(timeline: list[dict[str, str]]) -> str:
    """Assess a timeline, honoring event order rather than just event counts.

    A successful login only counts as "following" a brute-force attempt if
    it appears in the timeline after at least three prior failures.
    """
    failed_login_count = 0

    for entry in timeline:
        action = entry.get("action")

        if action == "FAILED_LOGIN":
            failed_login_count += 1
        elif action == "SUCCESSFUL_LOGIN" and failed_login_count >= 3:
            return "Brute-force attack followed by successful authentication"

    if failed_login_count >= 3:
        return "Repeated authentication failures observed"

    if any(entry.get("action") == "POWERSHELL_EXECUTION" for entry in timeline):
        return "Suspicious PowerShell activity observed"

    return "General IOC activity observed"


def generate_timeline_report(ioc: str, timeline: list[dict[str, str]]) -> Path:
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "ioc": ioc,
        "timeline_events": len(timeline),
        "assessment": assess_timeline(timeline),
        "timeline": timeline,
    }

    output = Path(REPORT_DIR) / "timeline_report.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return output
