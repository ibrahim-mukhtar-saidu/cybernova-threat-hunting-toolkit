from pathlib import Path
from datetime import datetime, UTC
import json
import re

LOG_FILE = "samples/threat_hunting.log"
REPORT_DIR = "reports/generated"

TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
ACTION_PATTERN = re.compile(r"ACTION=([A-Z_]+)")
USER_PATTERN = re.compile(r"USER=([A-Za-z0-9_]+)")
SRC_PATTERN = re.compile(r"SRC=([0-9.]+)")
DST_PATTERN = re.compile(r"DST=([A-Za-z0-9._-]+)")
FILE_PATTERN = re.compile(r"FILE=([A-Za-z0-9._-]+)")

def build_timeline(log_file: str, ioc: str):
    path = Path(log_file)

    if not path.exists():
        return []

    timeline = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if ioc.lower() not in line.lower():
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

    timeline.sort(key=lambda x: x["timestamp"])

    return timeline

def assess_timeline(timeline):
    actions = [entry["action"] for entry in timeline]

    if actions.count("FAILED_LOGIN") >= 3 and "SUCCESSFUL_LOGIN" in actions:
        return "Brute-force attack followed by successful authentication"

    if actions.count("FAILED_LOGIN") >= 3:
        return "Repeated authentication failures observed"

    if "POWERSHELL_EXECUTION" in actions:
        return "Suspicious PowerShell activity observed"

    return "General IOC activity observed"

def generate_timeline_report(ioc: str, timeline):
    Path(REPORT_DIR).mkdir(exist_ok=True)

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

if __name__ == "__main__":
    indicator = input("Enter IOC for timeline analysis: ").strip()

    timeline = build_timeline(LOG_FILE, indicator)

    print("\n=== Investigation Timeline ===")

    if not timeline:
        print("No timeline events found.")
    else:
        for entry in timeline:
            print(
                f"{entry['timestamp']} | {entry['action']} | USER={entry['user']} | DST={entry['destination']}"
            )

        assessment = assess_timeline(timeline)

        print("\nAssessment:")
        print(assessment)

        report_path = generate_timeline_report(indicator, timeline)

        print("\nTimeline report saved:")
        print(report_path)
