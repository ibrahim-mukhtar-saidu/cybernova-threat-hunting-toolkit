#!/usr/bin/env python3
# FILE: main.py

import argparse
import re
import sys

from hunters.hash_analyzer import (
    calculate_hashes,
    threat_intelligence_lookup,
)
from hunters.hash_analyzer import (
    generate_report as generate_hash_report,
)
from hunters.ioc_search import (
    classify_ioc,
    determine_severity,
    generate_report,
    search_ioc,
)
from hunters.log_hunter import (
    generate_report as generate_log_report,
)
from hunters.log_hunter import (
    hunt_logs,
)
from hunters.sigma_detector import detect_with_sigma
from hunters.timeline_builder import (
    assess_timeline,
    build_timeline,
    generate_timeline_report,
)
from hunters.yara_detector import scan_file

DEFAULT_LOG_FILE = "samples/threat_hunting.log"

# Raw log lines are attacker-influenced data. Strip terminal control
# characters before printing them so a crafted log entry cannot manipulate
# the analyst's terminal (cursor movement, screen clearing, etc.).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_for_display(text: str) -> str:
    return _CONTROL_CHARS.sub("", text)


def cmd_ioc(value: str, log_file: str) -> None:
    ioc_type = classify_ioc(value)

    results = search_ioc(log_file, value)
    severity = determine_severity(len(results))

    print("\n=== CYBERNOVA IOC ANALYSIS ===")
    print(f"IOC:      {value}")
    print(f"Type:     {ioc_type}")
    print(f"Matches:  {len(results)}")
    print(f"Severity: {severity}")

    if not results:
        print("\nNo matches found in the threat hunting log.")

        report_path = generate_report(value, results)
        print(f"Report saved: {report_path}")
        return

    print("\nMatching Events:")

    for result in results:
        print(f"Line {result['line']}: {sanitize_for_display(result['content'])}")

    report_path = generate_report(value, results)
    print(f"\nReport saved: {report_path}")


def cmd_hash(filepath: str) -> None:
    hashes = calculate_hashes(filepath)
    intel = threat_intelligence_lookup(hashes["sha256"])

    print("\n=== CYBERNOVA HASH ANALYSIS ===")
    print(f"File:   {filepath}")
    print(f"MD5:    {hashes['md5']}")
    print(f"SHA1:   {hashes['sha1']}")
    print(f"SHA256: {hashes['sha256']}")

    print("\nThreat Intelligence:")

    if intel["matched"]:
        print(f"Match:  {intel['threat_name']}")
    else:
        print("Match:  No known malicious hash match")

    print(f"Risk:   {intel['risk']}")

    report_path = generate_hash_report(filepath, hashes, intel)
    print(f"\nReport saved: {report_path}")


def cmd_log(filepath: str) -> None:
    findings = hunt_logs(filepath)

    print("\n=== CYBERNOVA LOG HUNTING ===")

    if not findings:
        print("No suspicious activity detected.")
        return

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['type']} | "
            f"{finding['destination']}"
        )
        print(f"  User: {finding['user']}")
        print(f"  File: {finding['file']}")
        print(f"  {finding['description']}")
        print()

    print(f"Total findings: {len(findings)}")

    report_path = generate_log_report(findings)
    print(f"Report saved: {report_path}")


def cmd_timeline(filepath: str, ioc: str) -> None:
    timeline = build_timeline(filepath, ioc)
    assessment = assess_timeline(timeline)

    print("\n=== CYBERNOVA TIMELINE ANALYSIS ===")
    print(f"Log: {filepath}")
    print(f"IOC: {ioc}")

    print("\nTimeline:")

    if not timeline:
        print("No timeline events found.")
    else:
        for event in timeline:
            print(
                "  "
                f"Timestamp: {sanitize_for_display(event["timestamp"])} | "
                f"Action: {sanitize_for_display(event["action"])} | "
                f"User: {sanitize_for_display(event["user"])} | "
                f"Source: {sanitize_for_display(event["source_ip"])} | "
                f"Destination: {sanitize_for_display(event["destination"])} | "
                f"File: {sanitize_for_display(event["file"])}"
            )

    print("\nAssessment:")
    print(assessment)

    report_path = generate_timeline_report(ioc, timeline)
    print(f"Report saved: {report_path}")


def cmd_sigma(logfile: str, rule: str) -> None:
    matches = detect_with_sigma(logfile, rule)

    print("\n=== CYBERNOVA SIGMA DETECTION ===")
    print(f"Log:     {logfile}")
    print(f"Rule:    {rule}")
    print(f"Matches: {len(matches)}")

    if not matches:
        print("\nNo Sigma rule matches detected.")
        return

    print("\nDetection Results:")

    for match in matches:
        print(
            f"[{match['level'].upper()}] "
            f"{match['rule']} | "
            f"Line {match['line']}"
        )
        print(f"  {sanitize_for_display(match['content'])}")


def cmd_yara(sample: str, rule: str) -> None:
    matches = scan_file(sample, rule)

    print("\n=== CYBERNOVA YARA ANALYSIS ===")
    print(f"Sample:  {sample}")
    print(f"Rule:    {rule}")
    print(f"Matches: {len(matches)}")

    if not matches:
        print("\nNo YARA matches detected.")
        return

    print("\nDetection Results:")

    for match in matches:
        meta = match["meta"]

        print(f"Rule:        {match['rule']}")
        print(f"Namespace:   {match['namespace']}")
        print(f"Severity:    {meta.get('severity', 'unknown')}")
        print(f"Description: {meta.get('description', 'N/A')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybernova",
        description="CYBERNOVA AI Threat Hunting Toolkit",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    ioc_parser = subparsers.add_parser(
        "ioc",
        help="Classify and investigate an indicator of compromise",
    )
    ioc_parser.add_argument(
        "value",
        help="IP address, domain, or file hash",
    )
    ioc_parser.add_argument(
        "--log",
        dest="log_file",
        default=DEFAULT_LOG_FILE,
        help=f"Log file to search (default: {DEFAULT_LOG_FILE})",
    )

    hash_parser = subparsers.add_parser(
        "hash",
        help="Analyze a file hash",
    )
    hash_parser.add_argument(
        "file",
        help="Path to the file",
    )

    log_parser = subparsers.add_parser(
        "log",
        help="Hunt suspicious activity in a log file",
    )
    log_parser.add_argument(
        "file",
        help="Path to the log file",
    )

    timeline_parser = subparsers.add_parser(
        "timeline",
        help="Build and assess an investigation timeline",
    )
    timeline_parser.add_argument(
        "file",
        help="Path to the log file",
    )
    timeline_parser.add_argument(
        "ioc",
        help="IOC to investigate",
    )

    sigma_parser = subparsers.add_parser(
        "sigma",
        help="Detect log events using a Sigma rule",
    )
    sigma_parser.add_argument(
        "file",
        help="Path to the log file",
    )
    sigma_parser.add_argument(
        "rule",
        help="Path to the Sigma rule",
    )

    yara_parser = subparsers.add_parser(
        "yara",
        help="Scan a file using a YARA rule",
    )
    yara_parser.add_argument(
        "sample",
        help="Path to the sample file",
    )
    yara_parser.add_argument(
        "rule",
        help="Path to the YARA rule",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "ioc":
            cmd_ioc(args.value, args.log_file)

        elif args.command == "hash":
            cmd_hash(args.file)

        elif args.command == "log":
            cmd_log(args.file)

        elif args.command == "timeline":
            cmd_timeline(args.file, args.ioc)

        elif args.command == "sigma":
            cmd_sigma(args.file, args.rule)

        elif args.command == "yara":
            cmd_yara(args.sample, args.rule)

    except FileNotFoundError as exc:
        print(f"Error: file not found: {exc}", file=sys.stderr)
        sys.exit(1)

    except ValueError as exc:
        print(f"Error: invalid input: {exc}", file=sys.stderr)
        sys.exit(1)

    except PermissionError as exc:
        print(f"Error: permission denied: {exc}", file=sys.stderr)
        sys.exit(1)

    except RuntimeError as exc:
        print(f"Error: unexpected failure: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
