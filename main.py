#!/usr/bin/env python3

import argparse
import sys

from hunters.ioc_search import classify_ioc, determine_severity, search_ioc
from hunters.hash_analyzer import (
    calculate_hashes,
    threat_intelligence_lookup,
    generate_report as generate_hash_report,
)
from hunters.log_hunter import hunt_logs, generate_report as generate_log_report
from hunters.timeline_builder import build_timeline, assess_timeline


def cmd_ioc(value):
    ioc_type = classify_ioc(value)

    print("\n=== CYBERNOVA IOC ANALYSIS ===")
    print(f"IOC:      {value}")
    print(f"Type:     {ioc_type}")

    # Classification alone does not indicate threat severity.
    # Severity is based on the number of matches returned by a log search.
    print("Status:   IOC classified successfully")


def cmd_hash(filepath):
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


def cmd_log(filepath):
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


def cmd_timeline(filepath, ioc):
    timeline = build_timeline(filepath, ioc)
    assessment = assess_timeline(timeline)

    print("\n=== CYBERNOVA TIMELINE ANALYSIS ===")
    print(f"Log: {filepath}")
    print(f"IOC: {ioc}")

    print("\nTimeline:")
    for event in timeline:
        print(event)

    print("\nAssessment:")
    print(assessment)


def main():
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
        help="Classify an indicator of compromise",
    )
    ioc_parser.add_argument(
        "value",
        help="IP address, domain, or file hash",
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

    args = parser.parse_args()

    try:
        if args.command == "ioc":
            cmd_ioc(args.value)

        elif args.command == "hash":
            cmd_hash(args.file)

        elif args.command == "log":
            cmd_log(args.file)

        elif args.command == "timeline":
            cmd_timeline(args.file, args.ioc)

    except FileNotFoundError as exc:
        print(f"Error: file not found: {exc}", file=sys.stderr)
        sys.exit(1)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
