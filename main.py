#!/usr/bin/env python3

import argparse
import sys

from hunters.ioc_search import (
    classify_ioc,
    determine_severity,
    search_ioc,
    generate_report,
)
from hunters.hash_analyzer import (
    calculate_hashes,
    threat_intelligence_lookup,
    generate_report as generate_hash_report,
)
from hunters.log_hunter import (
    hunt_logs,
    generate_report as generate_log_report,
)
from hunters.timeline_builder import (
    build_timeline,
    assess_timeline,
    generate_timeline_report,
)
from hunters.sigma_detector import detect_with_sigma
from hunters.yara_detector import scan_file


def cmd_ioc(value):
    ioc_type = classify_ioc(value)
    log_file = "samples/threat_hunting.log"

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
        print(f"Line {result['line']}: {result['content']}")

    report_path = generate_report(value, results)
    print(f"\nReport saved: {report_path}")


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

    if not timeline:
        print("No timeline events found.")
    else:
        for event in timeline:
            print(event)

    print("\nAssessment:")
    print(assessment)

    report_path = generate_timeline_report(ioc, timeline)
    print(f"Report saved: {report_path}")


def cmd_sigma(logfile, rule):
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
        print(f"  {match['content']}")


def cmd_yara(sample, rule):
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
        help="Classify and investigate an indicator of compromise",
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

        elif args.command == "sigma":
            cmd_sigma(args.file, args.rule)

        elif args.command == "yara":
            cmd_yara(args.sample, args.rule)

    except FileNotFoundError as exc:
        print(f"Error: file not found: {exc}", file=sys.stderr)
        sys.exit(1)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
