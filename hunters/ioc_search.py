from pathlib import Path
import json
from datetime import datetime, UTC


REPORT_DIR = "reports/generated"
LOG_FILE = "samples/threat_hunting.log"


def classify_ioc(ioc: str) -> str:
    parts = ioc.split(".")

    if len(parts) == 4 and all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in parts
    ):
        return "IP Address"

    if "." in ioc and not ioc.endswith(".log") and not ioc.endswith(".ps1"):
        domain_parts = ioc.split(".")

        if (
            len(domain_parts) >= 2
            and all(part and all(c.isalnum() or c == "-" for c in part) for part in domain_parts)
            and not all(part.isdigit() for part in domain_parts)
        ):
            return "Domain"

    if len(ioc) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in ioc
    ):
        return "Hash"

    return "File / Indicator"

def determine_severity(matches: int) -> str:
    if matches >= 4:
        return "CRITICAL"
    elif matches == 3:
        return "HIGH"
    elif matches == 2:
        return "MEDIUM"
    elif matches == 1:
        return "LOW"
    return "INFO"


def search_ioc(log_file: str, ioc: str):
    path = Path(log_file)

    if not path.exists():
        return []

    matches = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            if ioc.lower() in line.lower():
                matches.append(
                    {
                        "line": line_number,
                        "content": line.strip(),
                    }
                )

    return matches


def generate_report(ioc: str, results):
    Path(REPORT_DIR).mkdir(exist_ok=True)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "ioc": ioc,
        "ioc_type": classify_ioc(ioc),
        "matches": len(results),
        "severity": determine_severity(len(results)),
        "findings": results,
    }

    output = Path(REPORT_DIR) / "ioc_investigation_report.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return output


if __name__ == "__main__":
    indicator = input("Enter IOC: ").strip()

    results = search_ioc(LOG_FILE, indicator)

    print("\n=== IOC Search Results ===")

    if not results:
        print("No matches found.")
    else:
        severity = determine_severity(len(results))

        print(f"IOC: {indicator}")
        print(f"Type: {classify_ioc(indicator)}")
        print(f"Matches: {len(results)}")
        print(f"Severity: {severity}\n")

        for result in results:
            print(f"Line {result['line']}: {result['content']}")

        report_path = generate_report(indicator, results)

        print(f"\nInvestigation report saved:")
        print(report_path)
