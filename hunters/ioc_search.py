# FILE: hunters/ioc_search.py

import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path

from hunters.matching import ioc_appears_in_line, validate_ioc

REPORT_DIR = "reports/generated"
LOG_FILE = "samples/threat_hunting.log"

# Extensions that indicate the value is almost certainly a filename rather
# than a domain, even though it structurally looks like "label.label".
COMMON_FILE_EXTENSIONS = {
    "bin", "exe", "dll", "log", "ps1", "txt", "bat", "sh", "zip", "rar",
    "doc", "docx", "pdf", "jpg", "jpeg", "png", "gif", "csv", "json",
    "yml", "yaml", "py", "js", "dat", "tmp", "ini", "cfg", "conf", "sys",
}


def classify_ioc(ioc: str) -> str:
    value = ioc.strip()

    try:
        ipaddress.ip_address(value)
        return "IP Address"
    except ValueError:
        pass

    if len(value) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in value
    ):
        return "Hash"

    if _looks_like_domain(value):
        return "Domain"

    return "File / Indicator"


def _looks_like_domain(value: str) -> bool:
    labels = value.split(".")

    if len(labels) < 2 or not all(labels):
        return False

    if all(label.isdigit() for label in labels):
        return False

    tld = labels[-1]

    if not tld.isalpha() or not (2 <= len(tld) <= 24):
        return False

    if tld.lower() in COMMON_FILE_EXTENSIONS:
        return False

    valid_chars = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    )

    for label in labels:
        if not set(label) <= valid_chars:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def determine_severity(matches: int) -> str:
    if matches >= 4:
        return "CRITICAL"
    if matches == 3:
        return "HIGH"
    if matches == 2:
        return "MEDIUM"
    if matches == 1:
        return "LOW"
    return "INFO"


def search_ioc(log_file: str, ioc: str) -> list[dict]:
    indicator = validate_ioc(ioc)
    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    if not path.is_file():
        raise ValueError(f"Log path is not a file: {log_file}")

    matches = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            if ioc_appears_in_line(indicator, line):
                matches.append(
                    {
                        "line": line_number,
                        "content": line.strip(),
                    }
                )

    return matches


def generate_report(ioc: str, results: list[dict]) -> Path:
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

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
