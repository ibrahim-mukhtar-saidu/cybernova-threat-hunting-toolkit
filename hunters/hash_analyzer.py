# FILE: hunters/hash_analyzer.py

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

REPORT_DIR = "reports/generated"

KNOWN_MALICIOUS_HASHES = {
    "44b2ecb6fbd58d953e6f0b6d4d1d5d24d6e8f93a6bfbf7f0b0c2d77c4b8b8d61": "Simulated Malware Sample A",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "Test Malware Hash",
}


def calculate_hashes(file_path: str) -> dict[str, str]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        while chunk := f.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def threat_intelligence_lookup(sha256_hash: str) -> dict:
    if sha256_hash in KNOWN_MALICIOUS_HASHES:
        return {
            "matched": True,
            "threat_name": KNOWN_MALICIOUS_HASHES[sha256_hash],
            "risk": "HIGH",
        }

    return {
        "matched": False,
        "threat_name": None,
        "risk": "LOW",
    }


def generate_report(file_path: str, hashes: dict, intel: dict) -> Path:
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "file": file_path,
        "hashes": hashes,
        "threat_intelligence": intel,
    }

    output = Path(REPORT_DIR) / "hash_analysis_report.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return output
