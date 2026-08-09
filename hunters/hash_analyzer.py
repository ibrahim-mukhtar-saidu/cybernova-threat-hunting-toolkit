from pathlib import Path
from datetime import datetime, UTC
import hashlib
import json

REPORT_DIR = "reports/generated"

KNOWN_MALICIOUS_HASHES = {
    "44b2ecb6fbd58d953e6f0b6d4d1d5d24d6e8f93a6bfbf7f0b0c2d77c4b8b8d61": "Simulated Malware Sample A",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "Test Malware Hash",
}

def calculate_hashes(file_path: str):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
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

def threat_intelligence_lookup(sha256_hash: str):
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

def generate_report(file_path: str, hashes, intel):
    Path(REPORT_DIR).mkdir(exist_ok=True)

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

if __name__ == "__main__":
    target_file = input("Enter file path: ").strip()

    hashes = calculate_hashes(target_file)
    intel = threat_intelligence_lookup(hashes["sha256"])

    print("\n=== Hash Analysis ===")
    print(f"File: {target_file}")
    print(f"MD5: {hashes['md5']}")
    print(f"SHA1: {hashes['sha1']}")
    print(f"SHA256: {hashes['sha256']}")

    print("\nThreat Intelligence:")
    if intel["matched"]:
        print(f"Known malicious sample: {intel['threat_name']}")
    else:
        print("No known malicious hash match found.")

    print(f"Risk Level: {intel['risk']}")

    report_path = generate_report(target_file, hashes, intel)

    print("\nHash analysis report saved:")
    print(report_path)
