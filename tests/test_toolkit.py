import hashlib
import json
import tempfile
from pathlib import Path

from hunters.ioc_search import classify_ioc, determine_severity, search_ioc, generate_report
from hunters.hash_analyzer import calculate_hashes
from hunters.timeline_builder import assess_timeline


def test_classify_ip_address():
    assert classify_ioc("45.33.32.156") == "IP Address"


def test_classify_domain():
    assert classify_ioc("malicious-domain.com") == "Domain"


def test_classify_hash():
    assert classify_ioc(
        "d2a8304078ae990d9587f355bdb483b9eaa5ab2d8abec039fbba085627ce1bae"
    ) == "Hash"


def test_severity_levels():
    assert determine_severity(0) == "INFO"
    assert determine_severity(1) == "LOW"
    assert determine_severity(2) == "MEDIUM"
    assert determine_severity(3) == "HIGH"
    assert determine_severity(4) == "CRITICAL"


def test_hash_calculation():
    content = b"CYBERNOVA test sample"

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(content)
        temp_path = Path(temp.name)

    try:
        hashes = calculate_hashes(str(temp_path))

        assert hashes["md5"] == hashlib.md5(content).hexdigest()
        assert hashes["sha1"] == hashlib.sha1(content).hexdigest()
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()
    finally:
        temp_path.unlink(missing_ok=True)


def test_bruteforce_timeline_assessment():
    timeline = [
        {"action": "FAILED_LOGIN"},
        {"action": "FAILED_LOGIN"},
        {"action": "FAILED_LOGIN"},
        {"action": "SUCCESSFUL_LOGIN"},
    ]

    result = assess_timeline(timeline)

    assert result == "Brute-force attack followed by successful authentication"


def test_powershell_timeline_assessment():
    timeline = [
        {"action": "POWERSHELL_EXECUTION"},
    ]

    result = assess_timeline(timeline)

    assert result == "Suspicious PowerShell activity observed"

def test_ioc_search_finds_matching_events():
    results = search_ioc(
        "samples/threat_hunting.log",
        "45.33.32.156",
    )

    assert len(results) == 4
    assert results[0]["line"] == 1
    assert "FAILED_LOGIN" in results[0]["content"]
    assert results[-1]["line"] == 4
    assert "SUCCESSFUL_LOGIN" in results[-1]["content"]


def test_ioc_search_returns_no_matches():
    results = search_ioc(
        "samples/threat_hunting.log",
        "198.18.0.250",
    )

    assert results == []


def test_ioc_report_generation(tmp_path, monkeypatch):
    results = [
        {
            "line": 1,
            "content": (
                "2026-08-07 10:01:15 "
                "SRC=192.168.1.5 DST=45.33.32.156 "
                "USER=admin ACTION=FAILED_LOGIN FILE=ssh.log"
            ),
        }
    ]

    report_dir = tmp_path / "generated"
    monkeypatch.setattr(
        "hunters.ioc_search.REPORT_DIR",
        str(report_dir),
    )

    report_path = generate_report(
        "45.33.32.156",
        results,
    )

    assert report_path.exists()
    assert report_path.name == "ioc_investigation_report.json"


    with report_path.open("r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["ioc"] == "45.33.32.156"
    assert report["ioc_type"] == "IP Address"
    assert report["matches"] == 1
    assert report["severity"] == "LOW"
    assert len(report["findings"]) == 1

def test_classify_valid_ipv4_addresses():
    assert classify_ioc("8.8.8.8") == "IP Address"
    assert classify_ioc("192.168.1.1") == "IP Address"
    assert classify_ioc("255.255.255.255") == "IP Address"


def test_classify_invalid_ipv4_addresses():
    assert classify_ioc("999.999.999.999") == "File / Indicator"
    assert classify_ioc("45x33x32x156") == "File / Indicator"
