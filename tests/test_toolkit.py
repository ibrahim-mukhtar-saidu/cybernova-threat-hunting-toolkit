import hashlib
import tempfile
from pathlib import Path

from hunters.ioc_search import classify_ioc, determine_severity
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
