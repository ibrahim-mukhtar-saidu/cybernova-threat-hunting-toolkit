# FILE: tests/conftest.py

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


SAMPLE_LOG_CONTENT = (
    "2026-08-07 10:01:15 SRC=192.168.1.5 DST=45.33.32.156 USER=admin ACTION=FAILED_LOGIN FILE=ssh.log\n"
    "2026-08-07 10:02:40 SRC=192.168.1.5 DST=45.33.32.156 USER=admin ACTION=FAILED_LOGIN FILE=ssh.log\n"
    "2026-08-07 10:03:12 SRC=192.168.1.5 DST=45.33.32.156 USER=admin ACTION=FAILED_LOGIN FILE=ssh.log\n"
    "2026-08-07 10:05:55 SRC=192.168.1.5 DST=45.33.32.156 USER=admin ACTION=SUCCESSFUL_LOGIN FILE=ssh.log\n"
    "2026-08-07 10:06:20 SRC=192.168.1.5 DST=malicious-domain.com USER=admin ACTION=DNS_QUERY FILE=dns.log\n"
    "2026-08-07 10:07:44 SRC=192.168.1.5 DST=198.51.100.23 USER=system ACTION=FILE_DOWNLOAD FILE=update.bin\n"
    "2026-08-07 10:08:11 SRC=192.168.1.5 DST=203.0.113.50 USER=root ACTION=POWERSHELL_EXECUTION FILE=script.ps1\n"
)


@pytest.fixture
def sample_log_file(tmp_path: Path) -> Path:
    """A self-contained log fixture mirroring the project's documented sample data.

    Tests must not depend on samples/threat_hunting.log existing in the real
    repository checkout, so this content is written to an isolated tmp_path
    for every test that needs it.
    """
    log_path = tmp_path / "threat_hunting.log"
    log_path.write_text(SAMPLE_LOG_CONTENT, encoding="utf-8")
    return log_path


@pytest.fixture
def empty_log_file(tmp_path: Path) -> Path:
    log_path = tmp_path / "empty.log"
    log_path.write_text("", encoding="utf-8")
    return log_path


@pytest.fixture
def isolated_report_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect every hunter module's REPORT_DIR into an isolated tmp path.

    Without this, exercising main.py's CLI commands would write real files
    into the repository's reports/generated directory as a side effect of
    running the test suite.
    """
    report_dir = tmp_path / "reports_generated"

    monkeypatch.setattr("hunters.ioc_search.REPORT_DIR", str(report_dir))
    monkeypatch.setattr("hunters.hash_analyzer.REPORT_DIR", str(report_dir))
    monkeypatch.setattr("hunters.log_hunter.REPORT_DIR", str(report_dir))
    monkeypatch.setattr("hunters.timeline_builder.REPORT_DIR", str(report_dir))

    return report_dir

# FILE: tests/test_toolkit.py

"""Superseded by the modular test suite (test_matching.py, test_ioc_search.py,
test_timeline_builder.py, test_log_hunter.py, test_hash_analyzer.py,
test_sigma_detector.py, test_yara_detector.py, test_dashboard_generator.py,
test_main_cli.py). Kept as an empty module so historical references to this
filename do not break test collection.
"""

# FILE: tests/test_matching.py

import pytest

from hunters.matching import MIN_IOC_LENGTH, ioc_appears_in_line, validate_ioc


class TestValidateIoc:
    def test_strips_surrounding_whitespace(self):
        assert validate_ioc("  45.33.32.156  ") == "45.33.32.156"

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError, match="at least"):
            validate_ioc("")

    def test_rejects_whitespace_only_string(self):
        with pytest.raises(ValueError):
            validate_ioc("   ")

    def test_rejects_below_minimum_length(self):
        with pytest.raises(ValueError):
            validate_ioc("a" * (MIN_IOC_LENGTH - 1))

    def test_accepts_exactly_minimum_length(self):
        value = "a" * MIN_IOC_LENGTH
        assert validate_ioc(value) == value

    def test_error_message_includes_original_value(self):
        with pytest.raises(ValueError, match=r"'ab'"):
            validate_ioc("ab")


class TestIocAppearsInLine:
    def test_exact_match(self):
        assert ioc_appears_in_line("45.33.32.156", "DST=45.33.32.156 USER=admin") is True

    def test_case_insensitive_match(self):
        assert ioc_appears_in_line("MALICIOUS-DOMAIN.COM", "DST=malicious-domain.com") is True

    def test_no_match(self):
        assert ioc_appears_in_line("10.10.10.10", "DST=45.33.32.156") is False

    def test_rejects_ip_substring_collision(self):
        # "5.5.5.5" is a raw substring of "125.5.5.55" but is not the same
        # indicator; word-boundary matching must reject this occurrence.
        assert ioc_appears_in_line("5.5.5.5", "DST=125.5.5.55") is False

    def test_rejects_domain_substring_collision(self):
        # "evil.com" is a raw substring of "notevil.com".
        assert ioc_appears_in_line("evil.com", "DST=notevil.com") is False

    def test_matches_at_line_start(self):
        assert ioc_appears_in_line("45.33.32.156", "45.33.32.156 is suspicious") is True

    def test_matches_at_line_end(self):
        assert ioc_appears_in_line("45.33.32.156", "connected to 45.33.32.156") is True

    def test_matches_when_surrounded_by_punctuation(self):
        assert ioc_appears_in_line("45.33.32.156", "(45.33.32.156)") is True

    def test_no_match_on_empty_line(self):
        assert ioc_appears_in_line("45.33.32.156", "") is False

# FILE: tests/test_ioc_search.py

import json

import pytest

from hunters.ioc_search import (
    classify_ioc,
    determine_severity,
    generate_report,
    search_ioc,
)


class TestClassifyIoc:
    def test_ipv4_address(self):
        assert classify_ioc("45.33.32.156") == "IP Address"

    def test_ipv4_address_boundaries(self):
        assert classify_ioc("255.255.255.255") == "IP Address"
        assert classify_ioc("0.0.0.0") == "IP Address"  # nosec B104 - intentional IP boundary test

    def test_invalid_ipv4_is_not_an_ip(self):
        assert classify_ioc("999.999.999.999") != "IP Address"

    def test_invalid_ipv4_falls_back_to_file_indicator(self):
        assert classify_ioc("999.999.999.999") == "File / Indicator"

    def test_ipv6_address(self):
        assert classify_ioc("2001:db8::1") == "IP Address"

    def test_domain(self):
        assert classify_ioc("malicious-domain.com") == "Domain"

    def test_domain_with_subdomain(self):
        assert classify_ioc("evil.update.net") == "Domain"

    def test_md5_length_hash(self):
        assert classify_ioc("a" * 32) == "Hash"

    def test_sha1_length_hash(self):
        assert classify_ioc("a" * 40) == "Hash"

    def test_sha256_hash(self):
        assert classify_ioc(
            "d2a8304078ae990d9587f355bdb483b9eaa5ab2d8abec039fbba085627ce1bae"
        ) == "Hash"

    def test_binary_filename_is_not_a_domain(self):
        # Regression: previously misclassified as "Domain" because only
        # ".log"/".ps1" were excluded by name rather than recognizing common
        # file extensions generically.
        assert classify_ioc("update.bin") == "File / Indicator"

    def test_powershell_script_filename_is_not_a_domain(self):
        assert classify_ioc("script.ps1") == "File / Indicator"

    def test_text_filename_is_not_a_domain(self):
        assert classify_ioc("notes.txt") == "File / Indicator"

    def test_executable_filename_is_not_a_domain(self):
        assert classify_ioc("payload.exe") == "File / Indicator"

    def test_single_label_value_is_not_a_domain(self):
        assert classify_ioc("localhost") == "File / Indicator"

    def test_all_numeric_labels_are_not_a_domain(self):
        assert classify_ioc("192.168") == "File / Indicator"

    def test_domain_with_leading_hyphen_label_rejected(self):
        assert classify_ioc("-bad-.com") == "File / Indicator"

    def test_domain_with_short_alpha_tld(self):
        assert classify_ioc("bad-domain.org") == "Domain"


class TestDetermineSeverity:
    @pytest.mark.parametrize(
        "matches,expected",
        [
            (0, "INFO"),
            (1, "LOW"),
            (2, "MEDIUM"),
            (3, "HIGH"),
            (4, "CRITICAL"),
            (100, "CRITICAL"),
        ],
    )
    def test_severity_boundaries(self, matches, expected):
        assert determine_severity(matches) == expected


class TestSearchIoc:
    def test_finds_matching_events(self, sample_log_file):
        results = search_ioc(str(sample_log_file), "45.33.32.156")

        assert len(results) == 4
        assert results[0]["line"] == 1
        assert "FAILED_LOGIN" in results[0]["content"]
        assert results[-1]["line"] == 4
        assert "SUCCESSFUL_LOGIN" in results[-1]["content"]

    def test_no_matches_returns_empty_list(self, sample_log_file):
        assert search_ioc(str(sample_log_file), "198.18.0.250") == []

    def test_missing_log_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            search_ioc(str(tmp_path / "does_not_exist.log"), "45.33.32.156")

    def test_directory_as_log_file_raises(self, tmp_path):
        with pytest.raises(ValueError):
            search_ioc(str(tmp_path), "45.33.32.156")

    def test_empty_ioc_rejected(self, sample_log_file):
        with pytest.raises(ValueError):
            search_ioc(str(sample_log_file), "")

    def test_short_ioc_rejected(self, sample_log_file):
        with pytest.raises(ValueError):
            search_ioc(str(sample_log_file), "ab")

    def test_case_insensitive_match(self, sample_log_file):
        results = search_ioc(str(sample_log_file), "MALICIOUS-DOMAIN.COM")
        assert len(results) == 1

    def test_survives_invalid_utf8_bytes(self, tmp_path):
        log_path = tmp_path / "mixed_encoding.log"

        with log_path.open("wb") as handle:
            handle.write(b"\xff\xfe garbage line without indicator\n")
            handle.write(
                b"2026-08-07 10:01:15 SRC=1.1.1.1 DST=45.33.32.156 "
                b"USER=admin ACTION=FAILED_LOGIN FILE=ssh.log\n"
            )

        results = search_ioc(str(log_path), "45.33.32.156")
        assert len(results) == 1

    def test_substring_collision_not_matched(self, tmp_path):
        log_path = tmp_path / "collision.log"
        log_path.write_text(
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=125.5.5.55 ACTION=DNS_QUERY\n",
            encoding="utf-8",
        )

        assert search_ioc(str(log_path), "5.5.5.5") == []

    def test_duplicate_lines_all_counted(self, tmp_path):
        log_path = tmp_path / "duplicates.log"
        line = (
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=45.33.32.156 "
            "ACTION=FAILED_LOGIN FILE=ssh.log\n"
        )
        log_path.write_text(line * 5, encoding="utf-8")

        results = search_ioc(str(log_path), "45.33.32.156")
        assert len(results) == 5


class TestGenerateReport:
    def test_writes_expected_report(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "generated"
        monkeypatch.setattr("hunters.ioc_search.REPORT_DIR", str(report_dir))

        results = [
            {
                "line": 1,
                "content": (
                    "2026-08-07 10:01:15 SRC=192.168.1.5 DST=45.33.32.156 "
                    "USER=admin ACTION=FAILED_LOGIN FILE=ssh.log"
                ),
            }
        ]

        report_path = generate_report("45.33.32.156", results)

        assert report_path.exists()
        assert report_path.name == "ioc_investigation_report.json"

        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        assert report["ioc"] == "45.33.32.156"
        assert report["ioc_type"] == "IP Address"
        assert report["matches"] == 1
        assert report["severity"] == "LOW"
        assert len(report["findings"]) == 1

    def test_creates_missing_parent_directories(self, tmp_path, monkeypatch):
        # Regression: mkdir previously used exist_ok=True without
        # parents=True and would fail on a fresh checkout.
        report_dir = tmp_path / "does" / "not" / "exist" / "yet"
        monkeypatch.setattr("hunters.ioc_search.REPORT_DIR", str(report_dir))

        report_path = generate_report("45.33.32.156", [])
        assert report_path.exists()

    def test_report_with_no_findings(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "generated"
        monkeypatch.setattr("hunters.ioc_search.REPORT_DIR", str(report_dir))

        report_path = generate_report("198.18.0.250", [])

        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        assert report["matches"] == 0
        assert report["severity"] == "INFO"
        assert report["findings"] == []

# FILE: tests/test_timeline_builder.py


import pytest

from hunters.timeline_builder import (
    assess_timeline,
    build_timeline,
    generate_timeline_report,
)


class TestBuildTimeline:
    def test_reconstructs_ordered_timeline(self, sample_log_file):
        timeline = build_timeline(str(sample_log_file), "45.33.32.156")

        assert len(timeline) == 4
        assert [event["action"] for event in timeline] == [
            "FAILED_LOGIN",
            "FAILED_LOGIN",
            "FAILED_LOGIN",
            "SUCCESSFUL_LOGIN",
        ]

    def test_no_matches_returns_empty_list(self, sample_log_file):
        assert build_timeline(str(sample_log_file), "198.18.0.250") == []

    def test_missing_log_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            build_timeline(str(tmp_path / "missing.log"), "45.33.32.156")

    def test_directory_as_log_file_raises(self, tmp_path):
        with pytest.raises(ValueError):
            build_timeline(str(tmp_path), "45.33.32.156")

    def test_short_ioc_rejected(self, sample_log_file):
        with pytest.raises(ValueError):
            build_timeline(str(sample_log_file), "ab")

    def test_events_are_sorted_even_if_file_is_out_of_order(self, tmp_path):
        log_path = tmp_path / "out_of_order.log"
        log_path.write_text(
            "2026-08-07 10:05:00 SRC=1.1.1.1 DST=10.0.0.5 ACTION=SUCCESSFUL_LOGIN FILE=a.log\n"
            "2026-08-07 10:01:00 SRC=1.1.1.1 DST=10.0.0.5 ACTION=FAILED_LOGIN FILE=a.log\n",
            encoding="utf-8",
        )

        timeline = build_timeline(str(log_path), "10.0.0.5")

        assert [event["timestamp"] for event in timeline] == [
            "2026-08-07 10:01:00",
            "2026-08-07 10:05:00",
        ]

    def test_survives_invalid_utf8_bytes(self, tmp_path):
        log_path = tmp_path / "mixed.log"

        with log_path.open("wb") as handle:
            handle.write(b"\xff\xfe corrupted\n")
            handle.write(
                b"2026-08-07 10:01:15 SRC=1.1.1.1 DST=45.33.32.156 "
                b"USER=admin ACTION=FAILED_LOGIN FILE=ssh.log\n"
            )

        timeline = build_timeline(str(log_path), "45.33.32.156")
        assert len(timeline) == 1


class TestAssessTimeline:
    def test_brute_force_then_success(self):
        timeline = [
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "SUCCESSFUL_LOGIN"},
        ]

        assert assess_timeline(timeline) == (
            "Brute-force attack followed by successful authentication"
        )

    def test_success_before_failures_is_not_reported_as_brute_force(self):
        # Regression: order was previously ignored, so a success occurring
        # before the failures could be misreported as following them.
        timeline = [
            {"action": "SUCCESSFUL_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
        ]

        assert assess_timeline(timeline) == "Repeated authentication failures observed"

    def test_repeated_failures_without_success(self):
        timeline = [
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
        ]

        assert assess_timeline(timeline) == "Repeated authentication failures observed"

    def test_two_failures_is_not_treated_as_brute_force(self):
        timeline = [
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
        ]

        assert assess_timeline(timeline) == "General IOC activity observed"

    def test_powershell_activity(self):
        assert assess_timeline([{"action": "POWERSHELL_EXECUTION"}]) == (
            "Suspicious PowerShell activity observed"
        )

    def test_empty_timeline(self):
        assert assess_timeline([]) == "General IOC activity observed"

    def test_unrecognized_action_defaults_to_general(self):
        assert assess_timeline([{"action": "UNKNOWN"}]) == "General IOC activity observed"

    def test_second_success_after_threshold_still_detected(self):
        timeline = [
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "FAILED_LOGIN"},
            {"action": "SUCCESSFUL_LOGIN"},
        ]

        assert assess_timeline(timeline) == (
            "Brute-force attack followed by successful authentication"
        )


class TestGenerateTimelineReport:
    def test_writes_expected_report(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "generated"
        monkeypatch.setattr("hunters.timeline_builder.REPORT_DIR", str(report_dir))

        timeline = [
            {
                "timestamp": "2026-08-07 10:01:15",
                "action": "FAILED_LOGIN",
                "user": "admin",
                "source_ip": "192.168.1.5",
                "destination": "45.33.32.156",
                "file": "ssh.log",
            }
        ]

        report_path = generate_timeline_report("45.33.32.156", timeline)

        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        assert report["ioc"] == "45.33.32.156"
        assert report["timeline_events"] == 1
        assert report["assessment"] == "General IOC activity observed"

    def test_creates_missing_parent_directories(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "a" / "b" / "c"
        monkeypatch.setattr("hunters.timeline_builder.REPORT_DIR", str(report_dir))

        report_path = generate_timeline_report("45.33.32.156", [])
        assert report_path.exists()

# FILE: tests/test_log_hunter.py


import pytest

from hunters.log_hunter import generate_report as generate_log_report
from hunters.log_hunter import hunt_logs, parse_line


class TestParseLine:
    def test_parses_all_fields(self):
        line = (
            "2026-08-07 10:01:15 SRC=192.168.1.5 DST=45.33.32.156 "
            "USER=admin ACTION=FAILED_LOGIN FILE=ssh.log"
        )

        event = parse_line(line)

        assert event["timestamp"] == "2026-08-07 10:01:15"
        assert event["action"] == "FAILED_LOGIN"
        assert event["user"] == "admin"
        assert event["destination"] == "45.33.32.156"
        assert event["file"] == "ssh.log"

    def test_missing_fields_default_to_unknown(self):
        event = parse_line("this line has no recognizable fields")

        assert event["timestamp"] == "UNKNOWN"
        assert event["action"] == "UNKNOWN"
        assert event["user"] == "UNKNOWN"
        assert event["destination"] == "UNKNOWN"
        assert event["file"] == "UNKNOWN"

    def test_empty_line(self):
        assert parse_line("")["action"] == "UNKNOWN"


class TestHuntLogs:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            hunt_logs(str(tmp_path / "missing.log"))

    def test_directory_as_file_raises(self, tmp_path):
        with pytest.raises(ValueError):
            hunt_logs(str(tmp_path))

    def test_empty_log_produces_no_findings(self, empty_log_file):
        assert hunt_logs(str(empty_log_file)) == []

    def test_detects_powershell_dns_and_download(self, sample_log_file):
        findings = hunt_logs(str(sample_log_file))
        types = {finding["type"] for finding in findings}

        assert "PowerShell Execution" in types
        assert "Suspicious DNS Query" in types
        assert "File Download" in types
        assert "Authentication Anomaly" in types

    def test_dns_query_to_benign_domain_is_not_flagged(self, tmp_path):
        log_path = tmp_path / "benign.log"
        log_path.write_text(
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=example.com "
            "ACTION=DNS_QUERY FILE=dns.log\n",
            encoding="utf-8",
        )

        findings = hunt_logs(str(log_path))
        assert findings == []

    def test_findings_sorted_by_severity_descending(self, sample_log_file):
        findings = hunt_logs(str(sample_log_file))
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        ranks = [order[finding["severity"]] for finding in findings]

        assert ranks == sorted(ranks, reverse=True)

    def test_two_failed_logins_do_not_trigger_anomaly(self, tmp_path):
        log_path = tmp_path / "two_failures.log"
        log_path.write_text(
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.9 USER=bob "
            "ACTION=FAILED_LOGIN FILE=auth.log\n"
            "2026-08-07 10:00:05 SRC=1.1.1.1 DST=10.0.0.9 USER=bob "
            "ACTION=FAILED_LOGIN FILE=auth.log\n",
            encoding="utf-8",
        )

        assert hunt_logs(str(log_path)) == []

    def test_success_after_failures_is_critical_with_real_evidence(self, tmp_path):
        # Regression: the original implementation hardcoded user="admin"
        # and file="ssh.log" on every authentication anomaly finding
        # regardless of which account/log file was actually involved.
        log_path = tmp_path / "brute_force.log"
        log_path.write_text(
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.9 USER=bob "
            "ACTION=FAILED_LOGIN FILE=vpn.log\n"
            "2026-08-07 10:00:05 SRC=1.1.1.1 DST=10.0.0.9 USER=bob "
            "ACTION=FAILED_LOGIN FILE=vpn.log\n"
            "2026-08-07 10:00:10 SRC=1.1.1.1 DST=10.0.0.9 USER=bob "
            "ACTION=FAILED_LOGIN FILE=vpn.log\n"
            "2026-08-07 10:00:20 SRC=1.1.1.1 DST=10.0.0.9 USER=bob "
            "ACTION=SUCCESSFUL_LOGIN FILE=vpn.log\n",
            encoding="utf-8",
        )

        findings = hunt_logs(str(log_path))
        anomalies = [f for f in findings if f["type"] == "Authentication Anomaly"]

        assert len(anomalies) == 1
        assert anomalies[0]["severity"] == "CRITICAL"
        assert anomalies[0]["user"] == "bob"
        assert anomalies[0]["file"] == "vpn.log"
        assert anomalies[0]["destination"] == "10.0.0.9"
        assert anomalies[0]["description"] == (
            "Successful login after multiple failed login attempts."
        )

    def test_success_before_failures_is_high_not_critical(self, tmp_path):
        # Regression: temporal order was never checked previously, so a
        # success chronologically preceding the failures could be
        # misreported as a successful brute-force outcome.
        log_path = tmp_path / "reversed_order.log"
        log_path.write_text(
            "2026-08-07 09:00:00 SRC=1.1.1.1 DST=10.0.0.9 USER=alice "
            "ACTION=SUCCESSFUL_LOGIN FILE=vpn.log\n"
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.9 USER=mallory "
            "ACTION=FAILED_LOGIN FILE=vpn.log\n"
            "2026-08-07 10:00:05 SRC=1.1.1.1 DST=10.0.0.9 USER=mallory "
            "ACTION=FAILED_LOGIN FILE=vpn.log\n"
            "2026-08-07 10:00:10 SRC=1.1.1.1 DST=10.0.0.9 USER=mallory "
            "ACTION=FAILED_LOGIN FILE=vpn.log\n",
            encoding="utf-8",
        )

        findings = hunt_logs(str(log_path))
        anomalies = [f for f in findings if f["type"] == "Authentication Anomaly"]

        assert len(anomalies) == 1
        assert anomalies[0]["severity"] == "HIGH"
        assert anomalies[0]["description"] == "Multiple failed login attempts detected."
        assert anomalies[0]["user"] == "mallory"

    def test_unrelated_destinations_do_not_cross_contaminate(self, tmp_path):
        log_path = tmp_path / "two_destinations.log"
        log_path.write_text(
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.1 USER=a "
            "ACTION=FAILED_LOGIN FILE=x.log\n"
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.2 USER=b "
            "ACTION=FAILED_LOGIN FILE=y.log\n"
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.2 USER=b "
            "ACTION=FAILED_LOGIN FILE=y.log\n"
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=10.0.0.2 USER=b "
            "ACTION=FAILED_LOGIN FILE=y.log\n",
            encoding="utf-8",
        )

        findings = hunt_logs(str(log_path))
        anomalies = [f for f in findings if f["type"] == "Authentication Anomaly"]

        assert len(anomalies) == 1
        assert anomalies[0]["destination"] == "10.0.0.2"

    def test_survives_invalid_utf8_bytes(self, tmp_path):
        log_path = tmp_path / "mixed.log"

        with log_path.open("wb") as handle:
            handle.write(b"\xff\xfe garbage\n")
            handle.write(
                b"2026-08-07 10:08:11 SRC=1.1.1.1 DST=203.0.113.50 "
                b"USER=root ACTION=POWERSHELL_EXECUTION FILE=script.ps1\n"
            )

        findings = hunt_logs(str(log_path))
        assert any(f["type"] == "PowerShell Execution" for f in findings)


class TestLogGenerateReport:
    def test_writes_expected_summary(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "generated"
        monkeypatch.setattr("hunters.log_hunter.REPORT_DIR", str(report_dir))

        findings = [
            {
                "severity": "HIGH",
                "type": "PowerShell Execution",
                "timestamp": "2026-08-07 10:08:11",
                "user": "root",
                "destination": "203.0.113.50",
                "file": "script.ps1",
                "description": "Suspicious PowerShell execution detected.",
            }
        ]

        report_path = generate_log_report(findings)

        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        assert report["summary"]["total_findings"] == 1
        assert report["summary"]["high"] == 1
        assert report["summary"]["critical"] == 0
        assert report["summary"]["medium"] == 0
        assert report["summary"]["low"] == 0

    def test_creates_missing_parent_directories(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "x" / "y"
        monkeypatch.setattr("hunters.log_hunter.REPORT_DIR", str(report_dir))

        report_path = generate_log_report([])
        assert report_path.exists()

# FILE: tests/test_hash_analyzer.py

import hashlib

import pytest

from hunters.hash_analyzer import (
    calculate_hashes,
    threat_intelligence_lookup,
)
from hunters.hash_analyzer import (
    generate_report as generate_hash_report,
)


class TestCalculateHashes:
    def test_matches_hashlib_output(self, tmp_path):
        content = b"CYBERNOVA test sample"
        file_path = tmp_path / "sample.bin"
        file_path.write_bytes(content)

        hashes = calculate_hashes(str(file_path))

        assert hashes["md5"] == hashlib.md5(content, usedforsecurity=False).hexdigest()
        assert hashes["sha1"] == hashlib.sha1(content, usedforsecurity=False).hexdigest()
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()

    def test_empty_file(self, tmp_path):
        file_path = tmp_path / "empty.bin"
        file_path.write_bytes(b"")

        hashes = calculate_hashes(str(file_path))
        assert hashes["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()

    def test_content_spanning_multiple_chunks(self, tmp_path):
        content = b"A" * (5 * 1024 * 1024)
        file_path = tmp_path / "large.bin"
        file_path.write_bytes(content)

        hashes = calculate_hashes(str(file_path))
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()

    def test_binary_content_with_null_bytes(self, tmp_path):
        content = bytes(range(256)) * 10
        file_path = tmp_path / "binary.bin"
        file_path.write_bytes(content)

        hashes = calculate_hashes(str(file_path))
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            calculate_hashes(str(tmp_path / "missing.bin"))

    def test_directory_as_file_raises(self, tmp_path):
        with pytest.raises(ValueError):
            calculate_hashes(str(tmp_path))


class TestThreatIntelligenceLookup:
    def test_known_hash_matches(self):
        result = threat_intelligence_lookup(
            "44b2ecb6fbd58d953e6f0b6d4d1d5d24d6e8f93a6bfbf7f0b0c2d77c4b8b8d61"
        )

        assert result["matched"] is True
        assert result["risk"] == "HIGH"
        assert result["threat_name"] == "Simulated Malware Sample A"

    def test_second_known_hash_matches(self):
        result = threat_intelligence_lookup("a" * 64)
        assert result["matched"] is True
        assert result["threat_name"] == "Test Malware Hash"

    def test_unknown_hash_does_not_match(self):
        result = threat_intelligence_lookup("0" * 64)

        assert result["matched"] is False
        assert result["risk"] == "LOW"
        assert result["threat_name"] is None

    def test_empty_string_does_not_match(self):
        result = threat_intelligence_lookup("")
        assert result["matched"] is False


class TestHashGenerateReport:
    def test_writes_expected_report(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "generated"
        monkeypatch.setattr("hunters.hash_analyzer.REPORT_DIR", str(report_dir))

        hashes = {"md5": "x", "sha1": "y", "sha256": "z"}
        intel = {"matched": False, "threat_name": None, "risk": "LOW"}

        report_path = generate_hash_report("samples/update.bin", hashes, intel)

        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        assert report["file"] == "samples/update.bin"
        assert report["hashes"] == hashes
        assert report["threat_intelligence"] == intel

    def test_creates_missing_parent_directories(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "deep" / "nested" / "dir"
        monkeypatch.setattr("hunters.hash_analyzer.REPORT_DIR", str(report_dir))

        report_path = generate_hash_report(
            "sample.bin",
            {"md5": "x", "sha1": "y", "sha256": "z"},
            {"matched": False, "threat_name": None, "risk": "LOW"},
        )

        assert report_path.exists()

# FILE: tests/test_sigma_detector.py

import pytest

from hunters.sigma_detector import (
    detect_with_sigma,
    event_matches_selection,
    load_sigma_rule,
    parse_log_fields,
)

VALID_SIGMA_RULE = """\
title: Multiple Failed Login Attempts
id: cybernova-failed-login-001
status: experimental
description: Detects failed authentication attempts.

detection:
  selection:
    ACTION: FAILED_LOGIN
  condition: selection

level: medium
"""


@pytest.fixture
def valid_sigma_rule_file(tmp_path):
    path = tmp_path / "failed_login.yml"
    path.write_text(VALID_SIGMA_RULE, encoding="utf-8")
    return path


class TestLoadSigmaRule:
    def test_loads_valid_rule(self, valid_sigma_rule_file):
        rule = load_sigma_rule(str(valid_sigma_rule_file))

        assert rule["title"] == "Multiple Failed Login Attempts"
        assert rule["detection"]["selection"]["ACTION"] == "FAILED_LOGIN"
        assert rule["level"] == "medium"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_sigma_rule(str(tmp_path / "missing.yml"))

    def test_directory_as_rule_raises(self, tmp_path):
        with pytest.raises(TypeError):
            load_sigma_rule(str(tmp_path))

    def test_non_mapping_yaml_raises(self, tmp_path):
        path = tmp_path / "list_rule.yml"
        path.write_text("- one\n- two\n", encoding="utf-8")

        with pytest.raises(TypeError, match="mapping"):
            load_sigma_rule(str(path))

    def test_missing_required_fields_raises(self, tmp_path):
        path = tmp_path / "incomplete.yml"
        path.write_text("title: Incomplete Rule\n", encoding="utf-8")

        with pytest.raises(TypeError, match="detection"):
            load_sigma_rule(str(path))

    def test_empty_file_raises(self, tmp_path):
        path = tmp_path / "empty.yml"
        path.write_text("", encoding="utf-8")

        with pytest.raises(TypeError):
            load_sigma_rule(str(path))


class TestParseLogFields:
    def test_extracts_key_value_pairs(self):
        line = (
            "2026-08-07 10:01:15 SRC=192.168.1.5 DST=45.33.32.156 "
            "USER=admin ACTION=FAILED_LOGIN FILE=ssh.log"
        )

        fields = parse_log_fields(line)

        assert fields["SRC"] == "192.168.1.5"
        assert fields["DST"] == "45.33.32.156"
        assert fields["USER"] == "admin"
        assert fields["ACTION"] == "FAILED_LOGIN"
        assert fields["FILE"] == "ssh.log"

    def test_ignores_tokens_without_equals(self):
        fields = parse_log_fields("plain text ACTION=FAILED_LOGIN more text")
        assert fields == {"ACTION": "FAILED_LOGIN"}

    def test_ignores_empty_key_or_value(self):
        fields = parse_log_fields("=novalue KEY= ACTION=FAILED_LOGIN")
        assert fields == {"ACTION": "FAILED_LOGIN"}

    def test_empty_line_returns_empty_dict(self):
        assert parse_log_fields("") == {}

    def test_field_with_multiple_equals_splits_on_first(self):
        fields = parse_log_fields("NOTE=key=value")
        assert fields["NOTE"] == "key=value"


class TestEventMatchesSelection:
    def test_matching_event(self):
        event = {"ACTION": "FAILED_LOGIN", "USER": "admin"}
        selection = {"ACTION": "FAILED_LOGIN"}

        assert event_matches_selection(event, selection) is True

    def test_non_matching_event(self):
        event = {"ACTION": "SUCCESSFUL_LOGIN"}
        selection = {"ACTION": "FAILED_LOGIN"}

        assert event_matches_selection(event, selection) is False

    def test_missing_field_does_not_match(self):
        event = {"USER": "admin"}
        selection = {"ACTION": "FAILED_LOGIN"}

        assert event_matches_selection(event, selection) is False

    def test_empty_selection_never_matches(self):
        # Regression: an empty selection mapping previously matched every
        # event, turning a malformed rule into a wildcard rule.
        assert event_matches_selection({"ACTION": "FAILED_LOGIN"}, {}) is False

    def test_empty_event_and_empty_selection(self):
        assert event_matches_selection({}, {}) is False

    def test_multiple_fields_all_must_match(self):
        event = {"ACTION": "FAILED_LOGIN", "USER": "admin"}
        selection = {"ACTION": "FAILED_LOGIN", "USER": "root"}

        assert event_matches_selection(event, selection) is False

    def test_selection_value_coerced_to_string(self):
        event = {"PORT": "22"}
        selection = {"PORT": 22}

        assert event_matches_selection(event, selection) is True


class TestDetectWithSigma:
    def test_detects_matching_lines(self, sample_log_file, valid_sigma_rule_file):
        matches = detect_with_sigma(str(sample_log_file), str(valid_sigma_rule_file))

        assert len(matches) == 3
        assert matches[0]["line"] == 1
        assert matches[1]["line"] == 2
        assert matches[2]["line"] == 3
        assert matches[0]["rule"] == "Multiple Failed Login Attempts"
        assert matches[0]["level"] == "medium"

    def test_no_matches(self, sample_log_file, tmp_path):
        rule_path = tmp_path / "no_match.yml"
        rule_path.write_text(
            "title: No Match Rule\n"
            "detection:\n"
            "  selection:\n"
            "    ACTION: NONEXISTENT_ACTION\n"
            "  condition: selection\n",
            encoding="utf-8",
        )

        assert detect_with_sigma(str(sample_log_file), str(rule_path)) == []

    def test_missing_log_file_raises(self, valid_sigma_rule_file, tmp_path):
        with pytest.raises(FileNotFoundError):
            detect_with_sigma(str(tmp_path / "missing.log"), str(valid_sigma_rule_file))

    def test_directory_as_log_file_raises(self, valid_sigma_rule_file, tmp_path):
        with pytest.raises(ValueError):
            detect_with_sigma(str(tmp_path), str(valid_sigma_rule_file))

    def test_empty_selection_rejected(self, sample_log_file, tmp_path):
        rule_path = tmp_path / "empty_selection.yml"
        rule_path.write_text(
            "title: Empty Selection\n"
            "detection:\n"
            "  selection: {}\n"
            "  condition: selection\n",
            encoding="utf-8",
        )

        with pytest.raises(TypeError, match="non-empty"):
            detect_with_sigma(str(sample_log_file), str(rule_path))

    def test_unsupported_condition_rejected(self, sample_log_file, tmp_path):
        # Regression: this detector only implements a flat "selection"
        # condition and must reject anything else rather than silently
        # mis-evaluating it as if it were a plain selection.
        rule_path = tmp_path / "unsupported_condition.yml"
        rule_path.write_text(
            "title: Unsupported Condition\n"
            "detection:\n"
            "  selection:\n"
            "    ACTION: FAILED_LOGIN\n"
            "  condition: 1 of selection*\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="condition"):
            detect_with_sigma(str(sample_log_file), str(rule_path))

    def test_detection_missing_selection_key_raises(self, sample_log_file, tmp_path):
        rule_path = tmp_path / "missing_selection.yml"
        rule_path.write_text(
            "title: Missing Selection\n"
            "detection:\n"
            "  condition: selection\n",
            encoding="utf-8",
        )

        with pytest.raises(TypeError, match="selection"):
            detect_with_sigma(str(sample_log_file), str(rule_path))

    def test_detection_section_not_a_mapping_raises(self, sample_log_file, tmp_path):
        rule_path = tmp_path / "bad_detection.yml"
        rule_path.write_text(
            "title: Bad Detection\ndetection: not-a-mapping\n",
            encoding="utf-8",
        )

        with pytest.raises(TypeError, match="mapping"):
            detect_with_sigma(str(sample_log_file), str(rule_path))

# FILE: tests/test_yara_detector.py

import pytest
import yara  # type: ignore[import-not-found]

from hunters.yara_detector import compile_yara_rule, scan_file

VALID_YARA_RULE = """\
rule CyberNova_Test_Rule
{
    meta:
        description = "Test rule for detection"
        severity = "medium"

    strings:
        $s1 = "PowerShell execution detected"
        $s2 = "Possible credential theft behavior"

    condition:
        2 of them
}
"""

INVALID_RULE = "rule Broken { condition: this is not valid syntax }"


@pytest.fixture
def valid_yara_rule_file(tmp_path):
    path = tmp_path / "rule.yar"
    path.write_text(VALID_YARA_RULE, encoding="utf-8")
    return path


@pytest.fixture
def matching_sample_file(tmp_path):
    path = tmp_path / "sample_match.bin"
    path.write_bytes(
        b"header PowerShell execution detected middle "
        b"Possible credential theft behavior footer"
    )
    return path


@pytest.fixture
def non_matching_sample_file(tmp_path):
    path = tmp_path / "sample_clean.bin"
    path.write_bytes(b"nothing suspicious in this file at all")
    return path


class TestCompileYaraRule:
    def test_compiles_valid_rule(self, valid_yara_rule_file):
        rules = compile_yara_rule(str(valid_yara_rule_file))
        assert rules is not None

    def test_missing_rule_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            compile_yara_rule(str(tmp_path / "missing.yar"))

    def test_directory_as_rule_raises(self, tmp_path):
        with pytest.raises(ValueError):
            compile_yara_rule(str(tmp_path))

    def test_invalid_rule_syntax_raises(self, tmp_path):
        path = tmp_path / "broken.yar"
        path.write_text(INVALID_RULE, encoding="utf-8")

        with pytest.raises(yara.Error):
            compile_yara_rule(str(path))

    def test_empty_rule_file_raises(self, tmp_path):
        path = tmp_path / "empty.yar"
        path.write_text("", encoding="utf-8")

        with pytest.raises(yara.Error):
            compile_yara_rule(str(path))


class TestScanFile:
    def test_detects_match(self, matching_sample_file, valid_yara_rule_file):
        matches = scan_file(str(matching_sample_file), str(valid_yara_rule_file))

        assert len(matches) == 1
        assert matches[0]["rule"] == "CyberNova_Test_Rule"
        assert matches[0]["namespace"] == "default"
        assert matches[0]["meta"]["severity"] == "medium"
        assert matches[0]["sample"] == str(matching_sample_file)

    def test_no_match_returns_empty_list(self, non_matching_sample_file, valid_yara_rule_file):
        matches = scan_file(str(non_matching_sample_file), str(valid_yara_rule_file))
        assert matches == []

    def test_partial_string_match_is_insufficient(self, valid_yara_rule_file, tmp_path):
        # The rule requires 2 of the 2 defined strings; only one present
        # must not trigger a match.
        sample = tmp_path / "partial.bin"
        sample.write_bytes(b"PowerShell execution detected only")

        matches = scan_file(str(sample), str(valid_yara_rule_file))
        assert matches == []

    def test_missing_sample_raises(self, valid_yara_rule_file, tmp_path):
        with pytest.raises(FileNotFoundError, match="Sample file not found"):
            scan_file(str(tmp_path / "missing.bin"), str(valid_yara_rule_file))

    def test_directory_as_sample_raises(self, valid_yara_rule_file, tmp_path):
        with pytest.raises(ValueError, match="Sample path is not a file"):
            scan_file(str(tmp_path), str(valid_yara_rule_file))

    def test_missing_rule_raises(self, matching_sample_file, tmp_path):
        with pytest.raises(FileNotFoundError):
            scan_file(str(matching_sample_file), str(tmp_path / "missing.yar"))

    def test_directory_as_rule_raises(self, matching_sample_file, tmp_path):
        with pytest.raises(ValueError):
            scan_file(str(matching_sample_file), str(tmp_path))

    def test_empty_sample_file_no_match(self, valid_yara_rule_file, tmp_path):
        empty_sample = tmp_path / "empty.bin"
        empty_sample.write_bytes(b"")

        matches = scan_file(str(empty_sample), str(valid_yara_rule_file))
        assert matches == []

# FILE: tests/test_dashboard_generator.py


import pytest

from dashboards import dashboard_generator

VALID_REPORT = {
    "generated_at": "2026-08-09T16:20:12.543376+00:00",
    "findings": [
        {
            "severity": "CRITICAL",
            "type": "Authentication Anomaly",
            "timestamp": "MULTIPLE_EVENTS",
            "user": "admin",
            "destination": "45.33.32.156",
            "file": "ssh.log",
            "description": "Successful login after multiple failed login attempts.",
        }
    ],
    "summary": {
        "total_findings": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
    },
}


def write_report(path, report):
    path.write_text(json.dumps(report), encoding="utf-8")


class TestLoadReport:
    def test_loads_valid_report(self, tmp_path):
        report_path = tmp_path / "report.json"
        write_report(report_path, VALID_REPORT)

        report = dashboard_generator.load_report(report_path)
        assert report["summary"]["total_findings"] == 1

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            dashboard_generator.load_report(tmp_path / "missing.json")

    def test_non_object_report_raises(self, tmp_path):
        report_path = tmp_path / "list_report.json"
        report_path.write_text("[1, 2, 3]", encoding="utf-8")

        with pytest.raises(TypeError, match="JSON object"):
            dashboard_generator.load_report(report_path)

    def test_findings_not_a_list_raises(self, tmp_path):
        report_path = tmp_path / "bad_findings.json"
        write_report(report_path, {"findings": "not-a-list", "summary": {}})

        with pytest.raises(TypeError, match="findings"):
            dashboard_generator.load_report(report_path)

    def test_summary_not_an_object_raises(self, tmp_path):
        report_path = tmp_path / "bad_summary.json"
        write_report(report_path, {"findings": [], "summary": "not-an-object"})

        with pytest.raises(TypeError, match="summary"):
            dashboard_generator.load_report(report_path)

    def test_malformed_json_raises(self, tmp_path):
        report_path = tmp_path / "malformed.json"
        report_path.write_text("{not valid json", encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            dashboard_generator.load_report(report_path)


class TestRenderFindingRow:
    def test_escapes_html_in_description(self):
        finding = {
            "severity": "LOW",
            "type": "Test",
            "timestamp": "2026-01-01",
            "user": "admin",
            "destination": "10.0.0.1",
            "file": "test.log",
            "description": "<script>alert(1)</script>",
        }

        row = dashboard_generator.render_finding_row(finding)

        assert "<script>" not in row
        assert "&lt;script&gt;" in row

    def test_escapes_html_in_destination_field(self):
        finding = {"destination": '"><img src=x onerror=alert(1)>'}
        row = dashboard_generator.render_finding_row(finding)

        assert "<img" not in row

    def test_uses_unknown_for_missing_fields(self):
        row = dashboard_generator.render_finding_row({})

        assert "UNKNOWN" in row
        assert "No description available." in row


class TestGenerateDashboard:
    def test_generates_html_with_real_generated_at(self, tmp_path, monkeypatch):
        # Regression: the dashboard previously discarded the report's real
        # generated_at value and always displayed a hardcoded placeholder.
        report_path = tmp_path / "threat_hunting_report.json"
        output_path = tmp_path / "index.html"
        write_report(report_path, VALID_REPORT)

        monkeypatch.setattr(dashboard_generator, "REPORT_FILE", report_path)
        monkeypatch.setattr(dashboard_generator, "OUTPUT_FILE", output_path)

        result_path = dashboard_generator.generate_dashboard()

        assert result_path == output_path
        html_content = output_path.read_text(encoding="utf-8")

        assert "2026-08-09T16:20:12.543376+00:00" in html_content
        assert "CYBERNOVA AI Demo Dataset" not in html_content
        assert "Authentication Anomaly" in html_content

    def test_no_findings_shows_placeholder_row(self, tmp_path, monkeypatch):
        report_path = tmp_path / "empty_report.json"
        output_path = tmp_path / "index.html"

        write_report(
            report_path,
            {
                "generated_at": "2026-01-01T00:00:00+00:00",
                "findings": [],
                "summary": {
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
            },
        )

        monkeypatch.setattr(dashboard_generator, "REPORT_FILE", report_path)
        monkeypatch.setattr(dashboard_generator, "OUTPUT_FILE", output_path)

        dashboard_generator.generate_dashboard()

        html_content = output_path.read_text(encoding="utf-8")
        assert "No suspicious activity detected." in html_content

    def test_missing_report_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dashboard_generator, "REPORT_FILE", tmp_path / "missing.json")
        monkeypatch.setattr(dashboard_generator, "OUTPUT_FILE", tmp_path / "index.html")

        with pytest.raises(FileNotFoundError):
            dashboard_generator.generate_dashboard()

    def test_malformed_report_raises_and_does_not_write_output(self, tmp_path, monkeypatch):
        report_path = tmp_path / "bad_report.json"
        output_path = tmp_path / "index.html"

        write_report(report_path, {"findings": "not-a-list", "summary": {}})

        monkeypatch.setattr(dashboard_generator, "REPORT_FILE", report_path)
        monkeypatch.setattr(dashboard_generator, "OUTPUT_FILE", output_path)

        with pytest.raises(TypeError):
            dashboard_generator.generate_dashboard()

        assert not output_path.exists()

    def test_creates_output_parent_directory(self, tmp_path, monkeypatch):
        report_path = tmp_path / "report.json"
        output_path = tmp_path / "nested" / "dashboards" / "index.html"
        write_report(report_path, VALID_REPORT)

        monkeypatch.setattr(dashboard_generator, "REPORT_FILE", report_path)
        monkeypatch.setattr(dashboard_generator, "OUTPUT_FILE", output_path)

        dashboard_generator.generate_dashboard()
        assert output_path.exists()

# FILE: tests/test_main_cli.py

import pytest

import main as cli


class TestSanitizeForDisplay:
    def test_removes_escape_sequences(self):
        result = cli.sanitize_for_display("\x1b[31mRED\x1b[0m")

        assert "\x1b" not in result
        assert "RED" in result

    def test_removes_null_and_bell_characters(self):
        result = cli.sanitize_for_display("before\x00middle\x07after")

        assert "\x00" not in result
        assert "\x07" not in result
        assert result == "beforemiddleafter"

    def test_preserves_tabs_and_newlines(self):
        raw = "line1\tcolumn\nline2"
        assert cli.sanitize_for_display(raw) == raw

    def test_preserves_normal_text(self):
        text = "DST=45.33.32.156 ACTION=FAILED_LOGIN"
        assert cli.sanitize_for_display(text) == text

    def test_removes_delete_character(self):
        result = cli.sanitize_for_display("before\x7fafter")
        assert result == "beforeafter"


class TestBuildParser:
    def test_requires_a_subcommand(self):
        parser = cli.build_parser()

        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_ioc_default_log_file(self):
        parser = cli.build_parser()
        args = parser.parse_args(["ioc", "45.33.32.156"])

        assert args.value == "45.33.32.156"
        assert args.log_file == cli.DEFAULT_LOG_FILE

    def test_ioc_custom_log_file(self):
        parser = cli.build_parser()
        args = parser.parse_args(["ioc", "45.33.32.156", "--log", "custom.log"])

        assert args.log_file == "custom.log"

    def test_hash_subcommand(self):
        parser = cli.build_parser()
        args = parser.parse_args(["hash", "sample.bin"])
        assert args.file == "sample.bin"

    def test_timeline_subcommand(self):
        parser = cli.build_parser()
        args = parser.parse_args(["timeline", "log.txt", "45.33.32.156"])

        assert args.file == "log.txt"
        assert args.ioc == "45.33.32.156"

    def test_sigma_subcommand(self):
        parser = cli.build_parser()
        args = parser.parse_args(["sigma", "log.txt", "rule.yml"])

        assert args.file == "log.txt"
        assert args.rule == "rule.yml"

    def test_yara_subcommand(self):
        parser = cli.build_parser()
        args = parser.parse_args(["yara", "sample.bin", "rule.yar"])

        assert args.sample == "sample.bin"
        assert args.rule == "rule.yar"

    def test_unknown_subcommand_exits(self):
        parser = cli.build_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["not-a-real-command"])


class TestMainCliIntegration:
    def test_ioc_command_end_to_end(
        self, sample_log_file, isolated_report_dir, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            "sys.argv",
            ["cybernova", "ioc", "45.33.32.156", "--log", str(sample_log_file)],
        )

        cli.main()

        output = capsys.readouterr().out
        assert "CYBERNOVA IOC ANALYSIS" in output
        assert "Matches:  4" in output
        assert "Severity: CRITICAL" in output
        assert (isolated_report_dir / "ioc_investigation_report.json").exists()

    def test_ioc_command_with_no_matches(
        self, sample_log_file, isolated_report_dir, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            "sys.argv",
            ["cybernova", "ioc", "198.18.0.250", "--log", str(sample_log_file)],
        )

        cli.main()

        output = capsys.readouterr().out
        assert "No matches found in the threat hunting log." in output

    def test_hash_command_end_to_end(
        self, tmp_path, isolated_report_dir, monkeypatch, capsys
    ):
        sample_file = tmp_path / "sample.bin"
        sample_file.write_bytes(b"test content")

        monkeypatch.setattr("sys.argv", ["cybernova", "hash", str(sample_file)])

        cli.main()

        output = capsys.readouterr().out
        assert "CYBERNOVA HASH ANALYSIS" in output
        assert "No known malicious hash match" in output

    def test_log_command_end_to_end(
        self, sample_log_file, isolated_report_dir, monkeypatch, capsys
    ):
        monkeypatch.setattr("sys.argv", ["cybernova", "log", str(sample_log_file)])

        cli.main()

        output = capsys.readouterr().out
        assert "CYBERNOVA LOG HUNTING" in output
        assert "Total findings:" in output

    def test_log_command_no_findings(
        self, empty_log_file, isolated_report_dir, monkeypatch, capsys
    ):
        monkeypatch.setattr("sys.argv", ["cybernova", "log", str(empty_log_file)])

        cli.main()

        output = capsys.readouterr().out
        assert "No suspicious activity detected." in output

    def test_timeline_command_end_to_end(
        self, sample_log_file, isolated_report_dir, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            "sys.argv",
            ["cybernova", "timeline", str(sample_log_file), "45.33.32.156"],
        )

        cli.main()

        output = capsys.readouterr().out
        assert "CYBERNOVA TIMELINE ANALYSIS" in output
        assert "Brute-force attack followed by successful authentication" in output

    def test_sigma_command_end_to_end(self, sample_log_file, tmp_path, monkeypatch, capsys):
        rule_path = tmp_path / "failed_login.yml"
        rule_path.write_text(
            "title: Multiple Failed Login Attempts\n"
            "detection:\n"
            "  selection:\n"
            "    ACTION: FAILED_LOGIN\n"
            "  condition: selection\n"
            "level: medium\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["cybernova", "sigma", str(sample_log_file), str(rule_path)],
        )

        cli.main()

        output = capsys.readouterr().out
        assert "CYBERNOVA SIGMA DETECTION" in output
        assert "Matches: 3" in output

    def test_yara_command_end_to_end(self, tmp_path, monkeypatch, capsys):
        rule_path = tmp_path / "rule.yar"
        rule_path.write_text(
            "rule Test_Rule\n"
            "{\n"
            "    meta:\n"
            '        description = "test"\n'
            '        severity = "medium"\n'
            "    strings:\n"
            '        $s1 = "PowerShell execution detected"\n'
            '        $s2 = "Possible credential theft behavior"\n'
            "    condition:\n"
            "        2 of them\n"
            "}\n",
            encoding="utf-8",
        )

        sample_path = tmp_path / "sample.bin"
        sample_path.write_bytes(
            b"PowerShell execution detected and Possible credential theft behavior"
        )

        monkeypatch.setattr(
            "sys.argv",
            ["cybernova", "yara", str(sample_path), str(rule_path)],
        )

        cli.main()

        output = capsys.readouterr().out
        assert "CYBERNOVA YARA ANALYSIS" in output
        assert "Matches: 1" in output

    def test_ioc_command_sanitizes_control_characters_in_output(
        self, tmp_path, isolated_report_dir, monkeypatch, capsys
    ):
        log_path = tmp_path / "malicious.log"
        log_path.write_text(
            "2026-08-07 10:00:00 SRC=1.1.1.1 DST=45.33.32.156 "
            "ACTION=FAILED_LOGIN NOTE=\x1b[31mFAKE\x1b[0m\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["cybernova", "ioc", "45.33.32.156", "--log", str(log_path)],
        )

        cli.main()

        assert "\x1b" not in capsys.readouterr().out

    def test_missing_file_produces_clean_error_and_exit_code(
        self, monkeypatch, capsys, tmp_path
    ):
        monkeypatch.setattr("sys.argv", ["cybernova", "hash", str(tmp_path / "missing.bin")])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 1
        assert "file not found" in capsys.readouterr().err

    def test_invalid_ioc_produces_clean_error_and_exit_code(
        self, sample_log_file, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            "sys.argv", ["cybernova", "ioc", "ab", "--log", str(sample_log_file)]
        )

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 1
        assert "invalid input" in capsys.readouterr().err

    def test_directory_as_file_produces_clean_error(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr("sys.argv", ["cybernova", "hash", str(tmp_path)])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 1
        assert "invalid input" in capsys.readouterr().err

    def test_permission_error_is_reported_cleanly(self, monkeypatch, capsys):
        # PermissionError conditions are platform-dependent to reproduce
        # directly, so the CLI's error-handling boundary is exercised by
        # simulating the failure at the hunter-function boundary rather
        # than mocking main.py's own error-handling code.
        def raise_permission_error(_file_path):
            raise PermissionError("permission denied")

        monkeypatch.setattr(cli, "calculate_hashes", raise_permission_error)
        monkeypatch.setattr("sys.argv", ["cybernova", "hash", "irrelevant.bin"])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 1
        assert "permission denied" in capsys.readouterr().err

    def test_unexpected_error_is_reported_cleanly(self, monkeypatch, capsys):
        def raise_unexpected(_file_path):
            raise RuntimeError("something broke")

        monkeypatch.setattr(cli, "calculate_hashes", raise_unexpected)
        monkeypatch.setattr("sys.argv", ["cybernova", "hash", "irrelevant.bin"])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 1
        assert "unexpected failure" in capsys.readouterr().err
