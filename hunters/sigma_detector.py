from pathlib import Path
from typing import Any

import yaml


def load_sigma_rule(rule_path: str) -> dict[str, Any]:
    """Load and validate a Sigma rule from a YAML file."""
    path = Path(rule_path)

    if not path.exists():
        raise FileNotFoundError(f"Sigma rule not found: {rule_path}")

    with path.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError("Sigma rule must contain a YAML mapping.")

    required_fields = {"title", "detection"}

    missing_fields = required_fields - rule.keys()

    if missing_fields:
        raise ValueError(
            f"Sigma rule missing required fields: {sorted(missing_fields)}"
        )

    return rule


def parse_log_fields(line: str) -> dict[str, str]:
    """Extract KEY=VALUE fields from a threat hunting log line."""
    fields: dict[str, str] = {}

    for token in line.split():
        if "=" not in token:
            continue

        key, value = token.split("=", 1)

        if key and value:
            fields[key] = value

    return fields


def event_matches_selection(
    event: dict[str, str],
    selection: dict[str, Any],
) -> bool:
    """Return True when an event satisfies every selection field."""
    for field, expected_value in selection.items():
        actual_value = event.get(field)

        if actual_value != str(expected_value):
            return False

    return True


def detect_with_sigma(
    log_file: str,
    rule_path: str,
) -> list[dict[str, Any]]:
    """Apply a Sigma selection rule to a threat hunting log."""
    rule = load_sigma_rule(rule_path)

    detection = rule["detection"]

    if not isinstance(detection, dict):
        raise ValueError("Sigma detection section must be a mapping.")

    selection = detection.get("selection")

    if not isinstance(selection, dict):
        raise ValueError("Sigma rule must contain a 'selection' mapping.")

    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    matches: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            event = parse_log_fields(line)

            if event_matches_selection(event, selection):
                matches.append(
                    {
                        "line": line_number,
                        "content": line.strip(),
                        "rule": rule["title"],
                        "level": rule.get("level", "unknown"),
                    }
                )

    return matches
