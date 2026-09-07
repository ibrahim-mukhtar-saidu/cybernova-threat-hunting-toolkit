# FILE: hunters/sigma_detector.py

from pathlib import Path
from typing import Any

import yaml

# This detector evaluates a single flat "selection" mapping with implicit AND
# semantics. Full Sigma condition syntax (multiple named selections, "or",
# "not", "1 of", "contains", list values, etc.) is not implemented. Rules
# using anything other than a plain `condition: selection` are rejected
# rather than silently mis-evaluated.
SUPPORTED_CONDITION = "selection"


def load_sigma_rule(rule_path: str) -> dict[str, Any]:
    """Load and validate a Sigma rule from a YAML file."""
    path = Path(rule_path)

    if not path.exists():
        raise FileNotFoundError(f"Sigma rule not found: {rule_path}")

    if not path.is_file():
        raise TypeError(f"Sigma rule path is not a file: {rule_path}")

    with path.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise TypeError("Sigma rule must contain a YAML mapping.")

    required_fields = {"title", "detection"}
    missing_fields = required_fields - rule.keys()

    if missing_fields:
        raise TypeError(
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
    """Return True when an event satisfies every selection field.

    An empty selection is rejected rather than treated as "matches
    everything", since that would turn a malformed rule into a rule that
    fires on every log line.
    """
    if not selection:
        return False

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
        raise TypeError("Sigma detection section must be a mapping.")

    selection = detection.get("selection")

    if not isinstance(selection, dict) or not selection:
        raise TypeError("Sigma rule must contain a non-empty 'selection' mapping.")

    condition = detection.get("condition", SUPPORTED_CONDITION)

    if condition != SUPPORTED_CONDITION:
        raise ValueError(
            "This detector only supports a plain 'selection' condition; "
            f"got: {condition!r}"
        )

    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    if not path.is_file():
        raise ValueError(f"Log path is not a file: {log_file}")

    matches: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8", errors="replace") as file:
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
