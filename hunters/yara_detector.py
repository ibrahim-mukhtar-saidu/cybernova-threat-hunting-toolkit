from pathlib import Path
from typing import Any

import yara


def compile_yara_rule(rule_path: str) -> yara.Rules:
    """Compile a YARA rule file."""
    path = Path(rule_path)

    if not path.exists():
        raise FileNotFoundError(f"YARA rule not found: {rule_path}")

    if not path.is_file():
        raise ValueError(f"YARA rule path is not a file: {rule_path}")

    return yara.compile(filepath=str(path))


def scan_file(
    sample_path: str,
    rule_path: str,
) -> list[dict[str, Any]]:
    """Scan a sample file with a compiled YARA rule."""
    sample = Path(sample_path)

    if not sample.exists():
        raise FileNotFoundError(f"Sample file not found: {sample_path}")

    if not sample.is_file():
        raise ValueError(f"Sample path is not a file: {sample_path}")

    rules = compile_yara_rule(rule_path)
    matches = rules.match(str(sample))

    results: list[dict[str, Any]] = []

    for match in matches:
        results.append(
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": dict(match.meta),
                "sample": str(sample),
            }
        )

    return results
