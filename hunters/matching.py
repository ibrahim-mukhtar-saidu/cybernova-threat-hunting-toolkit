# FILE: hunters/matching.py

"""Shared IOC-matching helpers used by IOC search and timeline reconstruction."""

import re

MIN_IOC_LENGTH = 3


def validate_ioc(ioc: str) -> str:
    """Normalize and validate an IOC value before it is used in a search.

    A short or empty IOC would match an unreasonably large fraction of log
    lines via substring search, producing meaningless "critical" findings.
    """
    value = ioc.strip()

    if len(value) < MIN_IOC_LENGTH:
        raise ValueError(
            f"IOC value must be at least {MIN_IOC_LENGTH} characters: {ioc!r}"
        )

    return value


def ioc_appears_in_line(ioc: str, line: str) -> bool:
    """Check whether an IOC appears in a log line as a complete token.

    Boundaries are based on characters that legitimately extend an IP
    address, domain, or hash (word characters, dots, hyphens), so a short
    IOC does not match as a substring of a longer, unrelated value, e.g.
    "5.5.5.5" inside "125.5.5.55".
    """
    pattern = rf"(?<![\w.-]){re.escape(ioc)}(?![\w.-])"
    return re.search(pattern, line, re.IGNORECASE) is not None
