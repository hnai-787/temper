"""Whole-password blocklist matching.

SP 800-63B-4 SS3.1.1 requires comparing the ENTIRE proposed password
against a blocklist of commonly-used, expected, or compromised values --
not rejecting a password merely because it *contains* a blocklisted
substring. `check_blocklist` therefore only ever does exact (normalized)
whole-string comparison; it deliberately does not implement substring
scanning. Substring/pattern observations belong to the strength
estimator (`strength.py`), not this normative blocklist check.
"""

from __future__ import annotations

from pathlib import Path


def normalize(password: str) -> str:
    """Case-fold for matching -- blocklist comparison here is
    case-insensitive by policy choice (a documented, conservative
    design decision: "Password1" should hit the same blocklist entry as
    "password1"), not a requirement mandated by the standard itself.
    """
    return password.casefold()


def load_blocklist(path: str | Path) -> frozenset[str]:
    path = Path(path)
    entries = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.add(normalize(line))
    return frozenset(entries)


def check_blocklist(password: str, blocklist: frozenset[str]) -> tuple[bool, str | None]:
    normalized = normalize(password)
    if normalized in blocklist:
        return True, normalized
    return False, None


# Conservative, documented context-derivative rules (SP 800-63B-4
# explicitly permits context-specific words such as the service name and
# username, "and their derivatives"). This is intentionally a small, fixed
# rule set -- not an attempt to exhaustively enumerate every mangling a
# real attacker might try (that's the strength estimator's job).
_SUFFIXES = ("", "1", "12", "123", "1234", "!", "!!", "2024", "2025", "2026")


def build_context_blocklist(service_name: str, usernames: list[str]) -> frozenset[str]:
    terms: set[str] = set()
    for base in [service_name, *usernames]:
        if not base:
            continue
        variants = {
            base,
            base.replace(" ", ""),
            base.replace(" ", "-"),
            base.replace(" ", "_"),
        }
        for variant in variants:
            for suffix in _SUFFIXES:
                terms.add(normalize(variant + suffix))
    return frozenset(terms)


def check_context_blocklist(password: str, context_blocklist: frozenset[str]) -> tuple[bool, str | None]:
    return check_blocklist(password, context_blocklist)
