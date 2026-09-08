"""JSON and Markdown report generation.

Never emits a single combined "score" or a bare `nist_compliant: true`
-- see models.py and nist.py module docstrings for why.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import AnalysisRecord, NistVerifierPolicyResult


def records_to_json(records: list[AnalysisRecord], verifier_policy: NistVerifierPolicyResult | None = None) -> str:
    payload = {
        "standard": "NIST SP 800-63B-4",
        "coverage": [
            "3.1.1 password length",
            "3.1.1 composition rules",
            "3.1.1 periodic rotation",
            "3.1.1 blocklisting",
            "3.1.1 password manager / paste support",
            "3.2.2 throttling",
        ],
        "not_assessed": list(verifier_policy.not_assessed) if verifier_policy else [],
        "verifier_policy": asdict(verifier_policy) if verifier_policy else None,
        "passwords": [asdict(r) for r in records],
    }
    return json.dumps(payload, indent=2, default=str)


def _fmt_log10(value: float) -> str:
    return f"{value:.2f}"


def records_to_markdown(records: list[AnalysisRecord], verifier_policy: NistVerifierPolicyResult | None = None) -> str:
    lines: list[str] = []
    lines.append("# Password Policy & Crack-Resistance Report")
    lines.append("")
    lines.append("Standard: **NIST SP 800-63B-4**. This report separates four independent ")
    lines.append("measurement dimensions (standards selection eligibility, breach exposure, ")
    lines.append("modeled guessability, and empirical John the Ripper results) and never ")
    lines.append("combines them into one score. See PROJECT_NOTES.md for methodology.")
    lines.append("")

    if verifier_policy is not None:
        lines.append("## Verifier Policy Audit")
        lines.append("")
        lines.append(f"Overall: **{verifier_policy.overall_status.upper()}**")
        lines.append("")
        lines.append("| Requirement | Status | Detail |")
        lines.append("|---|---|---|")
        for finding in verifier_policy.findings:
            lines.append(f"| {finding.description} | {finding.status} | {finding.detail} |")
        lines.append("")
        lines.append("Not assessed by this tool: " + "; ".join(verifier_policy.not_assessed))
        lines.append("")

    lines.append("## Per-Password Analysis")
    lines.append("")
    lines.append(
        "| ID | Category | Length | Legacy complexity | NIST selection | HIBP | log10(guesses) | John |"
    )
    lines.append("|---|---|---:|---|---|---|---:|---|")
    for r in records:
        nist_ok = "pass" if r.nist_selection.selection_acceptable else "fail"
        if r.hibp.checked and r.hibp.found:
            hibp_str = f"found ({r.hibp.prevalence_count:,})"
        elif r.hibp.checked:
            hibp_str = "not found"
        else:
            hibp_str = "not checked"

        if r.john_attacks:
            john_str = "; ".join(
                f"{a.mode}:{'cracked' if a.cracked else 'not cracked'}" for a in r.john_attacks
            )
        else:
            john_str = "—"

        lines.append(
            f"| {r.id} | {r.category} | {r.length} | "
            f"{'pass' if r.legacy_complexity_pass else 'fail'} | {nist_ok} | {hibp_str} | "
            f"{_fmt_log10(r.strength.estimated_guesses_log10)} | {john_str} |"
        )

    lines.append("")
    lines.append("## Category Summary (demonstrations on this controlled fixture set only)")
    lines.append("")
    lines.append(
        "Small, deliberately constructed sample -- not a claim of statistical "
        "population-level significance. See the cited literature in README.md for that."
    )
    lines.append("")
    lines.append("| Category | Median log10(guesses) | HIBP hit rate | Legacy-complexity pass rate |")
    lines.append("|---|---:|---:|---:|")

    categories: dict[str, list[AnalysisRecord]] = {}
    for r in records:
        categories.setdefault(r.category, []).append(r)

    for category, items in categories.items():
        log10s = sorted(item.strength.estimated_guesses_log10 for item in items)
        median = log10s[len(log10s) // 2] if len(log10s) % 2 == 1 else (log10s[len(log10s) // 2 - 1] + log10s[len(log10s) // 2]) / 2
        hit_rate = sum(1 for item in items if item.hibp.checked and item.hibp.found) / len(items)
        complexity_rate = sum(1 for item in items if item.legacy_complexity_pass) / len(items)
        lines.append(f"| {category} | {median:.2f} | {hit_rate:.0%} | {complexity_rate:.0%} |")

    lines.append("")
    return "\n".join(lines)
