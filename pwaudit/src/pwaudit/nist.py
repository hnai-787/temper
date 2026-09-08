"""NIST SP 800-63B-4 (final, July 2025) password checks.

Scope boundary -- read this before using either function below. SP
800-63B-4 SS3.1.1/SS3.2.2 specify verifier/CSP behavior, not a property of
a single password string. A password is not "NIST compliant"; a
*verifier's policy* either does or doesn't implement the SHALL/SHOULD
requirements. This module therefore produces two distinct things and
never merges them:

1. `assess_selection` -- "would this verifier's configured policy accept
   this candidate password, in this auth context". This is a
   *selection-time* check, not a compliance certificate.
2. `audit_verifier_policy` -- an audit of a *verifier configuration*
   against the normative SHALL/SHOULD requirements. This is the only
   level that can meaningfully report "pass"/"fail" against the standard,
   and even then only for the requirements this tool actually checks
   (see NistVerifierPolicyResult.not_assessed).

Never emit a bare `nist_compliant: true` anywhere downstream of this
module -- see report.py.
"""

from __future__ import annotations

from .models import (
    NistSelectionResult,
    NistVerifierPolicyFinding,
    NistVerifierPolicyResult,
)

SINGLE_FACTOR_MIN_LENGTH = 15
MFA_MIN_LENGTH = 8
RECOMMENDED_MAX_LENGTH = 64
# SS3.2.2: 100 consecutive failed attempts is an explicit UPPER BOUND after
# which the authenticator must be disabled -- not a recommended target.
RATE_LIMIT_UPPER_BOUND = 100


def minimum_length_for(auth_context: str) -> int:
    if auth_context == "single_factor":
        return SINGLE_FACTOR_MIN_LENGTH
    if auth_context == "mfa":
        return MFA_MIN_LENGTH
    raise ValueError(f"unknown auth_context: {auth_context!r} (expected 'single_factor' or 'mfa')")


def assess_selection(
    password: str,
    auth_context: str,
    blocklist_hit: tuple[bool, str | None],
    context_blocklist_hit: tuple[bool, str | None],
) -> NistSelectionResult:
    min_length = minimum_length_for(auth_context)
    length = len(password)
    length_ok = length >= min_length
    blk_hit, blk_match = blocklist_hit
    ctx_hit, ctx_match = context_blocklist_hit

    return NistSelectionResult(
        auth_context=auth_context,
        minimum_length_required=min_length,
        length=length,
        length_ok=length_ok,
        blocklist_hit=blk_hit,
        blocklist_match=blk_match,
        context_blocklist_hit=ctx_hit,
        context_blocklist_match=ctx_match,
        selection_acceptable=length_ok and not blk_hit and not ctx_hit,
    )


def audit_verifier_policy(policy: dict) -> NistVerifierPolicyResult:
    findings: list[NistVerifierPolicyFinding] = []

    auth_context = policy["auth_context"]
    min_len = policy["minimum_length"]
    required = minimum_length_for(auth_context)
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-length",
            description=f"Minimum length SHALL be >= {required} for auth_context={auth_context}",
            status="pass" if min_len >= required else "fail",
            detail=f"configured minimum_length={min_len}",
        )
    )

    max_len = policy.get("maximum_length_supported")
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-max-length",
            description=f"Maximum supported length SHOULD be >= {RECOMMENDED_MAX_LENGTH}",
            status="pass" if (max_len or 0) >= RECOMMENDED_MAX_LENGTH else "fail",
            detail=f"configured maximum_length_supported={max_len}",
        )
    )

    composition = policy.get("composition_rules", False)
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-composition",
            description="Verifiers SHALL NOT require composition rules (mixed character types)",
            status="fail" if composition else "pass",
            detail=f"configured composition_rules={composition}",
        )
    )

    rotation = policy.get("periodic_rotation", False)
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-rotation",
            description="Verifiers SHALL NOT require periodic forced rotation absent evidence of compromise",
            status="fail" if rotation else "pass",
            detail=f"configured periodic_rotation={rotation}",
        )
    )

    truncation = policy.get("truncates_password", False)
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-truncation",
            description="Verifiers SHALL NOT truncate the password before verification",
            status="fail" if truncation else "pass",
            detail=f"configured truncates_password={truncation}",
        )
    )

    blocklist = policy.get("blocklist", {})
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-blocklist",
            description="Verifiers SHALL compare the whole prospective password against a blocklist "
            "of commonly-used, expected, or compromised values",
            status="pass" if blocklist.get("enabled") else "fail",
            detail=f"configured blocklist.enabled={blocklist.get('enabled')}",
        )
    )

    manager = policy.get("password_manager_autofill", False)
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-pwd-manager",
            description="Verifiers SHALL permit password manager / autofill input",
            status="pass" if manager else "fail",
            detail=f"configured password_manager_autofill={manager}",
        )
    )

    paste = policy.get("paste_allowed", False)
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.1.1-paste",
            description="Verifiers SHOULD permit pasting into the password field",
            status="pass" if paste else "fail",
            detail=f"configured paste_allowed={paste}",
        )
    )

    rate_limit = policy.get("rate_limit", {})
    rl_enabled = rate_limit.get("enabled", False)
    rl_max = rate_limit.get("max_consecutive_failures")
    rl_ok = bool(rl_enabled) and rl_max is not None and rl_max <= RATE_LIMIT_UPPER_BOUND
    findings.append(
        NistVerifierPolicyFinding(
            requirement_id="3.2.2-throttling",
            description=f"Verifiers SHALL rate-limit failed attempts "
            f"(<= {RATE_LIMIT_UPPER_BOUND} consecutive failures is an upper bound, not a recommended target)",
            status="pass" if rl_ok else "fail",
            detail=f"configured rate_limit={rate_limit}",
        )
    )

    not_assessed = (
        "FIPS validation of cryptographic modules",
        "authenticated protected channel (e.g. TLS) for the verifier",
        "full AAL (Authenticator Assurance Level) architecture",
        "password storage salt/hash scheme (a verifier storage audit, distinct from this policy audit)",
    )

    return NistVerifierPolicyResult(
        standard="NIST SP 800-63B-4",
        findings=tuple(findings),
        not_assessed=not_assessed,
    )
