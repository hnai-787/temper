import pytest

from pwaudit.nist import assess_selection, audit_verifier_policy, minimum_length_for


def test_single_factor_minimum_is_15():
    assert minimum_length_for("single_factor") == 15


def test_mfa_minimum_is_8():
    assert minimum_length_for("mfa") == 8


def test_unknown_auth_context_rejected():
    with pytest.raises(ValueError):
        minimum_length_for("something_else")


@pytest.mark.parametrize(
    "auth_context,length,expected_ok",
    [
        ("single_factor", 14, False),
        ("single_factor", 15, True),
        ("mfa", 7, False),
        ("mfa", 8, True),
    ],
)
def test_length_boundaries(auth_context, length, expected_ok):
    password = "a" * length
    result = assess_selection(password, auth_context, (False, None), (False, None))
    assert result.length_ok is expected_ok


def test_blocklist_hit_makes_selection_unacceptable_even_if_length_ok():
    password = "a" * 20
    result = assess_selection(password, "single_factor", (True, "a" * 20), (False, None))
    assert result.length_ok is True
    assert result.blocklist_hit is True
    assert result.selection_acceptable is False


def test_context_blocklist_hit_makes_selection_unacceptable():
    password = "a" * 20
    result = assess_selection(password, "single_factor", (False, None), (True, "match"))
    assert result.selection_acceptable is False


def _base_policy(**overrides):
    policy = {
        "auth_context": "single_factor",
        "minimum_length": 15,
        "maximum_length_supported": 128,
        "composition_rules": False,
        "periodic_rotation": False,
        "truncates_password": False,
        "password_manager_autofill": True,
        "paste_allowed": True,
        "blocklist": {"enabled": True},
        "rate_limit": {"enabled": True, "max_consecutive_failures": 10},
    }
    policy.update(overrides)
    return policy


def test_conformant_policy_passes_every_finding():
    result = audit_verifier_policy(_base_policy())
    assert result.overall_status == "pass"
    assert all(f.status == "pass" for f in result.findings)


def test_composition_rules_enabled_is_a_shall_failure():
    result = audit_verifier_policy(_base_policy(composition_rules=True))
    finding = next(f for f in result.findings if f.requirement_id == "3.1.1-composition")
    assert finding.status == "fail"
    assert result.overall_status == "fail"


def test_periodic_rotation_enabled_is_a_shall_failure():
    result = audit_verifier_policy(_base_policy(periodic_rotation=True))
    finding = next(f for f in result.findings if f.requirement_id == "3.1.1-rotation")
    assert finding.status == "fail"


def test_max_supported_length_below_64_is_a_should_failure():
    result = audit_verifier_policy(_base_policy(maximum_length_supported=32))
    finding = next(f for f in result.findings if f.requirement_id == "3.1.1-max-length")
    assert finding.status == "fail"


def test_blocklist_disabled_is_a_shall_failure():
    result = audit_verifier_policy(_base_policy(blocklist={"enabled": False}))
    finding = next(f for f in result.findings if f.requirement_id == "3.1.1-blocklist")
    assert finding.status == "fail"


def test_rate_limit_over_100_is_a_shall_failure():
    result = audit_verifier_policy(_base_policy(rate_limit={"enabled": True, "max_consecutive_failures": 500}))
    finding = next(f for f in result.findings if f.requirement_id == "3.2.2-throttling")
    assert finding.status == "fail"


def test_rate_limit_at_100_passes_the_upper_bound():
    result = audit_verifier_policy(_base_policy(rate_limit={"enabled": True, "max_consecutive_failures": 100}))
    finding = next(f for f in result.findings if f.requirement_id == "3.2.2-throttling")
    assert finding.status == "pass"


def test_mfa_context_uses_the_lower_minimum():
    result = audit_verifier_policy(_base_policy(auth_context="mfa", minimum_length=8))
    finding = next(f for f in result.findings if f.requirement_id == "3.1.1-length")
    assert finding.status == "pass"
