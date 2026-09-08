"""Adapter/schema sanity checks for the zxcvbn wrapper.

Deliberately does NOT pin exact upstream numerical scores (per the
research this was built from) -- zxcvbn's own scoring can change between
versions. These tests check the shape of pwaudit's output and a few
qualitative, extremely-unlikely-to-flip relationships instead.
"""

from pwaudit.strength import estimate_strength


def test_returns_expected_shape():
    result = estimate_strength("correct-horse-battery-staple-example")
    assert result.estimated_guesses > 0
    assert isinstance(result.estimated_guesses_log10, float)
    assert isinstance(result.pattern_summary, tuple)


def test_common_password_scores_far_below_a_long_random_one():
    weak = estimate_strength("password1")
    strong = estimate_strength("h=bZK#c-czC&-fXs0GjN")
    assert weak.estimated_guesses_log10 < strong.estimated_guesses_log10


def test_composition_rule_compliant_password_can_still_score_low():
    """The central point this project demonstrates: satisfying legacy
    composition rules (upper/lower/digit/symbol) does not imply high
    guess resistance.
    """
    result = estimate_strength("Password1!")
    assert result.estimated_guesses_log10 < 6  # well under a million guesses
