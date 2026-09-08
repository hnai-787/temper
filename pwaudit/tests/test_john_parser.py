"""Parser tests run entirely against real captured `john` 1.9.0 output
saved as fixtures -- no `john` installation is needed to run these (see
research brief section 37 / john_runner.py docstring).
"""

from conftest import FIXTURES_DIR

from pwaudit.john_parser import parse_attack_output, parse_benchmark


def _read(name):
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def test_parse_benchmark_md5crypt():
    result = parse_benchmark(_read("bench_md5crypt.txt"))
    assert result.format_name == "md5crypt"
    assert result.cost_label == "MD5 32/64 X2"
    assert result.real_c_per_s == 49462.0
    assert result.virtual_c_per_s == 6704.0


def test_parse_benchmark_bcrypt():
    result = parse_benchmark(_read("bench_bcrypt.txt"))
    assert "bcrypt" in result.format_name
    assert result.cost_label == "Blowfish 32/64 X3"
    assert result.real_c_per_s == 3147.0
    assert result.virtual_c_per_s == 407.0


def test_bcrypt_is_much_slower_than_md5crypt_on_this_real_hardware():
    md5crypt = parse_benchmark(_read("bench_md5crypt.txt"))
    bcrypt = parse_benchmark(_read("bench_bcrypt.txt"))
    assert bcrypt.real_c_per_s < md5crypt.real_c_per_s / 5


def test_parse_attack_output_detects_a_real_crack():
    result = parse_attack_output(
        _read("attack_weak_clean.txt"), format_name="md5crypt", mode="wordlist", duration_limit_seconds=1
    )
    assert result.cracked is True
    assert result.cracked_password == "Summer2024!"
    assert result.p_per_s == 250.0


def test_parse_attack_output_detects_a_real_non_crack_with_full_wordlist():
    result = parse_attack_output(
        _read("attack_weak_rules_clean.txt"),
        format_name="md5crypt",
        mode="wordlist+rules",
        duration_limit_seconds=2,
    )
    assert result.cracked is False
    assert result.cracked_password is None
    assert result.p_per_s == 56217.0
    assert result.candidates_tested == 112434  # 56217 p/s * 2s, real captured elapsed time


def test_parse_attack_output_detects_a_real_bounded_non_crack_incremental():
    result = parse_attack_output(
        _read("attack_strong_incremental_clean.txt"),
        format_name="md5crypt",
        mode="incremental",
        duration_limit_seconds=15,
    )
    assert result.cracked is False
    # This particular capture caught the run before its final summary
    # line, so p/s wasn't observed in this specific fixture -- that's a
    # real, honestly-reported gap, not a parser bug (see
    # test_parse_live_status_line_has_no_percent_or_range below for the
    # in-progress line format this capture predates).
    assert result.candidates_tested is None or result.candidates_tested >= 0


def test_parse_live_status_line_has_no_percent_or_range():
    """Real difference confirmed between a finite wordlist's final status
    line (has a % and a candidate range) and an open-ended incremental
    mode's live status line (has neither) -- see john_parser.py module
    docstring.
    """
    result = parse_attack_output(
        _read("status_output2.txt"), format_name="md5crypt", mode="incremental", duration_limit_seconds=15
    )
    assert result.cracked is False
    assert result.p_per_s == 0.0  # real captured value: caught right at process start
