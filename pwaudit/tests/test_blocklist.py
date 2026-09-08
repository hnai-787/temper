from pwaudit.blocklist import (
    build_context_blocklist,
    check_blocklist,
    check_context_blocklist,
    load_blocklist,
)


def test_whole_password_exact_match_is_a_hit(tmp_path):
    blocklist_file = tmp_path / "blocklist.txt"
    blocklist_file.write_text("correct\npassword123\n", encoding="utf-8")
    blocklist = load_blocklist(blocklist_file)

    hit, match = check_blocklist("password123", blocklist)
    assert hit is True
    assert match == "password123"


def test_substring_containment_is_not_a_hit():
    """SP 800-63B-4 compares the WHOLE password, not substrings -- a
    password that merely contains a blocklisted word must not be
    flagged, per the research this was built from.
    """
    blocklist = frozenset({"correct"})
    hit, _ = check_blocklist("planet-correct-horse-staple", blocklist)
    assert hit is False


def test_matching_is_case_insensitive():
    blocklist = frozenset({"password123"})
    hit, match = check_blocklist("PaSSword123", blocklist)
    assert hit is True
    assert match == "password123"


def test_no_match_returns_false_and_none():
    blocklist = frozenset({"password123"})
    hit, match = check_blocklist("something-else-entirely", blocklist)
    assert hit is False
    assert match is None


def test_load_blocklist_skips_blank_lines_and_comments(tmp_path):
    blocklist_file = tmp_path / "blocklist.txt"
    blocklist_file.write_text("# a comment\n\npassword123\n   \nqwerty\n", encoding="utf-8")
    blocklist = load_blocklist(blocklist_file)
    assert blocklist == frozenset({"password123", "qwerty"})


def test_context_blocklist_includes_service_name_and_username_derivatives():
    context_blocklist = build_context_blocklist("Avionics University Portal", ["alice"])
    hit, _ = check_context_blocklist("alice123", context_blocklist)
    assert hit is True

    hit2, _ = check_context_blocklist("avionicsuniversityportal", context_blocklist)
    assert hit2 is True


def test_context_blocklist_does_not_flag_unrelated_passwords():
    context_blocklist = build_context_blocklist("Avionics University Portal", ["alice"])
    hit, _ = check_context_blocklist("correct-horse-battery-staple-example", context_blocklist)
    assert hit is False
