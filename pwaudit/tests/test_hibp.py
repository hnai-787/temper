import hashlib

from pwaudit.hibp import check_offline, load_offline_corpus, sha1_hex


def test_sha1_hex_matches_hashlib_uppercase():
    assert sha1_hex("password") == hashlib.sha1(b"password").hexdigest().upper()


def test_load_offline_corpus_parses_hash_count_lines(tmp_path):
    corpus_file = tmp_path / "corpus.txt"
    digest = sha1_hex("password")
    corpus_file.write_text(f"{digest}:52372427\nDEADBEEF00000000000000000000000000000000:5\n", encoding="utf-8")

    corpus = load_offline_corpus(corpus_file)
    assert corpus[digest] == 52372427
    assert corpus["DEADBEEF00000000000000000000000000000000"] == 5


def test_check_offline_reports_found_with_count(tmp_path):
    corpus_file = tmp_path / "corpus.txt"
    digest = sha1_hex("password")
    corpus_file.write_text(f"{digest}:52372427\n", encoding="utf-8")
    corpus = load_offline_corpus(corpus_file)

    result = check_offline("password", corpus, snapshot_date="2026-09-08")
    assert result.checked is True
    assert result.mode == "offline"
    assert result.found is True
    assert result.prevalence_count == 52372427
    assert result.corpus_snapshot_date == "2026-09-08"


def test_check_offline_reports_not_found(tmp_path):
    corpus_file = tmp_path / "corpus.txt"
    corpus_file.write_text(f"{sha1_hex('password')}:1\n", encoding="utf-8")
    corpus = load_offline_corpus(corpus_file)

    result = check_offline("correct-horse-battery-staple-example", corpus, snapshot_date="2026-09-08")
    assert result.found is False
    assert result.prevalence_count is None
