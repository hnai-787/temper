import json

from conftest import REPO_ROOT

from pwaudit.analysis import analyze_dataset, load_policy
from pwaudit.nist import audit_verifier_policy
from pwaudit.report import records_to_json, records_to_markdown


def _records():
    return analyze_dataset(REPO_ROOT / "experiments" / "experiment.yaml")


def test_analyze_dataset_produces_one_record_per_password():
    records = _records()
    assert len(records) == 26  # 5 per category A-E + 1 extra E06, see dataset file


def test_common_breached_passwords_are_all_hibp_hits():
    records = {r.id: r for r in _records()}
    for pw_id in ("A01", "A02", "A03", "A04", "A05"):
        assert records[pw_id].hibp.found is True, f"{pw_id} should be a real HIBP hit"


def test_legacy_composition_category_is_the_central_finding():
    """The core empirical point: composition-rule compliance and breach
    exposure are unrelated -- every legacy-composition password in this
    real dataset both satisfies the legacy rule AND is a real HIBP hit.
    """
    records = [r for r in _records() if r.category == "legacy-composition"]
    assert len(records) == 5
    assert all(r.legacy_complexity_pass for r in records)
    assert all(r.hibp.found for r in records)
    # And none of them meet the current NIST single-factor length floor.
    assert all(not r.nist_selection.length_ok for r in records)


def test_random_generated_passwords_are_not_hibp_hits():
    records = {r.id: r for r in _records()}
    for pw_id in ("E01", "E02", "E03", "E04", "E05", "E06"):
        assert records[pw_id].hibp.found is False


def test_b02_has_real_john_attack_results_attached():
    records = {r.id: r for r in _records()}
    b02 = records["B02"]
    assert len(b02.john_attacks) == 2
    modes = {a.mode: a.cracked for a in b02.john_attacks}
    assert modes["wordlist"] is True
    assert modes["wordlist+rules"] is False


def test_report_never_emits_a_single_combined_score():
    output = records_to_json(_records())
    assert "security_score" not in output
    assert "nist_compliant" not in output


def test_json_report_is_valid_json_with_expected_top_level_keys():
    policy = audit_verifier_policy(load_policy(REPO_ROOT / "experiments" / "policy-nist-conformant.yaml"))
    output = records_to_json(_records(), policy)
    parsed = json.loads(output)
    assert parsed["standard"] == "NIST SP 800-63B-4"
    assert "not_assessed" in parsed
    assert len(parsed["passwords"]) == 26


def test_markdown_report_includes_verifier_policy_and_per_password_table():
    policy = audit_verifier_policy(load_policy(REPO_ROOT / "experiments" / "policy-nist-conformant.yaml"))
    output = records_to_markdown(_records(), policy)
    assert "Verifier Policy Audit" in output
    assert "Per-Password Analysis" in output
    assert "B02" in output
