"""Orchestrates the four independent measurement dimensions into one
AnalysisRecord per password, without ever collapsing them into a single
score (see models.py / README.md "Design decisions").
"""

from __future__ import annotations

from pathlib import Path

import yaml

from . import blocklist as blocklist_mod
from . import hibp as hibp_mod
from . import john_parser
from . import nist as nist_mod
from . import strength as strength_mod
from .models import AnalysisRecord, JohnAttackResult


# A conservative, explicit approximation of "legacy composition rule
# compliance" (upper + lower + digit + symbol, length >= 8) purely for
# classifying this project's own fixture set -- NOT a recommended real
# -world check, and never mixed with the NIST SS3.1.1 assessment above,
# which explicitly forbids requiring composition rules.
def legacy_complexity_pass(password: str) -> bool:
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return len(password) >= 8 and has_upper and has_lower and has_digit and has_symbol


def load_dataset(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data["passwords"]


def load_policy(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_attack_manifest(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_john_results_by_password_id(manifest_path: str | Path, base_dir: Path) -> dict[str, list[JohnAttackResult]]:
    manifest = load_attack_manifest(manifest_path)
    results: dict[str, list[JohnAttackResult]] = {}

    for attack in manifest.get("attacks", []):
        capture_path = base_dir / attack["capture_file"]
        text = capture_path.read_text(encoding="utf-8")
        result = john_parser.parse_attack_output(
            text,
            format_name=attack["format"],
            mode=attack["mode"],
            duration_limit_seconds=attack["duration_limit_seconds"],
        )
        results.setdefault(attack["password_id"], []).append(result)

    return results


def analyze_dataset(experiment_path: str | Path) -> list[AnalysisRecord]:
    experiment_path = Path(experiment_path)
    base_dir = experiment_path.parent
    experiment = load_policy(experiment_path)

    dataset = load_dataset(base_dir / experiment["dataset_file"])
    auth_context = experiment["selection_policy"]["auth_context"]

    common_blocklist = blocklist_mod.load_blocklist(base_dir / experiment["blocklist_file"])
    context = experiment.get("context", {})
    context_blocklist = blocklist_mod.build_context_blocklist(
        context.get("service_name", ""), context.get("usernames", [])
    )

    compromise_cfg = experiment.get("compromise_check", {})
    hibp_corpus = None
    snapshot_date = compromise_cfg.get("snapshot_date")
    if compromise_cfg.get("mode") == "offline":
        hibp_corpus = hibp_mod.load_offline_corpus(base_dir / compromise_cfg["corpus_file"])

    john_by_id: dict[str, list[JohnAttackResult]] = {}
    if "attack_manifest_file" in experiment:
        john_by_id = build_john_results_by_password_id(base_dir / experiment["attack_manifest_file"], base_dir)

    records: list[AnalysisRecord] = []
    for entry in dataset:
        password = entry["password"]

        blk_hit = blocklist_mod.check_blocklist(password, common_blocklist)
        ctx_hit = blocklist_mod.check_context_blocklist(password, context_blocklist)
        selection = nist_mod.assess_selection(password, auth_context, blk_hit, ctx_hit)

        if hibp_corpus is not None:
            hibp_result = hibp_mod.check_offline(password, hibp_corpus, snapshot_date)
        else:
            from .models import HibpResult

            hibp_result = HibpResult(checked=False, mode="not_checked", found=False, prevalence_count=None, corpus_snapshot_date=None)

        strength = strength_mod.estimate_strength(password)

        records.append(
            AnalysisRecord(
                id=entry["id"],
                category=entry["category"],
                length=len(password),
                legacy_complexity_pass=legacy_complexity_pass(password),
                nist_selection=selection,
                hibp=hibp_result,
                strength=strength,
                john_attacks=tuple(john_by_id.get(entry["id"], [])),
            )
        )

    return records
