"""pwaudit CLI: policy audit, password analysis, and reporting."""

from __future__ import annotations

import argparse
import sys

from .analysis import analyze_dataset, load_policy
from .nist import audit_verifier_policy
from .report import records_to_json, records_to_markdown


def _cmd_policy_audit(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy_file)
    result = audit_verifier_policy(policy)

    print(f"Standard: {result.standard}")
    print(f"Overall: {result.overall_status.upper()}")
    print()
    for finding in result.findings:
        print(f"[{finding.status.upper():4}] {finding.requirement_id}: {finding.description}")
        print(f"       {finding.detail}")
    print()
    print("Not assessed:")
    for item in result.not_assessed:
        print(f"  - {item}")

    return 0 if result.overall_status == "pass" else 1


def _cmd_analyze(args: argparse.Namespace) -> int:
    records = analyze_dataset(args.experiment_file)

    verifier_policy = None
    if args.policy_file:
        verifier_policy = audit_verifier_policy(load_policy(args.policy_file))

    if args.format == "json":
        output = records_to_json(records, verifier_policy)
    else:
        output = records_to_markdown(records, verifier_policy)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"wrote {args.output}")
    else:
        print(output)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pwaudit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_policy = sub.add_parser("policy-audit", help="audit a verifier policy against NIST SP 800-63B-4")
    p_policy.add_argument("policy_file")
    p_policy.set_defaults(func=_cmd_policy_audit)

    p_analyze = sub.add_parser("analyze", help="run the full analysis pipeline over a dataset")
    p_analyze.add_argument("experiment_file")
    p_analyze.add_argument("--policy-file", help="also audit this verifier policy and include it in the report")
    p_analyze.add_argument("--format", choices=["json", "markdown"], default="json")
    p_analyze.add_argument("--output", "-o")
    p_analyze.set_defaults(func=_cmd_analyze)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
