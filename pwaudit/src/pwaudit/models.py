"""Result dataclasses.

Deliberately kept as separate dimensions rather than one combined score
(see the research this was built from, and PROJECT_NOTES.md): guessability,
breach exposure, hash cost, and policy compliance answer different
questions and are never collapsed into a single number here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NistSelectionResult:
    """Per-password selection-time assessment (SP 800-63B-4 SS3.1.1)."""

    auth_context: str  # "single_factor" | "mfa"
    minimum_length_required: int
    length: int
    length_ok: bool
    blocklist_hit: bool
    blocklist_match: str | None
    context_blocklist_hit: bool
    context_blocklist_match: str | None
    selection_acceptable: bool


@dataclass(frozen=True)
class NistVerifierPolicyFinding:
    requirement_id: str
    description: str
    status: str  # "pass" | "fail" | "not_assessed"
    detail: str


@dataclass(frozen=True)
class NistVerifierPolicyResult:
    standard: str
    findings: tuple[NistVerifierPolicyFinding, ...]
    not_assessed: tuple[str, ...]

    @property
    def overall_status(self) -> str:
        return "fail" if any(f.status == "fail" for f in self.findings) else "pass"


@dataclass(frozen=True)
class HibpResult:
    checked: bool
    mode: str  # "offline" | "k-anonymity" | "not_checked"
    found: bool
    prevalence_count: int | None
    corpus_snapshot_date: str | None


@dataclass(frozen=True)
class StrengthEstimate:
    estimated_guesses: float
    estimated_guesses_log10: float
    pattern_summary: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class JohnBenchmarkResult:
    format_name: str
    cost_label: str
    real_c_per_s: float
    virtual_c_per_s: float | None
    john_version: str | None = None


@dataclass(frozen=True)
class JohnAttackResult:
    format_name: str
    mode: str  # "wordlist" | "wordlist+rules" | ...
    duration_limit_seconds: float
    cracked: bool
    elapsed_seconds: float | None
    candidates_tested: int | None
    p_per_s: float | None
    cracked_password: str | None = None


@dataclass(frozen=True)
class AnalysisRecord:
    """One password's full, dimension-separated analysis."""

    id: str
    category: str
    length: int
    legacy_complexity_pass: bool
    nist_selection: NistSelectionResult
    hibp: HibpResult
    strength: StrengthEstimate
    john_attacks: tuple[JohnAttackResult, ...] = field(default_factory=tuple)
