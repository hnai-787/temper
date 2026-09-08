"""Parse real John the Ripper output (never invented from memory).

Every regex here was written against actual captured output from a real
`john` 1.9.0 run (see `results/raw-captures/` and `tests/fixtures/`), not
guessed from documentation. Two output shapes matter and are NOT
interchangeable (see module docs in `models.py`):

- A benchmark line (`--test`): `Raw: N c/s real, M c/s virtual` --
  isolates hash-format throughput on this machine. Use for "how
  expensive is this hash format" comparisons (Experiment A).
- A status line (end-of-run or `--status`): `Ng H:MM:SS[:SS] [P%] G g/s
  P p/s C c/s CC C/s [range]` -- four DIFFERENT rate counters (g/s
  successful guesses/s, p/s candidates tested/s, c/s hash computations/s,
  C/s candidate*hash combinations/s). The trailing `%` and candidate
  `range` only appear for finite candidate sources (wordlist); they are
  absent for open-ended modes like `--incremental` (confirmed by
  comparing real captures of both).
"""

from __future__ import annotations

import re

from .models import JohnAttackResult, JohnBenchmarkResult

_BENCHMARK_RE = re.compile(
    r"Benchmarking:\s*(?P<name>.+?)\s*\[(?P<cost>[^\]]+)\]\.\.\.\s*DONE.*?"
    r"Raw:\s*(?P<real>[\d,]+)\s*c/s real(?:,\s*(?P<virtual>[\d,]+)\s*c/s virtual)?",
    re.DOTALL,
)

_STATUS_LINE_RE = re.compile(
    r"^(?P<guesses>\d+)g\s+"
    r"(?P<time>\d+:\d{2}:\d{2}(?::\d{2})?)\s+"
    r"(?:(?P<pct>\d+)%\s+)?"
    r"(?P<gs>[\d.]+)g/s\s+"
    r"(?P<ps>[\d.]+)p/s\s+"
    r"(?P<cs>[\d.]+)c/s\s+"
    r"(?P<Cs>[\d.]+)C/s"
    r"(?:\s+(?P<range>\S+\.\.\S+))?\s*$",
    re.MULTILINE,
)

_CRACKED_LINE_RE = re.compile(r"^(?P<password>.+?)\s{2,}\((?P<username>[^)]+)\)\s*$", re.MULTILINE)


def _parse_time_to_seconds(time_str: str) -> float:
    parts = [int(p) for p in time_str.split(":")]
    while len(parts) < 4:
        parts.insert(0, 0)
    days, hours, minutes, seconds = parts
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def parse_benchmark(text: str, john_version: str | None = None) -> JohnBenchmarkResult:
    match = _BENCHMARK_RE.search(text)
    if match is None:
        raise ValueError(f"could not find a benchmark line in john output:\n{text}")

    return JohnBenchmarkResult(
        format_name=match.group("name"),
        cost_label=match.group("cost"),
        real_c_per_s=float(match.group("real").replace(",", "")),
        virtual_c_per_s=float(match.group("virtual").replace(",", "")) if match.group("virtual") else None,
        john_version=john_version,
    )


def parse_attack_output(
    text: str,
    format_name: str,
    mode: str,
    duration_limit_seconds: float,
) -> JohnAttackResult:
    cracked_match = _CRACKED_LINE_RE.search(text)
    cracked = cracked_match is not None
    cracked_password = cracked_match.group("password") if cracked_match else None

    status_matches = list(_STATUS_LINE_RE.finditer(text))
    elapsed_seconds = None
    p_per_s = None
    candidates_tested = None

    if status_matches:
        # The last status line in the captured output is the final/most
        # recent one -- for a completed run that's the summary line, for
        # a mid-run --status capture there's exactly one.
        last = status_matches[-1]
        elapsed_seconds = _parse_time_to_seconds(last.group("time"))
        p_per_s = float(last.group("ps"))
        if elapsed_seconds is not None and p_per_s is not None:
            candidates_tested = round(p_per_s * elapsed_seconds)

    return JohnAttackResult(
        format_name=format_name,
        mode=mode,
        duration_limit_seconds=duration_limit_seconds,
        cracked=cracked,
        elapsed_seconds=elapsed_seconds,
        candidates_tested=candidates_tested,
        p_per_s=p_per_s,
        cracked_password=cracked_password,
    )
