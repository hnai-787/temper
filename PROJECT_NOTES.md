# Project Notes

## Source

Migrated from `air-university-cybersecurity-projects/projects/hash-cracking-john-the-ripper`
into this workspace as an independent project on 2026-09-07.

## Cleanup decisions

None needed — the source material was already explicitly scoped to dummy
hashes with no real credentials.

## Assumptions

None.

## Remaining work

None identified.

## 2026-09-08: Added pwaudit (NIST SP 800-63B-4 password-policy & crack-resistance auditor)

### What changed and why

The original lab cracked one dummy MD5 hash with John the Ripper and a
CUPP wordlist -- real, but indistinguishable from thousands of identical
tutorials. The gap this fills: ground "is this password/policy actually
weak" in the current real standard (NIST SP 800-63B-4, finalized July
2025) and real breach data, and measure -- not assume -- the empirical
cost difference between hash formats. Full research grounding (the exact
current SS3.1.1/SS3.2.2 requirements, HIBP's real offline/k-anonymity
modes, why zxcvbn's guess-based model is preferred over LUDS character
-set entropy, John's four distinct rate counters) is in `pwaudit/README.md`.

### A real correction the research surfaced before any code was written

The brief for this project was drafted assuming the older SP 800-63B
8-character minimum. The final **SP 800-63B-4** (July 2025) actually
requires **15 characters** for a password used as the sole factor (8 only
applies within MFA). Built against the corrected numbers from the start
-- `SINGLE_FACTOR_MIN_LENGTH = 15` in `pwaudit/src/pwaudit/nist.py`.

### A real environment constraint, investigated rather than assumed away

This Windows machine has no native `john`; WSL2 Ubuntu has John 1.9.0,
but it's Ubuntu's **core (non-jumbo)** package -- confirmed by actually
running `john --list=formats` (unsupported: "Unknown option") and reading
`john`'s own usage text, which lists only
`descrypt/bsdicrypt/md5crypt/bcrypt/LM/AFS/tripcode/dummy/crypt`. No
Raw-MD5. Building jumbo from source needs `libssl-dev`/`zlib1g-dev` etc.,
but `sudo` in this WSL distro requires an interactive password this
session cannot supply -- confirmed via `sudo -n true` failing, not
assumed. Rather than fabricate a "Raw-MD5" result or silently substitute
something and call it the same thing, the empirical hash-cost comparison
uses **md5crypt vs. bcrypt** instead (both real, salted, legacy-vs-modern
schemes) and this substitution is documented in
`pwaudit/experiments/attack-manifest.yaml` and `pwaudit/README.md`.

A second, purely mechanical environment issue: passing multi-line
scripts to `wsl.exe` through this session's Bash tool silently broke
every `$(...)` command substitution after the first line (confirmed via
a minimal `X=$(echo hello)` reproduction), and separately Git Bash's
automatic POSIX-path rewriting mangled `/mnt/c/...` arguments meant for
the WSL side. Fixed by writing real script files
(`pwaudit/experiments/wsl-scripts/`) instead of inline multi-line
strings, and setting `MSYS2_ARG_CONV_EXCL="*"` for any command whose
arguments must reach WSL unmodified.

### Every empirical number in this project is real, not invented

- **HIBP breach counts** (`pwaudit/data/hibp-snapshot-2026-09-08.txt`):
  fetched live from `https://api.pwnedpasswords.com`'s real k-anonymity
  API on 2026-09-08 for this project's own synthetic dataset. Example:
  `123456` -> 210,461,208 real observed occurrences; every
  `legacy-composition` category password (e.g. `Summer2024!`,
  `Football1!`) is also a confirmed real hit despite satisfying
  upper/lower/digit/symbol rules -- see `pwaudit/data/README.md` for the
  full table. This is the empirical core of the project's central
  finding: composition-rule compliance and breach exposure are unrelated.
- **John the Ripper results** (`pwaudit/results/raw-captures/`): real
  `john` 1.9.0 runs in WSL2 Ubuntu. `Summer2024!` cracked instantly by a
  5-word custom wordlist (real g/s=50, p/s=250, c/s=250, C/s=250) but
  **not** cracked by John's own bundled 3559-word `password.lst` +
  `--rules` -- a genuine, slightly inconvenient finding (an old, small
  wordlist misses a plausible-looking modern password) reported as-is
  rather than smoothed over. A CSPRNG-random 24-character password was
  not cracked by 15 seconds of `--incremental=Alnum` brute force
  (right-censored, reported as `cracked: false,
  duration_limit_seconds: 15`, never as an extrapolated "years").
- **Hash-format throughput**: real `john --test=5` benchmarks on this
  machine -- md5crypt 49,462 c/s real vs. bcrypt (cost 5) 3,147 c/s real,
  a genuine ~15.7x throughput difference from one real benchmark run.

### Key engineering decisions and why

- **Never a combined score.** `AnalysisRecord` keeps NIST selection
  eligibility, HIBP exposure, zxcvbn guessability, and John results as
  separate fields, per the research's central methodological point
  (guessability != hash cost != breach exposure != policy compliance).
  Verified by an explicit test asserting no `security_score` or
  `nist_compliant` key ever appears in a report
  (`tests/test_analysis_and_report.py::test_report_never_emits_a_single_combined_score`).
- **Whole-password blocklist matching only, never substring.** SP
  800-63B-4 requires comparing the entire candidate, and Rev. 4
  specifically dropped the older draft's "reject if it contains a
  dictionary word" framing. Verified by a regression test asserting
  `planet-correct-horse-staple` does NOT fail the blocklist merely for
  containing `correct`.
- **`guesses`/`guesses_log10` as the primary strength output**, not
  zxcvbn's crack-time-in-seconds strings, because "seconds" additionally
  assumes a hash algorithm/cost/hardware -- exactly the part this project
  measures empirically via John instead of modeling.
- **Two independent NIST outputs, never merged**: `assess_selection`
  (would a policy accept this one candidate) vs. `audit_verifier_policy`
  (does a policy configuration meet the SHALL/SHOULD requirements) --
  because a password string is never itself "NIST compliant"; only a
  verifier's behavior can be.

### Verification performed

46 pytest tests pass, all without requiring a John installation (the
parser is tested entirely against real captured fixtures). One
additional integration test (`test_john_runner_integration.py`), gated
behind `PWAUDIT_JOHN_CMD`, was actually run against real WSL John and
passed. Ruff reports zero issues. `pwaudit analyze` was actually run
end-to-end over the frozen 26-password dataset, producing
`results/password-analysis.md`/`.json` (committed as real evidence, not
regenerated-on-claim).

### Remaining work / honest limitations

See `pwaudit/README.md` "Limitations" -- notably: the 26-password/5
-category fixture set is smaller than the research's suggested 10-20 per
category (a deliberate portfolio-scope decision, documented as such
rather than silently reduced); the HIBP snapshot is an 11-row
single-lookup sample, not the full corpus; the empirical hash-cost
comparison substitutes md5crypt for Raw-MD5 due to the jumbo-build/sudo
constraint above.
