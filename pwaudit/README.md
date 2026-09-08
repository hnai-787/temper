# pwaudit

A password-security laboratory that measures four genuinely different
things about a password and never combines them into one score:

```text
NIST SP 800-63B-4 selection eligibility   <- would a compliant verifier accept it?
HIBP breach exposure                       <- has this exact password leaked?
zxcvbn pattern-aware guessability          <- how many guesses would a smart attacker need?
John the Ripper empirical results          <- what did a real, bounded attack actually achieve?
```

Built from (and grounded throughout in) real published standards and
research -- see "References" below. Not named "hash cracker": that's
one of its four measurements, not its product.

## Why this exists

The original lab cracked one dummy MD5 hash with John the Ripper and a
CUPP wordlist. That demonstrates a tool exists; it doesn't demonstrate
*why* a password is weak, in terms an engineer building a real login
system could act on. This rebuild keeps John the Ripper as one real
measurement dimension among four, grounds the "is this policy any good"
question in the actual current NIST standard, and uses real breach data
(the live HIBP API, not an invented list) throughout.

## Scope boundary — read this first

**SP 800-63B-4 describes verifier/CSP behavior, not a property of a
password string.** This tool never emits `nist_compliant: true` for a
password. It produces two distinct, separately-labeled things:

1. **Selection assessment** (`nist.assess_selection`): would a verifier
   configured with a given policy accept this candidate, in a given auth
   context (`single_factor` needs ≥15 characters; `mfa` needs ≥8)?
2. **Verifier policy audit** (`nist.audit_verifier_policy`): does a
   *policy configuration* (length bounds, composition rules, rotation,
   blocklisting, rate limiting, password-manager/paste support) meet the
   normative SHALL/SHOULD requirements? This is the only level that can
   meaningfully report pass/fail against the standard — and even then,
   only for the specific requirements it checks (see `not_assessed` in
   every report: FIPS validation, TLS, full AAL architecture, and
   password storage scheme are explicitly out of scope).

## Usage

```bash
pip install -e ".[dev]"

pwaudit policy-audit experiments/policy-nist-conformant.yaml
pwaudit policy-audit experiments/policy-legacy-noncompliant.yaml

pwaudit analyze experiments/experiment.yaml \
  --policy-file experiments/policy-nist-conformant.yaml \
  --format markdown --output results/password-analysis.md

pwaudit analyze experiments/experiment.yaml --format json --output results/password-analysis.json
```

## Running the tests

```bash
pytest -q                 # 46 tests, no John installation required
ruff check src tests
```

The one John-the-Ripper integration test (real subprocess call) is
skipped unless `PWAUDIT_JOHN_CMD` is set:

```bash
MSYS2_ARG_CONV_EXCL="*" PWAUDIT_JOHN_CMD="wsl -d Ubuntu -- john" pytest -q tests/test_john_runner_integration.py
# or, on a Linux machine with john on PATH:
PWAUDIT_JOHN_CMD="john" pytest -q tests/test_john_runner_integration.py
```

## Design decisions worth knowing

- **Never a combined score.** `AnalysisRecord` (`models.py`) keeps NIST
  selection, HIBP exposure, zxcvbn guessability, and John results as
  separate fields — deliberately, per the research this was built from:
  a password can be structurally hard to guess *and* already breached,
  or absent from any breach list *and* trivially guessable. Collapsing
  that into `security_score: 8.73` would destroy the information that
  makes the tool useful.
- **Blocklist matching is whole-password only, never substring.**
  SP 800-63B-4 requires comparing the entire candidate against the
  blocklist — a password merely *containing* a blocklisted word (e.g.
  `planet-correct-horse-staple` containing `correct`) must not fail this
  check. Substring/pattern observations belong to zxcvbn, not the
  normative blocklist (`blocklist.py`, tested explicitly in
  `tests/test_blocklist.py::test_substring_containment_is_not_a_hit`).
- **`guesses`, not zxcvbn's crack-time strings, is the primary strength
  output.** Guess count is a property of the password's pattern
  structure; a "seconds" estimate additionally bakes in an assumed hash
  algorithm, cost, and hardware — exactly the part this project measures
  *empirically* via John instead of estimating.
- **Offline HIBP mode is used for this project's own reproducible
  experiment**, even though the tool also implements the real
  k-anonymity API adapter (`hibp.py::check_k_anonymity`, genuinely
  callable, used to build the local snapshot — see `data/README.md`).
  The same corpus snapshot gives the same result even after HIBP ingests
  more data later.
- **Right-censored results are reported as such.** A bounded attack that
  didn't crack a password is reported as `cracked: false,
  duration_limit_seconds: N` — never as an extrapolated "would take 500
  years," unless that's an explicit, separately-labeled model estimate.
- **Real John output only.** Every regex in `john_parser.py` was written
  against actual captured `john` 1.9.0 output (`tests/fixtures/`,
  `results/raw-captures/`), not guessed from documentation. The parser
  needs no John installation to test; `john_runner.py` (the part that
  actually shells out) is covered by one separate, opt-in integration
  test.

## A real environment constraint, disclosed rather than routed around

This machine's `john` is Ubuntu's core (non-jumbo) 1.9.0 package,
reachable only via WSL. Core John does **not** include Raw-MD5/NTLM
formats, and no passwordless `sudo` was available to install the build
dependencies for a jumbo build from source. So the empirical hash-cost
comparison here is **md5crypt vs. bcrypt** (both real, salted, legacy
-vs-modern password-hashing schemes) rather than raw MD5 vs. bcrypt.
Documented in `experiments/attack-manifest.yaml` and `PROJECT_NOTES.md`,
not silently substituted.

## Verification performed

- **46 automated tests pass** (1 additional integration test, gated on
  `PWAUDIT_JOHN_CMD`, was also actually run against real WSL John and
  passed — see PROJECT_NOTES.md). Ruff reports zero issues.
- **Every HIBP number in `data/hibp-snapshot-2026-09-08.txt` is a real,
  live response** from `https://api.pwnedpasswords.com`, fetched on the
  date shown — not invented. See `data/README.md` for the full
  provenance and the exact counts.
- **Every John the Ripper result is a real captured run** from `john`
  1.9.0 in WSL2 Ubuntu — see `experiments/wsl-scripts/` for the exact
  commands and `results/raw-captures/` for their literal output.
- Running `pwaudit analyze experiments/experiment.yaml --policy-file
  experiments/policy-nist-conformant.yaml` end to end over the frozen
  26-password dataset produces `results/password-analysis.md` /
  `.json`, reproduced in this repo.

## The central finding (from this fixture set, not a population claim)

Every password in the `legacy-composition` category (satisfies
upper/lower/digit/symbol, e.g. `Password1!`, `Summer2024!`) is
**both** legacy-complexity-compliant **and** a real, confirmed HIBP
breach hit — while every `long-uncommon-passphrase` and
`random-generated` password is absent from HIBP and scores far higher on
zxcvbn's guessability estimate despite having no forced character-class
mixture. This is a demonstration on a small, deliberately constructed
fixture set (see `dataset/synthetic-passwords.yaml`), not a claim of
population-level statistical significance — the cited literature below
provides that at scale.

## Limitations

- Frozen dataset: 26 passwords across 5 categories (~5 each), smaller
  than the "10-20 per category" the source research suggested, for
  portfolio scope. Category summaries are explicitly labeled as
  fixture-set demonstrations, not population statistics.
- `data/hibp-snapshot-2026-09-08.txt` is an 11-row snapshot built from
  live single-password lookups against this project's own dataset, not
  the full multi-hundred-million-row Pwned Passwords corpus.
- Empirical hash-cost comparison uses md5crypt vs. bcrypt, not raw MD5
  vs. bcrypt (see "environment constraint" above).
- No GPU-accelerated or distributed cracking, no personalized attack
  models, no claim of full NIST certification for any system.

## Future Enhancements

- A jumbo John build (with sudo/root available) for Raw-MD5/NTLM/WPA and
  a wider format comparison.
- A full offline HIBP corpus via the official `PwnedPasswordsDownloader`
  for corpus-scale (not single-lookup) offline screening.
- Distinguishing entropy/guessability trends with a larger, IRB-style
  human password dataset — out of scope for a portfolio project, which
  is exactly why the cited literature below matters here.

## References

- NIST SP 800-63B-4 (July 2025), §3.1.1 (memorized secrets) and §3.2.2
  (general authenticator requirements / throttling).
- Wheeler, D. (2016). *zxcvbn: Low-Budget Password Strength Estimation*.
  25th USENIX Security Symposium.
- Kelley, P. G. et al. (2012). *Guess Again (and Again and Again):
  Measuring Password Strength by Simulating Password-Cracking
  Algorithms*. IEEE Symposium on Security and Privacy.
- Shay, R. et al. (2016). *Designing Password Policies for Strength and
  Usability*. ACM Transactions on Information and System Security, 18.
- Saint-Jean, D., Al Smadi, B., & Sumlin, C. (2026). *A Breach-Adjusted
  Entropy Model for Password Strength Evaluation*. ACDSA.
- Have I Been Pwned — Pwned Passwords (`https://haveibeenpwned.com/Passwords`).
