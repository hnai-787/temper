# Hash Cracking with John the Ripper + pwaudit

## Course Information

| Field | Details |
|---|---|
| Course | Introduction to Cyber Security |
| Semester | Semester 1 — Fall 2023 |
| University | Air University, Islamabad |
| Student | Hussain Ali (232095) |

## Overview

The original coursework is a lab demonstration/presentation covering
password hash cracking against a **dummy MD5 hash** using John the
Ripper and Johnny, plus a custom wordlist built with CUPP and a note on
cracking password-protected ZIP/PDF archives.

**New addition:** [`pwaudit/`](pwaudit/), a password-security laboratory
that measures four genuinely different things about a password (NIST SP
800-63B-4 policy eligibility, real Have I Been Pwned breach exposure,
zxcvbn pattern-aware guessability, and empirical John the Ripper
results) and never combines them into one score. Every number it reports
is real: live HIBP API data fetched for this project, and actual `john`
1.9.0 runs (cracks, non-cracks, and benchmarks) captured from a real WSL
Ubuntu environment. See [`pwaudit/README.md`](pwaudit/README.md).

## Problem Statement

Demonstrate, in a fully controlled lab setting, how weak password hashing
and predictable passwords are broken in practice — and what actually
mitigates it. *(New: and ground "what actually mitigates it" in the
current real standard and real breach data, not an assumed 2010s-era
password-policy folklore.)*

## Objectives

*(original)*
- Generate a dummy MD5 hash and a targeted wordlist with CUPP.
- Crack the dummy hash with John the Ripper (CLI) and Johnny (GUI).
- Explain mitigations: salting, adaptive hashing (bcrypt/scrypt/Argon2), MFA, rate limiting.

*(this rebuild)*
- Audit a verifier policy against NIST SP 800-63B-4's actual SHALL/SHOULD
  requirements (not the older, superseded 8-character-minimum guidance).
- Check a frozen, clearly-synthetic password dataset against real Have I
  Been Pwned breach data.
- Estimate pattern-aware guessability (zxcvbn) instead of naive
  character-set entropy.
- Empirically measure real John the Ripper crack outcomes and hash
  -format throughput, and report them separately from the modeled
  guessability estimate.

## Tools and Technologies

- Kali Linux, John the Ripper (CLI), Johnny (GUI), CUPP *(original)*
- **New:** Python 3.12, zxcvbn, the real HIBP Pwned Passwords API,
  John the Ripper 1.9.0 (WSL2 Ubuntu), pytest, Ruff, GitHub Actions

## Features

*(original)* N/A — a presentation/demonstration, not a coded artifact.

*(this rebuild — see `pwaudit/README.md` for full detail)*
- A NIST SP 800-63B-4 policy auditor with two distinct outputs: does a
  candidate password meet a policy's selection rules, and does the
  policy configuration itself meet the standard's SHALL/SHOULD
  requirements (length, no forced composition rules, no forced rotation,
  whole-password blocklisting, throttling, password-manager/paste
  support).
- A whole-password blocklist checker (never substring-based, per the
  current standard's actual wording) plus a small conservative
  context-specific blocklist generator (service name / username
  derivatives).
- Real Have I Been Pwned breach-exposure checking, both an offline
  `SHA1:count` corpus adapter and a genuine working k-anonymity API
  adapter (used to build this project's own real data snapshot).
- zxcvbn-based guessability estimation (`guesses`/`guesses_log10`),
  reported separately from empirical crack results.
- A John the Ripper output parser built entirely from real captured
  `john` 1.9.0 output (benchmarks and bounded-attack status lines,
  including all four of John's distinct rate counters), plus an optional
  real subprocess runner.
- 46 automated tests (zero requiring a John installation) plus one real,
  actually-executed integration test against WSL John.

## Methodology

1. *(original)* Generate a dummy MD5 hash for a fictitious password.
2. *(original)* Build a custom wordlist with CUPP based on plausible personal details.
3. *(original)* Crack the hash with John the Ripper, then repeat via the Johnny GUI.
4. *(original)* Cover `zip2john`/`pdf2john` for password-protected archive cracking.
5. *(original)* Present mitigations (salting, adaptive hashing, MFA, rate limiting).
6. **New:** freeze a 26-password synthetic dataset across 5 categories
   *before* running any check; audit it against NIST SP 800-63B-4, real
   HIBP breach data, zxcvbn, and real bounded John the Ripper attacks;
   report all four dimensions separately — see `pwaudit/README.md`
   "Methodology" and "The central finding" for the full pipeline and result.

## Repository Structure

```text
hash-cracking-john-the-ripper/
  README.md, PROJECT_NOTES.md, CHANGELOG.md, project.yaml
  pwaudit/                     NEW: the password-security laboratory
    README.md                 full design writeup, scope boundary, references
    src/pwaudit/               nist, blocklist, hibp, strength, john_parser,
                               john_runner, analysis, report, cli
    dataset/synthetic-passwords.yaml   frozen 26-password/5-category fixture set
    data/                      HIBP snapshot (real, live-fetched) + provenance
    experiments/               policy examples, experiment/attack manifests,
                               wsl-scripts/ (exact commands used for real captures)
    results/                   real generated reports + raw John captures
    tests/                     46 tests + 1 gated real John integration test
  presentation/Hash-Cracking.pptx   original, untouched
  screenshots/
  .github/workflows/pwaudit-ci.yml   NEW: Ruff + pytest, no John required
```

## Setup Instructions

Original: N/A — a lab walkthrough. To reproduce it yourself (in a lab
environment you control), install `john`, `cupp`, and `johnny` on Kali
Linux.

New (`pwaudit/`):

```bash
cd pwaudit
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Usage

Original: N/A.

New:

```bash
cd pwaudit
pwaudit policy-audit experiments/policy-nist-conformant.yaml
pwaudit analyze experiments/experiment.yaml --policy-file experiments/policy-nist-conformant.yaml --format markdown
```

## How to Review

1. Start with this README, then `presentation/Hash-Cracking.pptx` for the original.
2. Check `screenshots/` for CUPP, John the Ripper, and Johnny in use.
3. **New:** read `pwaudit/README.md`, then `pwaudit/src/pwaudit/nist.py` and
   `pwaudit/data/README.md` (the scope boundary and the real HIBP data
   provenance are the two things worth understanding first).
4. Open `pwaudit/results/password-analysis.md` for the actual generated
   report, and `pwaudit/PROJECT_NOTES.md`-referenced
   `results/raw-captures/` for the literal real John the Ripper output
   behind it.

## Screenshots

See `screenshots/` — 5 screenshots (CUPP, John the Ripper, Johnny GUI, presentation cover/table of contents).

## Results

**Original:** the dummy hash was successfully cracked with both John the
Ripper and Johnny using the CUPP-generated wordlist. The presentation
explicitly states: "Academic lab demonstration using dummy hashes only"
and "Educational use only: dummy hashes, controlled lab, authorized
testing."

**New:** 46 pytest tests pass (zero requiring John installed) plus one
real, actually-executed John integration test; Ruff reports zero issues.
Every HIBP number in the project is a real, live API response (e.g.
`123456` → 210,461,208 real observed breaches); every John result is a
real captured run, including an honest non-crack (a plausible modern
password not found by John's own 3559-word bundled list) and a
right-censored bounded brute-force attempt. See `pwaudit/README.md`
"The central finding" for the headline result.

## Limitations

*(original)*
- Demonstration-only — no original code or dataset beyond the dummy hash and generated wordlist.
- Dictionary/wordlist-based cracking only; no rule-based or brute-force benchmarking included.

*(this rebuild — see `pwaudit/README.md` for full detail)*
- 26-password/5-category fixture set (smaller than the 10-20/category the
  source research suggested) — a deliberate, disclosed portfolio-scope decision.
- The HIBP snapshot is 11 rows from live single-password lookups, not the
  full corpus.
- Empirical hash-cost comparison uses md5crypt vs. bcrypt, not raw MD5 vs.
  bcrypt — this machine's available John build is core/non-jumbo (see
  PROJECT_NOTES.md for the investigation).

## Future Enhancements

*(original)*
- Extend to rule-based mangling (`--rules` in John) and compare crack times against dictionary-only attacks — **done** in this rebuild (see `experiments/attack-manifest.yaml`).

*(this rebuild)*
- A jumbo John build for Raw-MD5/NTLM/WPA and a wider format comparison.
- A full offline HIBP corpus via the official `PwnedPasswordsDownloader`.

## Safety and Privacy

- Only a dummy, non-real password hash is used throughout the original lab.
- No real credentials, targets, or systems are involved anywhere in this project.
- `pwaudit`'s dataset (`dataset/synthetic-passwords.yaml`) is either
  well-known textbook-weak password examples or freshly CSPRNG-generated
  strings — never a real account's actual password. Only SHA-1 hashes of
  these synthetic values were ever sent to the real HIBP API (k
  -anonymity: only the first 5 hex characters leave the machine).

## Ethical Notice

This project is strictly an academic lab demonstration using dummy hashes
in a controlled environment. It must not be used against real accounts,
systems, or credentials without explicit authorization.
