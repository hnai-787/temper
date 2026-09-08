# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.1.0] - 2026-09-08

### Added

- **`pwaudit/`**: a new password-security laboratory measuring four
  independent dimensions and never combining them into one score:
  NIST SP 800-63B-4 policy selection/audit (`nist.py`), real Have I Been
  Pwned breach-exposure checking (`hibp.py`, offline `SHA1:count` corpus
  adapter and a genuine k-anonymity API adapter), zxcvbn pattern-aware
  guessability estimation (`strength.py`), and a John the Ripper output
  parser + optional real subprocess runner (`john_parser.py`,
  `john_runner.py`).
- `dataset/synthetic-passwords.yaml`: a frozen, 26-password/5-category
  fixture set (common/breached, legacy-composition, long-predictable
  -phrase, long-uncommon-passphrase, random-generated), fixed before any
  check was run.
- `data/hibp-snapshot-2026-09-08.txt`: a real snapshot built from live
  queries to the actual HIBP k-anonymity API for this dataset -- every
  count is real, live-fetched data (e.g. `123456` -> 210,461,208), not
  invented. See `data/README.md` for full provenance.
- `experiments/wsl-scripts/`: the exact real shell scripts run against
  `john` 1.9.0 in WSL2 Ubuntu to produce every file under
  `results/raw-captures/` -- real crack, real non-crack, real bounded
  brute-force timeout, and real hash-format benchmarks.
- `pwaudit analyze`/`policy-audit` CLI commands, and JSON/Markdown report
  generation (`results/password-analysis.{json,md}`, committed as real
  generated evidence).
- 46 pytest tests (zero requiring John installed -- the parser is tested
  entirely against real captured fixtures) plus one real, gated
  integration test against actual WSL John (`PWAUDIT_JOHN_CMD`).
- `.github/workflows/pwaudit-ci.yml`: Ruff + pytest, SHA-pinned actions,
  scoped to `pwaudit/` changes.

### Changed

- `project.yaml`: corrected description to reflect the current
  SP 800-63B-4 standard (superseding the older 8-character-minimum
  guidance the initial brief assumed); `portfolio.featured` set to `true`.

### Fixed

- (within `pwaudit`, new code) none -- see PROJECT_NOTES.md for the two
  real environment constraints investigated and worked around
  (non-jumbo John lacking Raw-MD5; a WSL/Git-Bash command-substitution
  and path-mangling issue in this session's own tooling).
