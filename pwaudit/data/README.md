# Compromise data provenance

**Source**: Have I Been Pwned — Pwned Passwords
(`https://api.pwnedpasswords.com`), queried via the real k-anonymity API
(only the first 5 hex characters of each password's SHA-1 were ever
sent — see `src/pwaudit/hibp.py::check_k_anonymity`).

**Snapshot acquired**: 2026-09-08
**File**: `hibp-snapshot-2026-09-08.txt`
**Representation**: `SHA1:count`, one entry per line, uppercase hex,
sorted.

**What this is and isn't**: this is a small, real snapshot built from
genuine live queries against this project's own synthetic password
dataset (`dataset/synthetic-passwords.yaml`) on the date above — every
count in this file was actually returned by the real HIBP service, not
invented. It is **not** the full Pwned Passwords corpus (that's several
hundred million rows and multiple gigabytes even compressed — not
practical to vendor in this repo). `pwaudit`'s offline-mode code path
(`hibp.py::check_offline`) works identically against a file of this
shape regardless of whether it holds 11 rows or the full corpus; a real
deployment should use HIBP's own official
[`PwnedPasswordsDownloader`](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
to build a complete local corpus instead.

**Licensing**: HIBP's Pwned Passwords API and data carry no licensing or
attribution requirement, though attribution is welcome — hence this file.

**Why offline mode for this project's own experiments**: the same
corpus snapshot gives the same result even after HIBP ingests more
breach data later, which is what makes `avionics-net verify`-style
reproducibility possible here too. `pwaudit`'s `check_k_anonymity` (a
real, working online adapter) is better suited to an interactive
application checking a live user-submitted password.

## What the snapshot actually shows

| Password | Category | Real HIBP prevalence |
|---|---|---:|
| `123456` | A (common/breached) | 210,461,208 |
| `password` | A | 52,372,427 |
| `qwerty123` | A | 13,871,714 |
| `letmein` | A | 1,406,604 |
| `iloveyou` | A | 7,007,935 |
| `Password1!` | B (legacy composition-rule variant) | 584,516 |
| `Summer2024!` | B | 3,614 |
| `Winter2023$` | B | 947 |
| `Football1!` | B | 24,954 |
| `Dragon123$` | B | 3,796 |
| `thisismypassword123` | C (long predictable phrase) | 1,772 |

Every category-B password — composition-rule compliant by construction
(upper/lower/digit/symbol) — is still real, observed breach data. That's
the empirical core of this project's finding: composition-rule
compliance and breach exposure are unrelated dimensions (see
`PROJECT_NOTES.md`). All category D (long uncommon passphrases) and
category E (CSPRNG-random) passwords in the dataset returned no match —
also genuinely checked against the live API, not assumed.
