# Password Policy & Crack-Resistance Report

Standard: **NIST SP 800-63B-4**. This report separates four independent 
measurement dimensions (standards selection eligibility, breach exposure, 
modeled guessability, and empirical John the Ripper results) and never 
combines them into one score. See PROJECT_NOTES.md for methodology.

## Verifier Policy Audit

Overall: **PASS**

| Requirement | Status | Detail |
|---|---|---|
| Minimum length SHALL be >= 15 for auth_context=single_factor | pass | configured minimum_length=15 |
| Maximum supported length SHOULD be >= 64 | pass | configured maximum_length_supported=128 |
| Verifiers SHALL NOT require composition rules (mixed character types) | pass | configured composition_rules=False |
| Verifiers SHALL NOT require periodic forced rotation absent evidence of compromise | pass | configured periodic_rotation=False |
| Verifiers SHALL NOT truncate the password before verification | pass | configured truncates_password=False |
| Verifiers SHALL compare the whole prospective password against a blocklist of commonly-used, expected, or compromised values | pass | configured blocklist.enabled=True |
| Verifiers SHALL permit password manager / autofill input | pass | configured password_manager_autofill=True |
| Verifiers SHOULD permit pasting into the password field | pass | configured paste_allowed=True |
| Verifiers SHALL rate-limit failed attempts (<= 100 consecutive failures is an upper bound, not a recommended target) | pass | configured rate_limit={'enabled': True, 'max_consecutive_failures': 10} |

Not assessed by this tool: FIPS validation of cryptographic modules; authenticated protected channel (e.g. TLS) for the verifier; full AAL (Authenticator Assurance Level) architecture; password storage salt/hash scheme (a verifier storage audit, distinct from this policy audit)

## Per-Password Analysis

| ID | Category | Length | Legacy complexity | NIST selection | HIBP | log10(guesses) | John |
|---|---|---:|---|---|---|---:|---|
| A01 | common-breached | 6 | fail | fail | found (210,461,208) | 0.30 | — |
| A02 | common-breached | 8 | fail | fail | found (52,372,427) | 0.48 | — |
| A03 | common-breached | 9 | fail | fail | found (13,871,714) | 2.34 | — |
| A04 | common-breached | 7 | fail | fail | found (1,406,604) | 1.23 | — |
| A05 | common-breached | 8 | fail | fail | found (7,007,935) | 1.68 | — |
| B01 | legacy-composition | 10 | pass | fail | found (584,516) | 4.26 | — |
| B02 | legacy-composition | 11 | pass | fail | found (3,614) | 7.44 | wordlist:cracked; wordlist+rules:not cracked |
| B03 | legacy-composition | 11 | pass | fail | found (947) | 7.87 | — |
| B04 | legacy-composition | 10 | pass | fail | found (24,954) | 4.30 | — |
| B05 | legacy-composition | 10 | pass | fail | found (3,796) | 5.51 | — |
| C01 | long-predictable-phrase | 18 | fail | pass | not found | 8.03 | — |
| C02 | long-predictable-phrase | 19 | fail | pass | found (1,772) | 9.28 | — |
| C03 | long-predictable-phrase | 14 | fail | fail | not found | 8.15 | — |
| C04 | long-predictable-phrase | 17 | fail | pass | not found | 12.09 | — |
| C05 | long-predictable-phrase | 17 | fail | pass | not found | 10.10 | — |
| D01 | long-uncommon-passphrase | 28 | fail | pass | not found | 21.33 | — |
| D02 | long-uncommon-passphrase | 36 | fail | pass | not found | 25.57 | — |
| D03 | long-uncommon-passphrase | 28 | fail | pass | not found | 19.02 | — |
| D04 | long-uncommon-passphrase | 31 | fail | pass | not found | 21.04 | — |
| D05 | long-uncommon-passphrase | 29 | fail | pass | not found | 20.90 | — |
| E01 | random-generated | 20 | pass | pass | not found | 20.00 | — |
| E02 | random-generated | 20 | pass | pass | not found | 20.00 | — |
| E03 | random-generated | 20 | pass | pass | not found | 20.00 | — |
| E04 | random-generated | 20 | pass | pass | not found | 20.00 | — |
| E05 | random-generated | 20 | pass | pass | not found | 20.00 | — |
| E06 | random-generated | 24 | pass | pass | not found | 24.00 | incremental:not cracked |

## Category Summary (demonstrations on this controlled fixture set only)

Small, deliberately constructed sample -- not a claim of statistical population-level significance. See the cited literature in README.md for that.

| Category | Median log10(guesses) | HIBP hit rate | Legacy-complexity pass rate |
|---|---:|---:|---:|
| common-breached | 1.23 | 100% | 0% |
| legacy-composition | 5.51 | 100% | 100% |
| long-predictable-phrase | 9.28 | 20% | 0% |
| long-uncommon-passphrase | 21.04 | 0% | 0% |
| random-generated | 20.00 | 0% | 100% |
