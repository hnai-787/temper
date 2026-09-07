# Hash Cracking with John the Ripper

## Course Information

| Field | Details |
|---|---|
| Course | Introduction to Cyber Security |
| Semester | Semester 1 — Fall 2023 |
| University | Air University, Islamabad |
| Student | Hussain Ali (232095) |

## Overview

A lab demonstration/presentation covering password hash cracking against a
**dummy MD5 hash** using John the Ripper and Johnny, plus a custom
wordlist built with CUPP and a note on cracking password-protected
ZIP/PDF archives.

## Problem Statement

Demonstrate, in a fully controlled lab setting, how weak password hashing
and predictable passwords are broken in practice — and what actually
mitigates it.

## Objectives

- Generate a dummy MD5 hash and a targeted wordlist with CUPP.
- Crack the dummy hash with John the Ripper (CLI) and Johnny (GUI).
- Explain mitigations: salting, adaptive hashing (bcrypt/scrypt/Argon2), MFA, rate limiting.

## Tools and Technologies

- Kali Linux
- John the Ripper (CLI)
- Johnny (GUI front-end for John)
- CUPP (Common User Password Profiler — wordlist generation)

## Features

N/A — this is a presentation/demonstration, not a coded artifact.

## Methodology

1. Generate a dummy MD5 hash for a fictitious password.
2. Build a custom wordlist with CUPP based on plausible personal details.
3. Crack the hash with John the Ripper, then repeat via the Johnny GUI.
4. Cover `zip2john`/`pdf2john` for password-protected archive cracking.
5. Present mitigations (salting, adaptive hashing, MFA, rate limiting).

## Repository Structure

```text
hash-cracking-john-the-ripper/
  README.md
  PROJECT_NOTES.md
  presentation/Hash-Cracking.pptx
  screenshots/
  project.yaml
```

## Setup Instructions

N/A — no runnable code is included; this is a lab walkthrough. To
reproduce it yourself (in a lab environment you control), install
`john`, `cupp`, and `johnny` on Kali Linux.

## Usage

N/A.

## How to Review

1. Start with this README.
2. Open `presentation/Hash-Cracking.pptx` for the full 22-slide walkthrough.
3. Check `screenshots/` for CUPP, John the Ripper, and Johnny in use.

## Screenshots

See `screenshots/` — 5 screenshots (CUPP, John the Ripper, Johnny GUI, presentation cover/table of contents).

## Results

The dummy hash was successfully cracked with both John the Ripper and
Johnny using the CUPP-generated wordlist. The presentation explicitly
states: "Academic lab demonstration using dummy hashes only" and
"Educational use only: dummy hashes, controlled lab, authorized testing."

## Limitations

- Demonstration-only — no original code or dataset beyond the dummy hash and generated wordlist.
- Dictionary/wordlist-based cracking only; no rule-based or brute-force benchmarking included.

## Future Enhancements

- Extend to rule-based mangling (`--rules` in John) and compare crack times against dictionary-only attacks.

## Safety and Privacy

- Only a dummy, non-real password hash is used throughout.
- No real credentials, targets, or systems are involved.

## Ethical Notice

This project is strictly an academic lab demonstration using dummy hashes
in a controlled environment. It must not be used against real accounts,
systems, or credentials without explicit authorization.
