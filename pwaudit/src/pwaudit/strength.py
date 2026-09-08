"""Pattern-aware guessability estimation via zxcvbn.

Deliberately not "entropy" (see PROJECT_NOTES.md / README.md): a naive
L*log2(N) character-set estimate assumes uniform random selection, which
is a badly wrong model for human-chosen passwords -- "Password1!" scores
high on that formula while being highly predictable in practice. zxcvbn
instead estimates the number of guesses a pattern-aware attacker would
need (dictionary words, names, dates, keyboard walks, l33t substitutions,
repeats/sequences) and was validated against real guessing attacks
(Wheeler 2016). This module surfaces `guesses`/`guesses_log10` as the
primary output and treats zxcvbn's own crack-time-scenario strings as
secondary, since "seconds" additionally bakes in an assumed hash
algorithm/hardware/parallelism -- this project measures THAT part
separately and empirically via John the Ripper (see john_parser.py).
"""

from __future__ import annotations

import math

from zxcvbn import zxcvbn

from .models import StrengthEstimate


def estimate_strength(password: str) -> StrengthEstimate:
    result = zxcvbn(password)
    guesses = float(result["guesses"])
    guesses_log10 = float(result.get("guesses_log10", math.log10(guesses) if guesses > 0 else 0.0))

    patterns = tuple(
        f"{m.get('pattern', 'unknown')}:{m.get('token', '')}" for m in result.get("sequence", [])
    )

    return StrengthEstimate(
        estimated_guesses=guesses,
        estimated_guesses_log10=guesses_log10,
        pattern_summary=patterns,
    )
