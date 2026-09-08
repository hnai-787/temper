"""Have I Been Pwned -- Pwned Passwords adapters.

Two independent modes, matching HIBP's own two supported access patterns:

- **Offline** (`check_offline`): look a password's SHA-1 up in a locally
  held `SHA1:count` corpus (the format HIBP's official
  PwnedPasswordsDownloader produces). Preferred for this project's
  reproducible experiments -- the same corpus snapshot gives the same
  result even after HIBP ingests more breach data later. Record the
  snapshot date alongside any result (see `data/README.md`).
- **k-anonymity** (`check_k_anonymity`): the real HIBP API pattern --
  only the first 5 hex characters of the SHA-1 are ever sent; the full
  comparison happens locally against the returned suffix list. Suitable
  for an interactive application; not used by this project's own
  experiments because it isn't reproducible across time.

Neither mode stores or transmits the plaintext password anywhere beyond
computing its SHA-1 in memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import requests

from .models import HibpResult

HIBP_RANGE_API = "https://api.pwnedpasswords.com/range/{prefix}"


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def load_offline_corpus(path: str | Path) -> dict[str, int]:
    """Load a `SHA1:count` file into a dict. Fine for the small synthetic
    fixtures this project ships; a real full HIBP corpus (billions of
    rows) needs a sorted-file binary search or prefix-partitioned lookup
    instead -- see README "Limitations".
    """
    path = Path(path)
    corpus: dict[str, int] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sha1, _, count = line.partition(":")
            corpus[sha1.upper()] = int(count) if count else 0
    return corpus


def check_offline(password: str, corpus: dict[str, int], snapshot_date: str) -> HibpResult:
    digest = sha1_hex(password)
    count = corpus.get(digest)
    return HibpResult(
        checked=True,
        mode="offline",
        found=count is not None,
        prevalence_count=count,
        corpus_snapshot_date=snapshot_date,
    )


def check_k_anonymity(password: str, timeout_seconds: float = 5.0) -> HibpResult:
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]

    response = requests.get(HIBP_RANGE_API.format(prefix=prefix), timeout=timeout_seconds)
    response.raise_for_status()

    for line in response.text.splitlines():
        candidate_suffix, _, count_str = line.partition(":")
        if candidate_suffix.strip().upper() == suffix:
            return HibpResult(
                checked=True,
                mode="k-anonymity",
                found=True,
                prevalence_count=int(count_str.strip()),
                corpus_snapshot_date=None,
            )

    return HibpResult(checked=True, mode="k-anonymity", found=False, prevalence_count=None, corpus_snapshot_date=None)
