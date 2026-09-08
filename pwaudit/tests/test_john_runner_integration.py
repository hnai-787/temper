"""Real end-to-end integration test against an actual `john` binary.

Skipped unless PWAUDIT_JOHN_CMD is set (e.g. `wsl -d Ubuntu -- john` on
this project's own Windows development machine, or plain `john` on a
Linux CI runner with it installed) -- see john_runner.py docstring and
research brief section 37: the rest of the suite must never require a
real John installation.
"""

import os

import pytest

from pwaudit.john_parser import parse_benchmark
from pwaudit.john_runner import run_benchmark

pytestmark = pytest.mark.skipif(
    "PWAUDIT_JOHN_CMD" not in os.environ,
    reason="set PWAUDIT_JOHN_CMD to run real John the Ripper integration tests",
)


def test_real_md5crypt_benchmark_runs_and_parses():
    output = run_benchmark("md5crypt", seconds=3)
    result = parse_benchmark(output)
    assert result.format_name == "md5crypt"
    assert result.real_c_per_s > 0
