"""Thin subprocess wrapper around a real `john` binary.

Deliberately separated from `john_parser.py` (research brief section 37):
the parser is tested against captured text fixtures and needs no `john`
installation at all; this module is what actually shells out, and is
only exercised by integration tests gated behind `PWAUDIT_JOHN_CMD` being
set (see tests/test_john_runner_integration.py) -- so CI can test the
report engine fully without John installed, while a real machine with
John (or, as in development here, WSL with John) can still run genuine
end-to-end experiments.
"""

from __future__ import annotations

import os
import subprocess


def john_command_prefix() -> list[str]:
    """The command prefix to invoke `john`, e.g. ["john"] on a machine
    with it on PATH, or ["wsl", "-d", "Ubuntu", "--", "john"] to reach it
    inside WSL from Windows. Configurable via PWAUDIT_JOHN_CMD (space
    -separated).
    """
    configured = os.environ.get("PWAUDIT_JOHN_CMD")
    if configured:
        return configured.split()
    return ["john"]


def run_benchmark(format_name: str, seconds: int = 5) -> str:
    cmd = [*john_command_prefix(), f"--test={seconds}", f"--format={format_name}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 30, check=False)
    return result.stdout + result.stderr


def run_attack(
    password_file: str,
    format_name: str,
    wordlist: str | None = None,
    rules: bool = False,
    incremental_mode: str | None = None,
    duration_limit_seconds: int = 30,
) -> str:
    cmd = [*john_command_prefix(), f"--format={format_name}"]
    if incremental_mode:
        cmd.append(f"--incremental={incremental_mode}")
    elif wordlist:
        cmd.append(f"--wordlist={wordlist}")
        if rules:
            cmd.append("--rules")
    cmd.append(password_file)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration_limit_seconds,
            check=False,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")

    return output.replace("\r", "\n")
