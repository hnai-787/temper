# How `results/raw-captures/` was actually produced

These two scripts are the exact, real commands run against `john` 1.9.0
in a WSL2 Ubuntu environment to produce every file under
`results/raw-captures/`. Nothing in that directory was hand-written or
invented -- these scripts are the provenance record.

Run from Windows via (note: `MSYS2_ARG_CONV_EXCL="*"` is required to stop
Git Bash from mangling the `/mnt/c/...` path meant for the WSL side):

```bash
MSYS2_ARG_CONV_EXCL="*" wsl -d Ubuntu -- bash /mnt/c/path/to/01-weak-vs-strong-and-benchmarks.sh
MSYS2_ARG_CONV_EXCL="*" wsl -d Ubuntu -- bash /mnt/c/path/to/02-real-wordlist-and-incremental.sh
```

`01-weak-vs-strong-and-benchmarks.sh`: generates the md5crypt test
hashes, runs the small-custom-wordlist attack against the weak password
(real crack), a first bounded attempt against the strong password, and
the md5crypt/bcrypt `--test` benchmarks.

`02-real-wordlist-and-incremental.sh`: re-runs the weak password against
John's own bundled `password.lst` + `--rules` (a real, honest *non*-crack
-- see PROJECT_NOTES.md), then a bounded 15-second `--incremental=Alnum`
brute-force attempt against the strong password, plus a live
`--status` capture mid-run.

On this development machine, `john` is only reachable inside WSL (core
Ubuntu package, non-jumbo -- see PROJECT_NOTES.md for why Raw-MD5 wasn't
available and md5crypt/bcrypt were used instead). A Linux machine with
`john` on PATH can run the equivalent commands directly, without WSL.
