#!/bin/bash
set -e
WORK=~/pwaudit-experiment
mkdir -p "$WORK"
cd "$WORK"
rm -f ~/.john/john.pot ./*.rec

echo "=== attack: weak password, real default wordlist + rules (expected crack) ==="
john --wordlist=/usr/share/john/password.lst --rules --format=md5crypt weak.pw > attack_weak_rules_stdout.txt 2>&1 || true
tr '\r' '\n' < attack_weak_rules_stdout.txt > attack_weak_rules_clean.txt
cat attack_weak_rules_clean.txt

echo "=== attack: strong password, incremental mode bounded to 15s (expected right-censored, not cracked) ==="
rm -f ~/.john/john.pot
timeout 15 john --incremental=Alnum --format=md5crypt strong.pw > attack_strong_incremental_stdout.txt 2>&1 || true
tr '\r' '\n' < attack_strong_incremental_stdout.txt > attack_strong_incremental_clean.txt
cat attack_strong_incremental_clean.txt
john --show --format=md5crypt strong.pw > show_strong2.txt 2>&1 || true
cat show_strong2.txt

echo "=== live status mid-run (incremental, bounded, capture status after 5s) ==="
rm -f ~/.john/john.pot ./incr_status.rec
(john --incremental=Alnum --format=md5crypt --session=incr_status strong.pw > /tmp/bg2.log 2>&1 &)
sleep 5
john --status=incr_status > status_output2.txt 2>&1 || true
cat status_output2.txt
pkill -f "session=incr_status" 2>/dev/null || true
sleep 1

echo "=== DONE2 ==="
