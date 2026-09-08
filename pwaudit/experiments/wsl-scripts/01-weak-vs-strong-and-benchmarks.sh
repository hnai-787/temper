#!/bin/bash
set -e
WORK=~/pwaudit-experiment
mkdir -p "$WORK"
cd "$WORK"
rm -f ~/.john/john.pot

echo "=== generating hashes ==="
openssl passwd -1 -salt abcdefgh "Summer2024!" > hash_weak.txt
openssl passwd -1 -salt qz7ktrxm "Xk9#mQ2vBpL7$wR4nTgY8sZ1" > hash_strong.txt
cat hash_weak.txt
cat hash_strong.txt

echo "demo1:$(cat hash_weak.txt)" > weak.pw
echo "demo2:$(cat hash_strong.txt)" > strong.pw

cat > wordlist.txt << 'EOF'
letmein
qwerty123
Summer2024!
dragon2020
iloveyou
EOF

echo "=== attack: weak password (expected to crack) ==="
john --wordlist=wordlist.txt --format=md5crypt weak.pw > attack_weak_stdout.txt 2>&1 || true
tr '\r' '\n' < attack_weak_stdout.txt > attack_weak_clean.txt
cat attack_weak_clean.txt
john --show --format=md5crypt weak.pw > show_weak.txt 2>&1 || true
cat show_weak.txt

echo "=== attack: strong password, bounded 20s timeout (expected not cracked) ==="
timeout 20 john --wordlist=wordlist.txt --format=md5crypt --rules=all strong.pw > attack_strong_stdout.txt 2>&1 || true
tr '\r' '\n' < attack_strong_stdout.txt > attack_strong_clean.txt
cat attack_strong_clean.txt
john --show --format=md5crypt strong.pw > show_strong.txt 2>&1 || true
cat show_strong.txt

echo "=== benchmark: md5crypt ==="
john --test=5 --format=md5crypt > bench_md5crypt.txt 2>&1 || true
cat bench_md5crypt.txt

echo "=== benchmark: bcrypt ==="
john --test=5 --format=bcrypt > bench_bcrypt.txt 2>&1 || true
cat bench_bcrypt.txt

echo "=== john --status form (mid-run status line format) ==="
john --wordlist=wordlist.txt --format=md5crypt --rules=all --session=statuscheck strong.pw > /tmp/bgrun.log 2>&1 &
JPID=$!
sleep 3
john --status=statuscheck > status_output.txt 2>&1 || true
cat status_output.txt
kill $JPID 2>/dev/null || true
wait $JPID 2>/dev/null || true

echo "=== DONE ==="
