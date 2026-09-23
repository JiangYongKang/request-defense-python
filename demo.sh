#!/usr/bin/env bash
# Local reproduction: rule block, rate limit, trusted vs malformed forwarding.
# Note: curl can bind to arbitrary *local* addresses on loopback, so the
# untrusted-peer case is covered by the unit tests; here we exercise the
# trusted-proxy path (127.0.0.1 is configured trusted) with good/bad XFF.
set -euo pipefail
cd "$(dirname "$0")"

export REQUEST_DEFENSE_CONFIG="${REQUEST_DEFENSE_CONFIG:-defense_config.example.json}"
export DEFENSE_LOG_LEVEL=INFO
PY=/home/smc/dev/workspace/.venv/bin/python

$PY -m uvicorn main:app --port 8077 >/tmp/demo_server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1.5

echo "== 1. normal request (interface behavior unchanged) =="
curl -s http://127.0.0.1:8077/ ; echo

echo "== 2. rule block: distinct reason, no Retry-After =="
curl -s -i http://127.0.0.1:8077/admin | grep -iE 'HTTP/|x-defense-reason|retry-after' ; echo

echo "== 3. burst boundary then rate limit (burst=5, shared per identity) =="
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "request $i -> %{http_code}\n" http://127.0.0.1:8077/health
done

echo "== 4a. trusted proxy + valid XFF: client 8.8.8.8 rate-limited twice =="
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "8.8.8.8 try $i -> %{http_code}\n" \
    -H "X-Forwarded-For: 8.8.8.8" http://127.0.0.1:8077/health
done

echo "== 4b. malformed XFF: falls back to peer (shares peer bucket) =="
curl -s -o /dev/null -w "junk xff -> %{http_code}\n" \
  -H "X-Forwarded-For: not-an-ip" http://127.0.0.1:8077/health

echo
echo "== server-side audit trail (first 3 verdicts) =="
grep defense_verdict /tmp/demo_server.log | head -3
