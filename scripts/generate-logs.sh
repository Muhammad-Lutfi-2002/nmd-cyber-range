#!/bin/sh
# generate-logs.sh
#
# Injects a deterministic, realistic "attack story" into /opt/admin/logs so the
# Blue Team has concrete forensic evidence to analyze, independent of whatever
# live traffic the lab actually sees. Run once at container startup.
#
# Story (matches the live exploit the Red Team path demonstrates):
#   18:50:10/12  legitimate admin background traffic (192.168.1.100)
#   18:50:15     attacker's first WAF-blocked <script> attempt (403)
#   18:50:40     attacker's WAF-bypass payload (<svg onload=...>) accepted
#   18:51:10     admin views the dashboard -> stored XSS fires in admin's
#                browser -> cookie exfiltrated
#   18:51:12     exfiltrated cookie arrives at attacker's collector,
#                Base64-encoded inside X-Forwarded-For
#   18:51:55     attacker replays the stolen adm_sess cookie directly
#                against /dashboard -> 200 OK, NEVER touching /api/verify-mfa
#   18:53:10     IR system flags the whole sequence as a CRITICAL anomaly

set -e

LOG_DIR="/opt/admin/logs"
mkdir -p "$LOG_DIR"

ACCESS_LOG="$LOG_DIR/access.log"
ERROR_LOG="$LOG_DIR/error.log"

DATE_TAG="07/Oct/2026"

# NOTE for the Blue Team: this Base64 string is intentionally stored WITHOUT
# its trailing '=' padding, the way a real attacker trying to slip past naive
# log-scanning rules might do it. Add padding back before decoding it.
EXFIL_B64="UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0"

cat >> "$ACCESS_LOG" <<EOF
192.168.1.100 - - [${DATE_TAG}:18:50:10 +0700] "GET / HTTP/1.1" 200 1532 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" XFF:"-"
192.168.1.100 - - [${DATE_TAG}:18:50:12 +0700] "GET /robots.txt HTTP/1.1" 200 78 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" XFF:"-"
10.10.14.50 - - [${DATE_TAG}:18:50:15 +0700] "POST /feedback HTTP/1.1" 403 92 "-" "Mozilla/5.0" XFF:"-"
10.10.14.50 - - [${DATE_TAG}:18:50:40 +0700] "POST /feedback HTTP/1.1" 200 141 "-" "Mozilla/5.0" XFF:"-"
192.168.1.100 - - [${DATE_TAG}:18:51:10 +0700] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" XFF:"-"
10.10.14.50 - - [${DATE_TAG}:18:51:12 +0700] "GET /collect?exfil=cookie HTTP/1.1" 204 0 "-" "Mozilla/5.0" XFF:"${EXFIL_B64}"
10.10.14.50 - - [${DATE_TAG}:18:51:55 +0700] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0" XFF:"-"
EOF

cat >> "$ERROR_LOG" <<EOF
[${DATE_TAG} 18:50:15] [WARN] WAF blocked request from 10.10.14.50 to /feedback: payload contained <script> tag
[${DATE_TAG} 18:51:12] [INFO] Inbound request to /collect carried a Base64-encoded value in X-Forwarded-For (44-ish char, non-standard header usage) — investigate
[${DATE_TAG} 18:51:55] [CRITICAL] Cookie reuse detected: adm_sess presented by 10.10.14.50 was never issued via /api/verify-mfa for this client
[${DATE_TAG} 18:53:10] [CRITICAL] Authentication bypass anomaly: admin session granted without MFA verification step for source IP 10.10.14.50
EOF

echo "Synthetic attack logs written to $LOG_DIR"
