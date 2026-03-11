#!/usr/bin/env bash
# =============================================================================
# test_roster.sh — test harness for roster.sh
# run from anywhere — put this and roster.sh wherever you want
# just make sure roster.sh is in lib/ relative to this file
# OR set ROSTER_SH env var to point directly at roster.sh
# =============================================================================

PASS=0; FAIL=0

# find roster.sh — check env var first, then lib/ relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROSTER_SH="${ROSTER_SH:-${SCRIPT_DIR}/lib/roster.sh}"

if [[ ! -f "$ROSTER_SH" ]]; then
    echo "[ERROR] cannot find roster.sh"
    echo "        looked at: ${ROSTER_SH}"
    echo "        either put roster.sh in lib/ next to this file"
    echo "        or run: ROSTER_SH=/path/to/roster.sh bash test_roster.sh"
    exit 1
fi

echo "[INFO]  using roster.sh at: ${ROSTER_SH}"

# temp dir in user home — avoids permission issues with /tmp
TEST_DIR="${HOME}/.ldown_test_$$"
mkdir -p "$TEST_DIR"
trap 'rm -rf "$TEST_DIR"' EXIT

# stub common.sh in temp dir
cat > "${TEST_DIR}/common.sh" << 'EOF'
log_ok()    { echo "[OK]    $*"; }
log_info()  { echo "[INFO]  $*"; }
log_warn()  { echo "[WARN]  $*"; }
log_error() { echo "[ERROR] $*" >&2; }
EOF

run_test() {
    local NAME="$1" EXPECT="$2" MOCK_IP="$3"
    local ROSTER_PATH="${TEST_DIR}/roster.conf"
    cat > "$ROSTER_PATH"
    echo ""; echo "────────────────────────────────────────"
    echo "TEST: ${NAME}"; echo "────────────────────────────────────────"
    (
        export _ROSTER_DIR="$TEST_DIR"
        unset _ROSTER_SH_LOADED
        source "$ROSTER_SH"
        _detect_my_ip() { echo "$MOCK_IP"; return 0; }
        roster_load "$ROSTER_PATH"
    )
    local STATUS=$?
    if [[ "$EXPECT" == "pass" && $STATUS -eq 0 ]]; then
        echo "  → [PASS]"; PASS=$((PASS+1))
    elif [[ "$EXPECT" == "fail" && $STATUS -ne 0 ]]; then
        echo "  → [PASS]"; PASS=$((PASS+1))
    elif [[ "$EXPECT" == "pass" ]]; then
        echo "  → [FAIL] expected success got failure"; FAIL=$((FAIL+1))
    else
        echo "  → [FAIL] expected failure got success"; FAIL=$((FAIL+1))
    fi
}

run_dump() {
    local NAME="$1" MOCK_IP="$2"
    local ROSTER_PATH="${TEST_DIR}/roster.conf"
    cat > "$ROSTER_PATH"
    echo ""; echo "────────────────────────────────────────"
    echo "DUMP: ${NAME}"; echo "────────────────────────────────────────"
    (
        export _ROSTER_DIR="$TEST_DIR"
        unset _ROSTER_SH_LOADED
        source "$ROSTER_SH"
        _detect_my_ip() { echo "$MOCK_IP"; return 0; }
        roster_load "$ROSTER_PATH" && roster_dump
    )
    PASS=$((PASS+1))
}

# =============================================================================
# tests
# =============================================================================

run_test "basic valid roster" pass "203.0.113.11" << 'R'
203.0.113.10 --czar
203.0.113.11
203.0.113.12
R

run_test "all flags" pass "203.0.113.12" << 'R'
SUBNET=10.10.0
WG_PORT=51820
203.0.113.10 --czar --relay --name nyc
203.0.113.11 --name lon --keepalive 25
203.0.113.12 --tunnel 10.99.0.1
192.168.1.5  --name home --keepalive 25
R

run_test "no czar" fail "203.0.113.10" << 'R'
203.0.113.10
203.0.113.11
203.0.113.12
R

run_test "two czars" fail "203.0.113.10" << 'R'
203.0.113.10 --czar
203.0.113.11 --czar
203.0.113.12
R

run_test "single node" fail "203.0.113.10" << 'R'
203.0.113.10 --czar
R

run_test "duplicate public IPs" fail "203.0.113.10" << 'R'
203.0.113.10 --czar
203.0.113.11
203.0.113.11
R

run_test "duplicate tunnel IPs" fail "203.0.113.10" << 'R'
203.0.113.10 --czar --tunnel 10.10.0.1
203.0.113.11 --tunnel 10.10.0.1
203.0.113.12
R

run_test "duplicate names" fail "203.0.113.10" << 'R'
203.0.113.10 --czar --name same
203.0.113.11 --name same
203.0.113.12
R

run_test "my IP not in roster" fail "9.9.9.9" << 'R'
203.0.113.10 --czar
203.0.113.11
203.0.113.12
R

run_test "invalid port" fail "203.0.113.10" << 'R'
203.0.113.10 --czar --port abc
203.0.113.11
203.0.113.12
R

run_test "invalid keepalive" fail "203.0.113.10" << 'R'
203.0.113.10 --czar
203.0.113.11 --keepalive notanumber
203.0.113.12
R

run_test "tunnel wrong subnet manual override allowed" pass "203.0.113.10" << 'R'
SUBNET=10.10.0
203.0.113.10 --czar
203.0.113.11 --tunnel 10.20.0.5
203.0.113.12
R

run_test "comments and blanks" pass "203.0.113.11" << 'R'
# comment
SUBNET=10.10.0

# another
203.0.113.10 --czar

203.0.113.11
203.0.113.12
R

run_test "I am czar" pass "203.0.113.10" << 'R'
203.0.113.10 --czar --name czar-node
203.0.113.11
203.0.113.12
R

run_test "I am relay" pass "203.0.113.11" << 'R'
203.0.113.10 --czar
203.0.113.11 --relay --name relay-node
203.0.113.12
R

run_test "mixed tunnel IPs" pass "203.0.113.12" << 'R'
SUBNET=10.10.0
203.0.113.10 --czar
203.0.113.11 --tunnel 10.99.0.1
203.0.113.12
203.0.113.13 --tunnel 10.55.0.2
R

run_test "tunnel octet 0 fails" fail "203.0.113.10" << 'R'
203.0.113.10 --czar
203.0.113.11 --tunnel 10.10.0.0
203.0.113.12
R

run_test "tunnel octet 255 fails" fail "203.0.113.10" << 'R'
203.0.113.10 --czar
203.0.113.11 --tunnel 10.10.0.255
203.0.113.12
R

run_test "relay behind NAT warns but passes" pass "203.0.113.10" << 'R'
203.0.113.10 --czar
192.168.1.5 --relay
203.0.113.12
R

run_dump "full roster dump" "203.0.113.11" << 'R'
SUBNET=10.10.0
WG_PORT=51820
LDOWN_PORT=51821
203.0.113.10 --czar --relay --name nyc-vps
203.0.113.11 --name lon-vps
203.0.113.12 --name sgp-vps
192.168.1.5  --name home-office --keepalive 25
10.0.0.5     --name corp-node --keepalive 25
R

# =============================================================================
echo ""
echo "════════════════════════════════════════"
echo "RESULTS: ${PASS} passed, ${FAIL} failed"
echo "════════════════════════════════════════"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1