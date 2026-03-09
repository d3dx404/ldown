#!/usr/bin/env bash
# =============================================================================
# roster.sh — roster parsing, validation, and identity resolution
# part of ldown — deterministic self-healing WireGuard mesh orchestrator
# =============================================================================
#
# this file is sourced by other modules, never run directly
# after sourcing, call: roster_load [path/to/roster.conf]
#
# exports all variables other modules need:
#   MY_*        — this node's identity
#   CZAR_*      — czar node info
#   RELAY_*     — relay node arrays
#   PEER_*      — all peer arrays (excludes self)
#   NODE_COUNT  — total nodes in roster
#   ROSTER_HASH — sha256 of roster file
#   ROSTER_FILE — path to roster.conf
# =============================================================================

# guard against double-sourcing
[[ -n "${_ROSTER_SH_LOADED}" ]] && return 0
_ROSTER_SH_LOADED=1

# source common.sh — use _ROSTER_DIR env override for testing, otherwise
# resolve relative to this file
if [[ -z "$_ROSTER_DIR" ]]; then
    _ROSTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
source "${_ROSTER_DIR}/common.sh" 2>/dev/null || {
    echo "[ERROR] cannot source common.sh from ${_ROSTER_DIR}" >&2
    exit 1
}

# =============================================================================
# defaults — overridden by roster header or flags
# =============================================================================

ROSTER_FILE="${ROSTER_FILE:-/etc/ldown/roster.conf}"
SUBNET="${SUBNET:-10.10.0}"
WG_PORT="${WG_PORT:-51820}"
LDOWN_PORT="${LDOWN_PORT:-51821}"
CLUSTER_PUBKEY_FILE="${CLUSTER_PUBKEY_FILE:-/etc/ldown/cluster.pub}"
ROSTER_SIG_FILE="${ROSTER_SIG_FILE:-/etc/ldown/roster.sig}"

# =============================================================================
# internal state — cleared on each roster_load call
# =============================================================================

_roster_reset() {
    # my identity
    MY_IP=""
    MY_NAME=""
    MY_TUNNEL_IP=""
    MY_POSITION=""
    MY_WG_PORT=""
    MY_KEEPALIVE=""
    MY_IS_CZAR="false"
    MY_IS_RELAY="false"

    # czar
    CZAR_IP=""
    CZAR_TUNNEL_IP=""
    CZAR_NAME=""

    # arrays — must be explicitly reset
    RELAY_IPS=()
    RELAY_TUNNEL_IPS=()
    PEER_IPS=()
    PEER_TUNNEL_IPS=()
    PEER_NAMES=()
    PEER_KEEPALIVES=()
    PEER_PORTS=()

    # cluster state
    NODE_COUNT=0
    ROSTER_HASH=""

    # internal tracking for validation
    _CZAR_COUNT=0
    _ALL_PUBLIC_IPS=()
    _ALL_TUNNEL_IPS=()
    _ALL_NAMES=()
}

# =============================================================================
# ip detection — finds which roster entry belongs to this machine
# tries multiple sources, first match against roster wins
# =============================================================================

_detect_my_ip() {
    local FILE="$1"

    local CANDIDATES=()

    # source 1 — routing table (most reliable for local IPs)
    local ROUTE_IP
    ROUTE_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{
        for(i=1;i<=NF;i++) if($i=="src") { print $(i+1); exit }
    }')
    [[ -n "$ROUTE_IP" ]] && CANDIDATES+=("$ROUTE_IP")

    # source 2 — all local interface IPs
    while IFS= read -r IFACE_IP; do
        [[ -n "$IFACE_IP" ]] && CANDIDATES+=("$IFACE_IP")
    done < <(hostname -I 2>/dev/null | tr ' ' '\n')

    # source 3 — external public IP (last resort, slowest)
    # try two endpoints in case one is down
    local PUBLIC_IP
    PUBLIC_IP=$(curl -fs --max-time 5 https://api.ipify.org 2>/dev/null              || curl -fs --max-time 5 ifconfig.me 2>/dev/null)
    [[ -n "$PUBLIC_IP" ]] && CANDIDATES+=("$PUBLIC_IP")

    # try each candidate against roster — first match wins
    for IP in "${CANDIDATES[@]}"; do
        [[ -z "$IP" ]] && continue
        # check if this IP appears as first field on any non-comment non-header line
        if grep -vE '^\s*(#|$|SUBNET=|WG_PORT=|LDOWN_PORT=)' "$FILE" \
           | awk '{print $1}' \
           | grep -qx "$IP"; then
            echo "$IP"
            return 0
        fi
    done

    # no match found
    return 1
}

# =============================================================================
# flag parsing helpers
# =============================================================================

# extract value from --flag value pair
# usage: parse_flag "line content" "--flag"
# uses awk — no grep -P, works on busybox and minimal systems
parse_flag() {
    local LINE="$1"
    local FLAG="$2"
    awk -v flag="$FLAG" '{
        for(i=1;i<=NF;i++)
            if($i==flag && (i+1)<=NF)
                { print $(i+1); exit }
    }' <<< "$LINE"
}

# check if flag exists on line (boolean flags like --czar --relay)
# usage: has_flag "line content" "--flag"
# returns: "true" or "false"
has_flag() {
    local LINE="$1"
    local FLAG="$2"
    if echo "$LINE" | grep -qw -- "$FLAG"; then
        echo "true"
    else
        echo "false"
    fi
}

# =============================================================================
# flag validation
# =============================================================================

_validate_flag_values() {
    local NAME="$1"
    local PORT="$2"
    local KEEPALIVE="$3"
    local TUNNEL="$4"
    local LINE_NUM="$5"
    local ERRORS=0

    # --name must be non-empty string (already checked by parse_flag returning empty)
    # nothing more to check here — empty means not set which is fine

    # --port must be integer 1-65535
    if [[ -n "$PORT" ]]; then
        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
            log_error "line ${LINE_NUM}: --port '${PORT}' must be integer 1-65535"
            ERRORS=$((ERRORS + 1))
        fi
    fi

    # --keepalive must be positive integer
    if [[ -n "$KEEPALIVE" ]]; then
        if ! [[ "$KEEPALIVE" =~ ^[0-9]+$ ]] || (( KEEPALIVE < 1 )); then
            log_error "line ${LINE_NUM}: --keepalive '${KEEPALIVE}' must be a positive integer"
            ERRORS=$((ERRORS + 1))
        fi
    fi

    # --tunnel must be valid IPv4 format and valid host address
    if [[ -n "$TUNNEL" ]]; then
        if ! [[ "$TUNNEL" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            log_error "line ${LINE_NUM}: --tunnel '${TUNNEL}' is not valid IPv4 format"
            ERRORS=$((ERRORS + 1))
        else
            # check last octet is 1-254
            local LAST_OCTET="${TUNNEL##*.}"
            if (( LAST_OCTET < 1 || LAST_OCTET > 254 )); then
                log_error "line ${LINE_NUM}: --tunnel '${TUNNEL}' last octet must be 1-254"
                ERRORS=$((ERRORS + 1))
            fi
            # --tunnel explicitly overrides subnet — manual IPs are not prefix-checked
            # SUBNET only governs auto-assignment, not manual overrides
        fi
    fi

    return $ERRORS
}

# =============================================================================
# signature verification
# =============================================================================

_verify_roster_signature() {
    local ROSTER="$1"

    # no public key — skip verification entirely
    if [[ ! -f "$CLUSTER_PUBKEY_FILE" ]]; then
        return 0
    fi

    # public key exists but no signature — warn and continue
    if [[ ! -f "$ROSTER_SIG_FILE" ]]; then
        log_warn "cluster signing key exists but roster.sig is missing"
        log_warn "roster has not been signed — proceeding without verification"
        return 0
    fi

    # both exist — verify
    if ! openssl dgst -sha256 -verify "$CLUSTER_PUBKEY_FILE" \
         -signature "$ROSTER_SIG_FILE" "$ROSTER" >/dev/null 2>&1; then
        log_error "roster signature verification FAILED"
        log_error "roster.conf may have been tampered with"
        return 1
    fi

    log_ok "roster signature verified"
    return 0
}

# =============================================================================
# post-parse validation
# =============================================================================

_validate_roster() {
    local ERRORS=0

    # must have found myself in roster
    if [[ -z "$MY_IP" ]]; then
        log_error "this machine IP was not found in roster.conf"
        log_error "add this machine to the roster before running init"
        log_error "detected IP candidates were:"
        local _ROUTE_IP _IFACE_IP _PUB_IP
        _ROUTE_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')
        [[ -n "$_ROUTE_IP" ]] && log_error "  routing:   ${_ROUTE_IP}"
        while IFS= read -r _IFACE_IP; do
            [[ -n "$_IFACE_IP" ]] && log_error "  interface: ${_IFACE_IP}"
        done < <(hostname -I 2>/dev/null | tr ' ' '\n')
        _PUB_IP=$(curl -fs --max-time 5 https://api.ipify.org 2>/dev/null || curl -fs --max-time 5 ifconfig.me 2>/dev/null)
        [[ -n "$_PUB_IP" ]] && log_error "  public:    ${_PUB_IP}"
        ERRORS=$((ERRORS + 1))
    fi

    # exactly one czar required
    if (( _CZAR_COUNT == 0 )); then
        log_error "no --czar defined in roster.conf"
        log_error "exactly one node must be designated czar"
        ERRORS=$((ERRORS + 1))
    elif (( _CZAR_COUNT > 1 )); then
        log_error "multiple --czar entries found (${_CZAR_COUNT})"
        log_error "only one node may be designated czar"
        ERRORS=$((ERRORS + 1))
    fi

    # need at least 2 nodes
    if (( NODE_COUNT < 2 )); then
        log_error "roster contains only ${NODE_COUNT} node(s)"
        log_error "a mesh requires at least 2 nodes"
        ERRORS=$((ERRORS + 1))
    fi

    # duplicate public IPs — associative array O(n) check
    declare -A _SEEN_IPS
    for IP in "${_ALL_PUBLIC_IPS[@]}"; do
        if [[ -n "${_SEEN_IPS[$IP]+_}" ]]; then
            log_error "duplicate public IP in roster: ${IP}"
            ERRORS=$((ERRORS + 1))
        fi
        _SEEN_IPS[$IP]=1
    done
    unset _SEEN_IPS

    # duplicate tunnel IPs
    declare -A _SEEN_TUNNELS
    for TIP in "${_ALL_TUNNEL_IPS[@]}"; do
        if [[ -n "${_SEEN_TUNNELS[$TIP]+_}" ]]; then
            log_error "duplicate tunnel IP in roster: ${TIP}"
            ERRORS=$((ERRORS + 1))
        fi
        _SEEN_TUNNELS[$TIP]=1
    done
    unset _SEEN_TUNNELS

    # duplicate names
    declare -A _SEEN_NAMES
    for NAME in "${_ALL_NAMES[@]}"; do
        if [[ -n "${_SEEN_NAMES[$NAME]+_}" ]]; then
            log_error "duplicate node name in roster: ${NAME}"
            ERRORS=$((ERRORS + 1))
        fi
        _SEEN_NAMES[$NAME]=1
    done
    unset _SEEN_NAMES

    # warnings — soft failures
    if (( ${#RELAY_IPS[@]} == 0 )); then
        log_warn "no --relay node defined"
        log_warn "NAT traversal will not work for double-NAT scenarios"
    fi

    # relay behind NAT warning
    for i in "${!RELAY_IPS[@]}"; do
        local RELAY="${RELAY_IPS[$i]}"
        # check if relay IP looks like a private/internal address
        if [[ "$RELAY" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
            log_warn "relay node ${RELAY} appears to be behind NAT"
            log_warn "relay nodes should have public IPs for reliable forwarding"
        fi
    done

    return $ERRORS
}

# =============================================================================
# main parse loop
# =============================================================================

_parse_roster() {
    local FILE="$1"
    local MY_DETECTED_IP="$2"
    local LINE_NUM=0
    local NODE_POSITION=0
    local PARSE_ERRORS=0

    while IFS= read -r RAW_LINE; do
        LINE_NUM=$((LINE_NUM + 1))

        # normalize whitespace
        local LINE
        LINE=$(echo "$RAW_LINE" | xargs 2>/dev/null || echo "$RAW_LINE")

        # skip blank lines
        [[ -z "$LINE" ]] && continue

        # skip comments
        [[ "$LINE" =~ ^# ]] && continue

        # parse header values — these do not count as nodes
        if [[ "$LINE" =~ ^SUBNET= ]]; then
            SUBNET="${LINE#*=}"
            # validate subnet format x.x.x
            if ! [[ "$SUBNET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                log_error "line ${LINE_NUM}: SUBNET '${SUBNET}' is not valid format (expected x.x.x e.g. 10.10.0)"
                PARSE_ERRORS=$((PARSE_ERRORS + 1))
            fi
            continue
        fi
        if [[ "$LINE" =~ ^WG_PORT= ]];   then WG_PORT="${LINE#*=}";   continue; fi
        if [[ "$LINE" =~ ^LDOWN_PORT= ]]; then LDOWN_PORT="${LINE#*=}"; continue; fi

        # everything past here is a node line
        NODE_POSITION=$((NODE_POSITION + 1))

        # extract public IP — always first field
        local NODE_IP
        NODE_IP=$(echo "$LINE" | awk '{print $1}')

        # extract flags
        local NODE_NAME NODE_TUNNEL NODE_PORT NODE_KEEPALIVE
        local NODE_IS_CZAR NODE_IS_RELAY
        NODE_NAME=$(parse_flag "$LINE" "--name")
        NODE_TUNNEL=$(parse_flag "$LINE" "--tunnel")
        NODE_PORT=$(parse_flag "$LINE" "--port")
        NODE_KEEPALIVE=$(parse_flag "$LINE" "--keepalive")
        NODE_IS_CZAR=$(has_flag "$LINE" "--czar")
        NODE_IS_RELAY=$(has_flag "$LINE" "--relay")

        # validate flag values — hard error on bad types
        if ! _validate_flag_values \
            "$NODE_NAME" "$NODE_PORT" "$NODE_KEEPALIVE" "$NODE_TUNNEL" \
            "$LINE_NUM"; then
            PARSE_ERRORS=$((PARSE_ERRORS + 1))
            continue
        fi

        # fallback name to position-based default
        [[ -z "$NODE_NAME" ]] && NODE_NAME="node-${NODE_POSITION}"

        # assign tunnel IP — manual override wins
        local TUNNEL_IP
        if [[ -n "$NODE_TUNNEL" ]]; then
            TUNNEL_IP="$NODE_TUNNEL"
        else
            TUNNEL_IP="${SUBNET}.${NODE_POSITION}"
        fi

        # record czar count
        [[ "$NODE_IS_CZAR" == "true" ]] && _CZAR_COUNT=$((_CZAR_COUNT + 1))

        # track all values for duplicate detection
        _ALL_PUBLIC_IPS+=("$NODE_IP")
        _ALL_TUNNEL_IPS+=("$TUNNEL_IP")
        _ALL_NAMES+=("$NODE_NAME")

        # czar identity
        if [[ "$NODE_IS_CZAR" == "true" ]]; then
            CZAR_IP="$NODE_IP"
            CZAR_TUNNEL_IP="$TUNNEL_IP"
            CZAR_NAME="$NODE_NAME"
        fi

        # relay list
        if [[ "$NODE_IS_RELAY" == "true" ]]; then
            RELAY_IPS+=("$NODE_IP")
            RELAY_TUNNEL_IPS+=("$TUNNEL_IP")
        fi

        # is this me?
        if [[ "$NODE_IP" == "$MY_DETECTED_IP" ]]; then
            MY_IP="$NODE_IP"
            MY_NAME="$NODE_NAME"
            MY_TUNNEL_IP="$TUNNEL_IP"
            MY_POSITION="$NODE_POSITION"
            MY_WG_PORT="${NODE_PORT:-$WG_PORT}"
            MY_KEEPALIVE="$NODE_KEEPALIVE"
            MY_IS_CZAR="$NODE_IS_CZAR"
            MY_IS_RELAY="$NODE_IS_RELAY"
        else
            # add to peer arrays — self never appears here
            PEER_IPS+=("$NODE_IP")
            PEER_TUNNEL_IPS+=("$TUNNEL_IP")
            PEER_NAMES+=("$NODE_NAME")
            PEER_PORTS+=("${NODE_PORT:-$WG_PORT}")
            PEER_KEEPALIVES+=("$NODE_KEEPALIVE")
        fi

        NODE_COUNT=$((NODE_COUNT + 1))

    done < "$FILE"

    return $PARSE_ERRORS
}

# =============================================================================
# public API
# =============================================================================

# primary entry point — load and validate roster
# usage: roster_load [path/to/roster.conf]
roster_load() {
    local FILE="${1:-$ROSTER_FILE}"

    # update global
    ROSTER_FILE="$FILE"

    # file must exist and be readable
    if [[ ! -f "$FILE" ]]; then
        log_error "roster.conf not found: ${FILE}"
        return 1
    fi

    if [[ ! -r "$FILE" ]]; then
        log_error "roster.conf is not readable: ${FILE}"
        return 1
    fi

    # reset all state
    _roster_reset

    # compute hash before anything touches the file
    ROSTER_HASH=$(sha256sum "$FILE" | awk '{print $1}')

    # verify signature if applicable
    if ! _verify_roster_signature "$FILE"; then
        return 1
    fi

    # detect this machine's IP
    local MY_DETECTED_IP
    MY_DETECTED_IP=$(_detect_my_ip "$FILE")
    local DETECT_STATUS=$?

    if (( DETECT_STATUS != 0 )) || [[ -z "$MY_DETECTED_IP" ]]; then
        log_error "could not detect this machine's IP from roster"
        log_error "checked: ip route, hostname -I, ifconfig.me"
        log_error "none matched any entry in ${FILE}"
        return 1
    fi

    # parse the roster
    if ! _parse_roster "$FILE" "$MY_DETECTED_IP"; then
        log_error "roster parsing failed — fix errors above before continuing"
        return 1
    fi

    # validate post-parse
    if ! _validate_roster; then
        log_error "roster validation failed — fix errors above before continuing"
        return 1
    fi

    log_ok "roster loaded — ${NODE_COUNT} nodes, czar ${CZAR_IP}, ${#RELAY_IPS[@]} relay(s)"
    return 0
}

# return this node's tunnel IP
roster_my_tunnel_ip() {
    echo "$MY_TUNNEL_IP"
}

# return czar IP
roster_get_czar() {
    echo "$CZAR_IP"
}

# return relay IPs as newline separated list
roster_get_relays() {
    local IP
    for IP in "${RELAY_IPS[@]}"; do
        echo "$IP"
    done
}

# return peer count (excludes self)
roster_peer_count() {
    echo "${#PEER_IPS[@]}"
}

# return total node count (includes self)
roster_node_count() {
    echo "$NODE_COUNT"
}

# return roster hash
roster_hash() {
    echo "$ROSTER_HASH"
}

# return true if this node is czar
roster_is_czar() {
    [[ "$MY_IS_CZAR" == "true" ]]
}

# return true if this node is a relay
roster_is_relay() {
    [[ "$MY_IS_RELAY" == "true" ]]
}

# print full parsed state — useful for debugging and make_roster output
roster_dump() {
    log_info "roster state dump"
    echo ""
    echo "  ROSTER_FILE     = ${ROSTER_FILE}"
    echo "  ROSTER_HASH     = ${ROSTER_HASH}"
    echo "  NODE_COUNT      = ${NODE_COUNT}"
    echo "  SUBNET          = ${SUBNET}"
    echo "  WG_PORT         = ${WG_PORT}"
    echo "  LDOWN_PORT      = ${LDOWN_PORT}"
    echo ""
    echo "  MY_IP           = ${MY_IP}"
    echo "  MY_NAME         = ${MY_NAME}"
    echo "  MY_TUNNEL_IP    = ${MY_TUNNEL_IP}"
    echo "  MY_POSITION     = ${MY_POSITION}"
    echo "  MY_WG_PORT      = ${MY_WG_PORT}"
    echo "  MY_KEEPALIVE    = ${MY_KEEPALIVE:-none}"
    echo "  MY_IS_CZAR      = ${MY_IS_CZAR}"
    echo "  MY_IS_RELAY     = ${MY_IS_RELAY}"
    echo ""
    echo "  CZAR_IP         = ${CZAR_IP}"
    echo "  CZAR_TUNNEL_IP  = ${CZAR_TUNNEL_IP}"
    echo "  CZAR_NAME       = ${CZAR_NAME}"
    echo ""
    echo "  RELAYS          = ${RELAY_IPS[*]:-none}"
    echo ""
    echo "  PEERS:"
    local i
    for i in "${!PEER_IPS[@]}"; do
        printf "    [%d] %-20s tunnel=%-15s name=%-15s port=%s keepalive=%s\n" \
            "$((i+1))" \
            "${PEER_IPS[$i]}" \
            "${PEER_TUNNEL_IPS[$i]}" \
            "${PEER_NAMES[$i]}" \
            "${PEER_PORTS[$i]}" \
            "${PEER_KEEPALIVES[$i]:-none}"
    done
}

# =============================================================================
# end roster.sh
# =============================================================================
