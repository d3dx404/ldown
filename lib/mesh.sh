#!/usr/bin/env bash
# =============================================================================
# mesh.sh — mesh orchestration commands
# part of ldown — deterministic self-healing WireGuard mesh orchestrator
# =============================================================================
#
# sourced by bin/ldown — never run directly
# requires: common.sh, wireguard.sh, roster.sh already sourced
# =============================================================================

[[ -n "${_MESH_SH_LOADED:-}" ]] && return 0
_MESH_SH_LOADED=1

_MESH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${_MESH_DIR}/roster.sh"

# =============================================================================
# internal helpers
# =============================================================================

# sign a control plane message with ed25519 or fallback to CLUSTER_TOKEN
# usage: sign_msg <payload>  →  Ed25519 signature or sha256(payload + CLUSTER_TOKEN)
# if czar key exists, use cryptographic signing; otherwise use HMAC fallback
sign_msg() {
  local payload="$1"
  local privkey="${KEY_DIR}/czar-control.key"
  if [[ ! -f "${privkey}" ]]; then
    printf '%s' "${payload}${CLUSTER_TOKEN}" | sha256sum | awk '{print $1}'
    return
  fi
  printf '%s' "${payload}" | \
    openssl dgst -sha256 -sign "${privkey}" | \
    base64 -w0
}

# serve this node's public key on LDOWN_PORT for exactly one connection
# used during mesh start bootstrap before listener.sh exists
# returns the background PID
_mesh_serve_pubkey() {
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
  [[ -f "${pubfile}" ]] || fatal "public key not found: ${pubfile}"
  ncat -l "${LDOWN_PORT}" --send-only --sh-exec "cat ${pubfile}" &
  echo $!
}

# fetch a peer's public key via ncat
# usage: _mesh_fetch_pubkey <peer_ip> <port>
# prints the key or returns 1 on failure
_mesh_fetch_pubkey() {
  local ip="$1"
  local port="$2"
  local key
  key="$(printf 'PUBKEY\n' | ncat --wait 5 "${ip}" "${port}" 2>/dev/null)"
  [[ -n "${key}" ]] || return 1
  printf '%s\n' "${key}"
}

# fetch pubkey with retry — up to 10 attempts, 1s apart
# usage: _mesh_fetch_pubkey_retry <peer_ip> <port>
_mesh_fetch_pubkey_retry() {
  local ip="$1"
  local port="$2"
  local key=""
  local attempt
  for (( attempt = 1; attempt <= 10; attempt++ )); do
    key="$(_mesh_fetch_pubkey "${ip}" "${port}")" && {
      printf '%s\n' "${key}"
      return 0
    }
    sleep 1
  done
  return 1
}

# check handshake for a specific peer pubkey on an interface
# usage: _mesh_check_peer_handshake <iface> <peer_pubkey>
# returns 0 if handshake timestamp > 0, 1 otherwise
_mesh_check_peer_handshake() {
  local iface="$1"
  local peer_pubkey="$2"
  local ts
  ts="$(wg show "${iface}" latest-handshakes 2>/dev/null \
    | awk -v k="${peer_pubkey}" '$1==k {print $2}')"
  [[ -n "${ts}" && "${ts}" != "0" ]]
}

# sort peer indices by tunnel IP last octet for deterministic ordering
# usage: for i in $(_mesh_sorted_peer_indices); do ...
_mesh_sorted_peer_indices() {
  local i
  for i in "${!PEER_TUNNEL_IPS[@]}"; do
    printf '%s %s\n' "${PEER_TUNNEL_IPS[$i]}" "${i}"
  done | sort -t. -k4 -n | awk '{print $2}'
}

# =============================================================================
# cmd_mesh_init
# =============================================================================
# sets up this node from scratch:
#   - validates dependencies
#   - loads roster, confirms this node is in it
#   - generates WireGuard keypair if not present
#   - generates TLS cert
#   - writes /etc/ldown/mesh.conf
#   - creates log dirs
# =============================================================================

cmd_mesh_init() {
  banner
  require_root

  # parse flags
  local OPT_IP
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ip)
        OPT_IP="${2:-}"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done

  # export OPT_IP so roster.sh can use it for IP detection
  export OPT_IP

  step "checking dependencies"
  check_dependency wg openssl ncat

  step "loading roster"

  [[ -f "${ROSTER_CONF}" ]] || fatal "roster not found: ${ROSTER_CONF} — copy your roster.conf there before running init"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load — fix errors above"

  info "node identified: ${MY_NAME} (${MY_IP})"
  info "tunnel IP:       ${MY_TUNNEL_IP}"
  info "czar:            ${MY_IS_CZAR}"
  info "relay:           ${MY_IS_RELAY}"

  # ── create directories ──────────────────────────────────
  step "creating directories"

  local dirs=( "${CONFIG_DIR}" "${KEY_DIR}" "${WG_DIR}" "${PEER_DIR}" "${LOG_DIR}" )
  local d
  for d in "${dirs[@]}"; do
    if [[ ! -d "${d}" ]]; then
      must "create ${d}" mkdir -p "${d}"
      status_ok "created" "${d}"
    else
      status_ok "exists" "${d}"
    fi
  done

  must "secure key dir" chmod 700 "${KEY_DIR}"

  # ── wireguard keypair ───────────────────────────────────
  step "wireguard keypair"

  local privfile="${KEY_DIR}/${MY_NAME}.private.key"
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"

  if [[ -f "${privfile}" ]]; then
    info "keypair exists — skipping (use --rotate to regenerate)"
  else
    must "generate keypair" wg_generate_keypair_named "${MY_NAME}" "${KEY_DIR}"
    # verify pubkey was written correctly
    local verify_pub
    { read -r verify_pub < "${pubfile}"; } 2>/dev/null || true
    if [[ -z "${verify_pub}" ]]; then
      warn "keypair generation produced empty pubkey — regenerating"
      cat "${privfile}" | wg pubkey > "${pubfile}" || true
      chmod 644 "${pubfile}"
    fi
    status_ok "keypair generated" "${pubfile}"
  fi

  local my_pubkey
  { read -r my_pubkey < "${pubfile}"; } 2>/dev/null || true
  [[ -n "${my_pubkey}" ]] || fatal "pubkey is empty — check wireguard-tools"

  # ── node signing keypair ────────────────────────────────
  local node_key="${KEY_DIR}/${MY_NAME}-node.key"
  local node_pub="${KEY_DIR}/${MY_NAME}-node.pub"
  if [[ ! -f "${node_key}" ]]; then
    step "generating node signing keypair"
    openssl genpkey -algorithm ed25519 -out "${node_key}" 2>/dev/null
    openssl pkey -in "${node_key}" -pubout -out "${node_pub}" 2>/dev/null
    chmod 600 "${node_key}"
    chmod 644 "${node_pub}"
    status_ok "node signing keypair" "${node_pub}"
  else
    status_ok "node signing keypair exists" "${node_key} — skipping"
  fi

  # ── czar signing keypair ────────────────────────────────
  if [[ "${MY_IS_CZAR}" == "true" ]]; then
    local czar_key="/etc/ldown/keys/czar-control.key"
    local czar_pub="/etc/ldown/keys/czar-control.pub"
    if [[ ! -f "${czar_key}" ]]; then
      step "generating czar signing keypair"
      openssl genpkey -algorithm ed25519 -out "${czar_key}" 2>/dev/null
      openssl pkey -in "${czar_key}" -pubout -out "${czar_pub}" 2>/dev/null
      chmod 600 "${czar_key}"
      chmod 644 "${czar_pub}"
      status_ok "czar signing keypair" "${czar_pub}"
    else
      status_ok "czar signing keypair exists" "${czar_key} — skipping"
    fi
  fi

  # ── TLS cert ────────────────────────────────────────────
  step "TLS certificate"

  if [[ -f "${TLS_CERT}" && -f "${TLS_KEY}" ]]; then
    status_ok "TLS cert exists" "${TLS_CERT} — skipping"
  else
    must "generate TLS cert" openssl req -x509 -newkey rsa:4096 \
      -keyout "${TLS_KEY}" \
      -out    "${TLS_CERT}" \
      -days   "${TLS_CERT_DAYS}" \
      -nodes  \
      -subj   "/CN=ldown-${MY_NAME}"

    must "secure TLS key" chmod 600 "${TLS_KEY}"
    status_ok "TLS cert written" "${TLS_CERT}"
    status_ok "TLS key written"  "${TLS_KEY}"
  fi

  local tls_fingerprint
  tls_fingerprint="$(openssl x509 -in "${TLS_CERT}" \
    -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  [[ -n "${tls_fingerprint}" ]] || fatal "failed to extract TLS fingerprint from ${TLS_CERT}"
  status_ok "fingerprint" "${tls_fingerprint}"

  # compute czar signing key fingerprint if available
  local czar_fp=""
  if [[ "${MY_IS_CZAR}" == "true" ]]; then
    czar_fp="$(openssl pkey \
      -in /etc/ldown/keys/czar-control.pub \
      -pubin -outform DER 2>/dev/null \
      | sha256sum | awk '{print $1}')"
  elif [[ -f "/etc/ldown/keys/czar-control.pub" ]]; then
    czar_fp="$(openssl pkey \
      -in /etc/ldown/keys/czar-control.pub \
      -pubin -outform DER 2>/dev/null \
      | sha256sum | awk '{print $1}')"
  fi

  # extract node signing public key for mesh.conf
  local node_signing_pub
  node_signing_pub="$(cat "${node_pub}" 2>/dev/null | tr -d '\n')"

  # ── write mesh.conf ─────────────────────────────────────
  step "writing mesh.conf"

  local ts
  printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1

  write_conf "${MESH_CONF}" "# generated by ldown mesh init — ${ts}
MY_IP=${MY_IP}
MY_NAME=${MY_NAME}
MY_TUNNEL_IP=${MY_TUNNEL_IP}
MY_POSITION=${MY_POSITION}
MY_WG_PORT=${MY_WG_PORT}
MY_IS_CZAR=${MY_IS_CZAR}
MY_IS_RELAY=${MY_IS_RELAY}
CZAR_IP=${CZAR_IP}
CZAR_TUNNEL_IP=${CZAR_TUNNEL_IP}
WG_PORT=${WG_PORT}
LDOWN_PORT=${LDOWN_PORT}
SUBNET=${SUBNET}
TLS_FINGERPRINT=\"${tls_fingerprint}\"
CZAR_PUBKEY_FP=\"${czar_fp}\"
NODE_SIGNING_PUBKEY=\"${node_signing_pub}\"
WG_PUBKEY=\"${my_pubkey}\"
INIT_TIME=\"${ts}\""

  must "secure mesh.conf" chmod 600 "${MESH_CONF}"
  status_ok "mesh.conf written" "${MESH_CONF}"

  # ── initialize logs ─────────────────────────────────────
  step "initializing logs"

  local logfiles=( "${LOG_MAIN}" "${LOG_LISTENER}" "${LOG_SYNC}" "${LOG_SECURITY}" )
  local lf
  for lf in "${logfiles[@]}"; do
    must "create log ${lf}" touch "${lf}"
    must "secure log ${lf}" chmod 640 "${lf}"
    status_ok "log ready" "${lf}"
  done

  printf '\n'
  success "init complete — ${MY_NAME} is ready"
  printf '\n'
  info "next step: ldown mesh start"
  printf '\n'
}

# =============================================================================
# cmd_mesh_start
# =============================================================================
# forms the full mesh — run on every node after init is complete on all nodes
#
# flow:
#   1. verify init has been run
#   2. load roster
#   3. serve this node's public key on LDOWN_PORT (bootstrap exchange)
#   4. bring up WireGuard interface
#   5. for each peer (sorted by tunnel IP): fetch pubkey with retry, add to interface
#   6. verify per-peer handshakes
# =============================================================================

cmd_mesh_start() {
  banner
  require_root
  check_dependency wg ncat
    # ── pre-flight teardown ─────────────────────────────────
  step "pre-flight cleanup"
  
  # kill any stale listener or bootstrap ncat on control port
  fuser -k "${LDOWN_PORT}"/tcp 2>/dev/null || true
  pkill -f "ncat.*${LDOWN_PORT}" 2>/dev/null || true
  
  # bring down WG interface if already up — ensures clean state
  if is_valid_iface "${WG_INTERFACE}"; then
    wg-quick down "${WG_INTERFACE}" 2>/dev/null || \
      ip link delete "${WG_INTERFACE}" 2>/dev/null || true
    status_ok "interface cleared" "${WG_INTERFACE}"
  fi
  
  # kill any stale listener daemon
  local listener_pid=""
  local pidfile="/run/ldown/listener.pid"
  if [[ -f "${pidfile}" ]]; then
    { read -r listener_pid < "${pidfile}"; } 2>/dev/null
    [[ -n "${listener_pid}" ]] && kill "${listener_pid}" 2>/dev/null || true
    rm -f "${pidfile}" /tmp/ldown-handler.* 2>/dev/null || true
    status_ok "listener cleared" "pid ${listener_pid:-unknown}"
  fi
                               
  sleep 0.5
  status_ok "pre-flight done" "ready to start"
  step "verifying init"

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — run: ldown mesh init"
  [[ -f "${TLS_CERT}" ]]  || fatal "TLS cert not found — run: ldown mesh init"

  source_if_exists "${MESH_CONF}"

  [[ -n "${MY_NAME:-}" ]]      || fatal "mesh.conf missing MY_NAME — re-run: ldown mesh init"
  [[ -n "${MY_TUNNEL_IP:-}" ]] || fatal "mesh.conf missing MY_TUNNEL_IP — re-run: ldown mesh init"
  [[ -n "${MY_WG_PORT:-}" ]]   || fatal "mesh.conf missing MY_WG_PORT — re-run: ldown mesh init"

  local privfile="${KEY_DIR}/${MY_NAME}.private.key"
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
  [[ -f "${privfile}" ]] || fatal "private key not found: ${privfile} — re-run: ldown mesh init"
  [[ -f "${pubfile}" ]]  || fatal "public key not found: ${pubfile} — re-run: ldown mesh init"
  status_ok "init verified" "${MY_NAME}"

  step "loading roster"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load — fix errors above"
  
  if [[ "${MY_IS_CZAR}" != "true" ]]; then
    fatal "this node is not the czar — use: ldown mesh join"
  fi

  step "bringing up WireGuard interface"

  local privkey
  read -r privkey < "${privfile}"

  wg_write_interface \
    "${WG_DIR}/interface.conf" \
    "${MY_TUNNEL_IP}/24" \
    "${MY_WG_PORT}" \
    "${privkey}"

  must "copy interface config" cp "${WG_DIR}/interface.conf" "${WG_DIR}/${WG_INTERFACE}.conf"
  wg_sync "${WG_INTERFACE}" "${WG_DIR}/${WG_INTERFACE}.conf"
  status_ok "interface up" "${WG_INTERFACE} — ${MY_TUNNEL_IP}/24"

  export LDOWN_QUIET=true
  source "${BASH_SOURCE[0]%/*}/listener.sh"
  cmd_listener_start
  source "${BASH_SOURCE[0]%/*}/sync.sh"
  cmd_sync_start
  export LDOWN_QUIET=false
  success "mesh started — ${MY_NAME} is live"
  printf '\n'
  if [[ "${OPT_WATCH:-false}" == "true" ]]; then
    cmd_mesh_watch
  fi
  exit 0
}

# =============================================================================
# cmd_mesh_join
# =============================================================================
# join a live mesh via the czar — run on a new node after init
#
# flow:
#   1. verify init done, load mesh.conf + roster
#   2. bring up WireGuard interface
#   3. send our pubkey + identity to czar
#   4. receive peer list from czar (NAME TUNNEL_IP PUBLIC_IP:PORT PUBKEY [KEEPALIVE])
#   5. connect to all peers, verify per-peer handshakes
# =============================================================================

cmd_mesh_join() {
  banner
  require_root
  check_dependency wg ncat

  # check for existing join process
  local existing_join
  existing_join=$(pgrep -f "ldown mesh join" 2>/dev/null | \
    grep -v "^$$\$" | head -1)
  if [[ -n "${existing_join}" ]]; then
    warn "mesh join already running (pid ${existing_join})"
    warn "running multiple joins simultaneously causes listener conflicts"
    confirm "kill existing join process and start fresh?" || \
      { info "join cancelled"; exit 1; }
    kill "${existing_join}" 2>/dev/null || true
    sleep 1
  fi

  step "verifying init"

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — run: ldown mesh init"
  [[ -f "${TLS_CERT}" ]]  || fatal "TLS cert not found — run: ldown mesh init"

  source_if_exists "${MESH_CONF}"

  [[ -n "${MY_NAME:-}" ]]      || fatal "mesh.conf missing MY_NAME — re-run: ldown mesh init"
  [[ -n "${MY_TUNNEL_IP:-}" ]] || fatal "mesh.conf missing MY_TUNNEL_IP — re-run: ldown mesh init"
  [[ -n "${MY_WG_PORT:-}" ]]   || fatal "mesh.conf missing MY_WG_PORT — re-run: ldown mesh init"

  local privfile="${KEY_DIR}/${MY_NAME}.private.key"
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
  [[ -f "${privfile}" ]] || fatal "private key not found: ${privfile} — re-run: ldown mesh init"
  [[ -f "${pubfile}" ]]  || fatal "public key not found: ${pubfile} — re-run: ldown mesh init"

  local my_pubkey
  read -r my_pubkey < "${pubfile}"
  status_ok "init verified" "${MY_NAME}"

  step "loading roster"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load — fix errors above"
  
  if [[ "${MY_IS_CZAR}" == "true" ]]; then
    fatal "czar nodes use mesh start, not mesh join"
  fi
  
  [[ -n "${CZAR_IP:-}" ]] || fatal "no czar found in roster"
  info "czar: ${CZAR_IP} (${CZAR_TUNNEL_IP})"

  step "bringing up WireGuard interface"

  local privkey
  read -r privkey < "${privfile}"

  wg_write_interface \
    "${WG_DIR}/interface.conf" \
    "${MY_TUNNEL_IP}/24" \
    "${MY_WG_PORT}" \
    "${privkey}"

  must "copy interface config" cp "${WG_DIR}/interface.conf" "${WG_DIR}/${WG_INTERFACE}.conf"
  wg_sync "${WG_INTERFACE}" "${WG_DIR}/${WG_INTERFACE}.conf"
  status_ok "interface up" "${WG_INTERFACE} — ${MY_TUNNEL_IP}/24"

  step "contacting czar"
  info "sending identity to czar at ${CZAR_IP}:${LDOWN_PORT}"

  local node_signing_pub
  node_signing_pub="$(openssl pkey \
    -in /etc/ldown/keys/${MY_NAME}-node.pub \
    -pubin -outform DER 2>/dev/null | base64 -w0)"

  local peer_list
  local _join_payload="JOIN ${MY_NAME} ${MY_TUNNEL_IP} ${MY_IP} ${my_pubkey} ${node_signing_pub}"
  peer_list="$(printf '%s\n' "$(sign_msg "${_join_payload}" "true") ${_join_payload}" \
    | ncat "${CZAR_IP}" "${LDOWN_PORT}" 2>/dev/null)" || \
    fatal "could not reach czar at ${CZAR_IP}:${LDOWN_PORT} — is the mesh running?"

  [[ -n "${peer_list}" ]] || \
    fatal "czar returned empty peer list — join rejected or czar not ready"
  status_ok "czar responded" "peer list received"

  step "connecting to peers"

  local confirmed=0
  local failed=0
  declare -A _joined_pubkeys

  while IFS= read -r peer_line; do
    [[ -z "${peer_line}" ]] && continue
    [[ "${peer_line}" =~ ^ERROR ]] && fatal "czar rejected join: ${peer_line}"

    local peer_name peer_tunnel peer_endpoint peer_pubkey peer_keepalive peer_node_pub
    read -r peer_name peer_tunnel peer_endpoint peer_pubkey peer_keepalive peer_node_pub \
      <<< "${peer_line}"

    [[ "${peer_name}" == "${MY_NAME}" ]] && continue
    [[ -z "${peer_pubkey}" ]] && {
      warn "malformed peer line — skipping: ${peer_line}"
      failed=$(( failed + 1 ))
      continue
    }

    is_valid_wg_key "${peer_pubkey}" || {
      status_fail "${peer_name}" "invalid public key in peer list"
      failed=$(( failed + 1 ))
      continue
    }

    [[ "${peer_keepalive}" == "0" ]] && peer_keepalive=""
    
    if [[ -n "${peer_node_pub}" ]]; then
      printf '%s' "${peer_node_pub}" | base64 -d | \
        openssl pkey -pubin -inform DER -outform PEM \
        -out "${KEY_DIR}/${peer_name}-node.pub" 2>/dev/null
      chmod 644 "${KEY_DIR}/${peer_name}-node.pub"
    fi

    wg_write_peer \
      "${PEER_DIR}/peer-${peer_tunnel}.conf" \
      "${peer_pubkey}" \
      "${peer_tunnel}/32" \
      "${peer_endpoint}" \
      "${peer_keepalive:-}"

    local wg_args=(
      wg set "${WG_INTERFACE}"
      peer "${peer_pubkey}"
      allowed-ips "${peer_tunnel}/32"
      endpoint "${peer_endpoint}"
    )
    [[ -n "${peer_keepalive:-}" ]] && wg_args+=(persistent-keepalive "${peer_keepalive}")

    must "add peer ${peer_name}" "${wg_args[@]}"
    _joined_pubkeys["${peer_name}"]="${peer_pubkey}"
    status_ok "${peer_name}" "${peer_tunnel} via ${peer_endpoint}"
    confirmed=$(( confirmed + 1 ))

  done <<< "${peer_list}"

  step "assembling final config"
  wg_assemble_config "${WG_DIR}" "${WG_INTERFACE}"
  status_ok "config written" "${WG_DIR}/${WG_INTERFACE}.conf"

  step "verifying handshakes"

  local peer_name peer_pubkey
  for peer_name in "${!_joined_pubkeys[@]}"; do
    [[ "${peer_name}" == "${MY_NAME}" ]] && continue
    peer_pubkey="${_joined_pubkeys[$peer_name]}"
    local attempt
    for (( attempt = 1; attempt <= 20; attempt++ )); do
      if _mesh_check_peer_handshake "${WG_INTERFACE}" "${peer_pubkey}"; then
        status_ok "${peer_name}" "handshake confirmed"
        break
      fi
      sleep 1
    done
    [[ $attempt -gt 20 ]] && status_warn "${peer_name}" "no handshake yet — sync loop will connect within 30s"
  done

  printf '\n'
  divider
  status_ok "peers connected" "${confirmed}"
  [[ "${failed}" -gt 0 ]] && status_warn "peers skipped" "${failed}"
  divider
  printf '\n'

  if (( failed > 0 )); then
    printf '\n'
    info "some peers not yet reachable — this is normal during join flood"
    info "the sync loop runs every 30s and will connect missing peers"
    info "run: ldown mesh status --watch  to watch them come online"
    printf '\n'
  fi

  if [[ "${confirmed}" -eq 0 ]]; then
    warn "connected to 0 peers — czar may be only node, or timing issue"
    warn "sync loop will attempt recovery — use: ldown mesh recover if needed"
  fi
  
  source "${BASH_SOURCE[0]%/*}/listener.sh"
  cmd_listener_start
  source "${BASH_SOURCE[0]%/*}/sync.sh"
  cmd_sync_start

  success "${MY_NAME} has joined the mesh"
  printf '\n'
  if [[ "${OPT_WATCH:-false}" == "true" ]]; then
    cmd_mesh_watch
  fi
  exit 0
}

# =============================================================================
# cmd_mesh_leave
# =============================================================================
# graceful departure from the mesh
#
# flow:
#   1. verify mesh state exists
#   2. load roster
#   3. notify czar
#   4. tear down WireGuard interface
#   5. remove peer configs and wg config
#   6. remove mesh.conf (keys + TLS kept for rejoin)
# =============================================================================

cmd_mesh_leave() {
  banner
  require_root
  check_dependency wg ncat

  step "verifying mesh state"

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — not part of a mesh"
  source_if_exists "${MESH_CONF}"
  [[ -n "${MY_NAME:-}" ]] || fatal "mesh.conf missing MY_NAME"

  if ! is_valid_iface "${WG_INTERFACE}"; then
    warn "WireGuard interface ${WG_INTERFACE} is not up — will clean up state only"
  else
    status_ok "interface" "${WG_INTERFACE} is up"
  fi

  step "loading roster"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load"

  printf '\n'
  confirm "remove ${MY_NAME} from the mesh?" || { info "leave cancelled"; exit 0; }

  step "notifying czar"

  local my_pubkey=""
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
  [[ -f "${pubfile}" ]] && read -r my_pubkey < "${pubfile}"

  local _leave_payload="LEAVE ${MY_NAME} ${MY_TUNNEL_IP} ${my_pubkey}"
  local response
  response="$(printf '%s\n' "$(sign_msg "${_leave_payload}" "true") ${_leave_payload}" | ncat "${CZAR_IP}" "${LDOWN_PORT}" 2>/dev/null)" || true
  
  if [[ "${response}" == *"OK"* ]]; then
    status_ok "czar notified" "${CZAR_IP}"
  elif [[ -n "${response}" ]]; then
    warn "czar response: ${response}"
  else
    warn "czar did not respond — continuing with local cleanup"
  fi

  step "stopping daemons"

  kill "$(cat /run/ldown/listener.pid 2>/dev/null)" 2>/dev/null || true
  kill "$(cat /run/ldown/sync.pid 2>/dev/null)" 2>/dev/null || true
  status_ok "daemons stopped" "listener and sync"

  step "tearing down WireGuard interface"

  wg-quick down "${WG_INTERFACE}" 2>/dev/null || \
    ip link delete "${WG_INTERFACE}" 2>/dev/null || true
  status_ok "interface down" "${WG_INTERFACE}"

  step "removing peer configs"

  local count=0
  if [[ -d "${PEER_DIR}" ]]; then
    local f
    for f in "${PEER_DIR}"/peer-*.conf; do
      [[ -f "${f}" ]] || continue
      rm -f "${f}"
      count=$(( count + 1 ))
    done
  fi
  status_ok "peer configs removed" "${count}"

  if [[ -f "${WG_DIR}/${WG_INTERFACE}.conf" ]]; then
    rm -f "${WG_DIR}/${WG_INTERFACE}.conf"
    status_ok "wg config removed" "${WG_DIR}/${WG_INTERFACE}.conf"
  fi

  step "clearing mesh state"

  rm -f "${MESH_CONF}"
  status_ok "mesh.conf removed" "${MESH_CONF}"

  rm -f /run/ldown/listener.pid /run/ldown/sync.pid
  status_ok "PID files cleaned" ""

  printf '\n'
  success "${MY_NAME} has left the mesh"
  printf '\n'
  info "keys and TLS cert kept in ${KEY_DIR} — run init + join to rejoin"
  printf '\n'
}

# =============================================================================
# cmd_mesh_recover
# =============================================================================
# rebuild the mesh from zero saved state — the killer feature
# no mesh.conf needed — just roster.conf + keys + live peers
#
# flow:
#   1. verify roster + keys exist
#   2. recreate directories
#   3. bring up WireGuard interface
#   4. probe each peer (sorted) with retry — fetch pubkey from whoever responds
#   5. build peer configs, add to interface
#   6. rebuild mesh.conf
# =============================================================================

cmd_mesh_recover() {
  banner
  require_root
  check_dependency wg ncat

  step "verifying keys"

  [[ -f "${ROSTER_CONF}" ]] || fatal "roster not found: ${ROSTER_CONF} — cannot recover without roster"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load — fix errors above"

  local privfile="${KEY_DIR}/${MY_NAME}.private.key"
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
  [[ -f "${privfile}" ]] || fatal "private key not found: ${privfile} — run: ldown mesh init"
  [[ -f "${pubfile}" ]]  || fatal "public key not found: ${pubfile} — run: ldown mesh init"

  local my_pubkey
  read -r my_pubkey < "${pubfile}"

  status_ok "identity"   "${MY_NAME} (${MY_IP})"
  status_ok "tunnel IP"  "${MY_TUNNEL_IP}"
  status_ok "keys found" "${KEY_DIR}"

  # ensure local listener is up before probing peers
  if ! bin/ldown listener status &>/dev/null; then
    bin/ldown listener start
  fi

  step "recreating directories"

  local dirs=( "${CONFIG_DIR}" "${KEY_DIR}" "${WG_DIR}" "${PEER_DIR}" "${LOG_DIR}" )
  local d
  for d in "${dirs[@]}"; do
    [[ -d "${d}" ]] || must "create ${d}" mkdir -p "${d}"
  done
  must "secure key dir" chmod 700 "${KEY_DIR}"
  status_ok "directories ready" "${CONFIG_DIR}"

  step "bringing up WireGuard interface"

  ip link delete "${WG_INTERFACE}" 2>/dev/null || true
  sleep 0.5

  local privkey
  read -r privkey < "${privfile}" || true

  if [[ -z "${privkey}" ]]; then
    fatal "private key not found at ${privfile} — run: ldown mesh init"
  fi

  wg_write_interface \
    "${WG_DIR}/interface.conf" \
    "${MY_TUNNEL_IP}/24" \
    "${MY_WG_PORT}" \
    "${privkey}"

  must "copy interface config" cp "${WG_DIR}/interface.conf" "${WG_DIR}/${WG_INTERFACE}.conf"
  wg_sync "${WG_INTERFACE}" "${WG_DIR}/${WG_INTERFACE}.conf" || true
  status_ok "interface up" "${WG_INTERFACE} — ${MY_TUNNEL_IP}/24"

  step "probing peers"

  local recovered=0
  local failed=0
  declare -A _recovered_pubkeys

  local i
  for i in $(_mesh_sorted_peer_indices); do
    local peer_ip="${PEER_IPS[$i]}"
    local peer_tunnel="${PEER_TUNNEL_IPS[$i]}"
    local peer_name="${PEER_NAMES[$i]}"
    local peer_port="${PEER_PORTS[$i]}"
    local peer_keepalive="${PEER_KEEPALIVES[$i]:-}"

    printf '\n'
    info "probing ${peer_name} (${peer_ip})"

    local peer_pubkey
    peer_pubkey="$(_mesh_fetch_pubkey_retry "${peer_ip}" "${LDOWN_PORT}")" || {
      status_fail "${peer_name}" "could not fetch public key from ${peer_ip}:${LDOWN_PORT} after 10s"
      failed=$(( failed + 1 ))
      continue
    }

    is_valid_wg_key "${peer_pubkey}" || {
      status_fail "${peer_name}" "invalid public key received from ${peer_ip}"
      failed=$(( failed + 1 ))
      continue
    }

    wg_write_peer \
      "${PEER_DIR}/peer-${peer_tunnel}.conf" \
      "${peer_pubkey}" \
      "${peer_tunnel}/32" \
      "${peer_ip}:${peer_port}" \
      "${peer_keepalive}"

    local wg_args=(
      wg set "${WG_INTERFACE}"
      peer "${peer_pubkey}"
      allowed-ips "${peer_tunnel}/32"
      endpoint "${peer_ip}:${peer_port}"
    )
    [[ -n "${peer_keepalive}" ]] && wg_args+=(persistent-keepalive "${peer_keepalive}")

    must "add peer ${peer_name}" "${wg_args[@]}"
    _recovered_pubkeys[$i]="${peer_pubkey}"
    status_ok "${peer_name}" "${peer_tunnel} via ${peer_ip}:${peer_port}"
    recovered=$(( recovered + 1 ))
  done

  step "rebuilding mesh.conf"

  local tls_fingerprint=""
  [[ -f "${TLS_CERT}" ]] && \
    tls_fingerprint="$(openssl x509 -in "${TLS_CERT}" \
      -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"

  local ts
  printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1

  write_conf "${MESH_CONF}" "# rebuilt by ldown mesh recover — ${ts}
MY_IP=${MY_IP}
MY_NAME=${MY_NAME}
MY_TUNNEL_IP=${MY_TUNNEL_IP}
MY_POSITION=${MY_POSITION}
MY_WG_PORT=${MY_WG_PORT}
MY_IS_CZAR=${MY_IS_CZAR}
MY_IS_RELAY=${MY_IS_RELAY}
CZAR_IP=${CZAR_IP}
CZAR_TUNNEL_IP=${CZAR_TUNNEL_IP}
WG_PORT=${WG_PORT}
LDOWN_PORT=${LDOWN_PORT}
SUBNET=${SUBNET}
TLS_FINGERPRINT=\"${tls_fingerprint}\"
WG_PUBKEY=\"${my_pubkey}\"
INIT_TIME=\"${ts}\""

  must "secure mesh.conf" chmod 600 "${MESH_CONF}"
  status_ok "mesh.conf rebuilt" "${MESH_CONF}"

  wg_assemble_config "${WG_DIR}" "${WG_INTERFACE}"
  status_ok "config written" "${WG_DIR}/${WG_INTERFACE}.conf"

  printf '\n'
  divider
  status_ok "peers recovered"   "${recovered}/${#PEER_IPS[@]}"
  [[ "${failed}" -gt 0 ]] && \
    status_warn "peers failed" "${failed} — check connectivity and public key validity"
  divider
  printf '\n'

  [[ "${recovered}" -eq 0 ]] && \
    fatal "no peers responded — ensure at least one peer is online"

  source "${BASH_SOURCE[0]%/*}/listener.sh"
  cmd_listener_start
  source "${BASH_SOURCE[0]%/*}/sync.sh"
  cmd_sync_start

  success "${MY_NAME} recovered — back in the mesh"
  printf '\n'
}

# =============================================================================
# cmd_mesh_export
# =============================================================================
# create an encrypted onboarding bundle for a new node
# contains: roster.conf, cluster.pub, tls.cert, mesh_export.conf
# never contains private keys
# output: ldown-export-<timestamp>.tar.gz.enc
# =============================================================================

cmd_mesh_export() {
  banner
  require_root
  check_dependency openssl tar

  step "verifying state"

  [[ -f "${MESH_CONF}" ]]   || fatal "mesh.conf not found — run: ldown mesh init"
  [[ -f "${ROSTER_CONF}" ]] || fatal "roster.conf not found: ${ROSTER_CONF}"
  [[ -f "${TLS_CERT}" ]]    || fatal "TLS cert not found — run: ldown mesh init"

  source_if_exists "${MESH_CONF}"
  [[ -n "${MY_NAME:-}" ]] || fatal "mesh.conf missing MY_NAME"
  status_ok "state verified" "${MY_NAME}"

  local ts
  printf -v ts '%(%Y%m%d_%H%M%S)T' -1
  local bundle_name="ldown-export-${ts}"
  local output_dir="${1:-.}"
  local bundle_out="${output_dir}/${bundle_name}.tar.gz.enc"

  step "assembling bundle"

  local tmpdir
  tmpdir="$(mktemp -d)" || fatal "cannot create temp directory"
  trap 'rm -rf "${tmpdir}"' EXIT

  local stagedir="${tmpdir}/${bundle_name}"
  must "create staging dir" mkdir -p "${stagedir}"

  must "copy roster"   cp "${ROSTER_CONF}" "${stagedir}/roster.conf"
  status_ok "included" "roster.conf"

  must "copy TLS cert" cp "${TLS_CERT}" "${stagedir}/tls.cert"
  status_ok "included" "tls.cert"

  local czar_pub="/etc/ldown/keys/czar-control.pub"
  if [[ -f "${czar_pub}" ]]; then
    cp "${czar_pub}" "${stagedir}/cluster.pub"
    status_ok "included" "cluster.pub (czar signing key)"
  else
    fatal "czar-control.pub not found — run: ldown mesh init first"
  fi

  write_conf "${stagedir}/mesh_export.conf" "# ldown export bundle — ${ts}
# generated by: ${MY_NAME}
CZAR_IP=${CZAR_IP}
CZAR_TUNNEL_IP=${CZAR_TUNNEL_IP}
LDOWN_PORT=${LDOWN_PORT}
WG_PORT=${WG_PORT}
SUBNET=${SUBNET}
EXPORTED_BY=${MY_NAME}
EXPORTED_AT=${ts}"
  status_ok "included" "mesh_export.conf"

  if find "${stagedir}" -name "*.private.key" | grep -q .; then
    fatal "private key detected in bundle — aborting"
  fi

  step "compressing bundle"
  local tarball="${tmpdir}/${bundle_name}.tar.gz"
  must "create tarball" tar -czf "${tarball}" -C "${tmpdir}" "${bundle_name}"
  status_ok "compressed" "${bundle_name}.tar.gz"

  step "encrypting bundle"
  info "you will be prompted for a passphrase — share it securely with the new node"
  printf '\n'

  must "encrypt bundle" openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
    -in  "${tarball}" \
    -out "${bundle_out}"

  must "secure bundle" chmod 600 "${bundle_out}"
  status_ok "encrypted bundle" "${bundle_out}"

  printf '\n'
  success "export complete"
  printf '\n'
  info "send ${bundle_out} to the new node"
  info "on the new node run: ldown mesh import ${bundle_out}"
  printf '\n'
}

# =============================================================================
# cmd_mesh_import
# =============================================================================
# unpack an export bundle and prepare this node to join
# run on a brand new node before: ldown mesh init + ldown mesh join
#
# flow:
#   1. decrypt bundle
#   2. validate contents — reject if any private key present
#   3. install roster.conf, tls.cert, cluster.pub, mesh_export.conf
#   4. prompt to run init next
# =============================================================================

cmd_mesh_import() {
  banner
  require_root
  check_dependency openssl tar

  local bundle="${1:-}"
  [[ -n "${bundle}" ]] || fatal "usage: ldown mesh import <bundle.tar.gz.enc>"
  [[ -f "${bundle}" ]] || fatal "bundle not found: ${bundle}"

  step "importing bundle"
  info "bundle: ${bundle}"

  step "decrypting bundle"

  local tmpdir
  tmpdir="$(mktemp -d)" || fatal "cannot create temp directory"
  trap 'rm -rf "${tmpdir}"' EXIT

  local tarball="${tmpdir}/bundle.tar.gz"
  must "decrypt bundle" openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
    -in  "${bundle}" \
    -out "${tarball}"
  status_ok "decrypted" "ok"

  step "unpacking bundle"
  must "unpack tarball" tar -xzf "${tarball}" \
    --no-same-owner \
    --no-same-permissions \
    -C "${tmpdir}"

  # verify no path traversal in extracted files
  while IFS= read -r -d '' extracted_file; do
    local real_path
    real_path="$(realpath "${extracted_file}")"
    if [[ "${real_path}" != "${tmpdir}"* ]]; then
      fatal "path traversal detected in bundle: ${extracted_file}"
    fi
  done < <(find "${tmpdir}" -print0)

  local stagedir
  stagedir="$(find "${tmpdir}" -maxdepth 1 -mindepth 1 -type d | head -1)"
  [[ -n "${stagedir}" ]] || fatal "bundle appears empty after unpacking"
  status_ok "unpacked" "${stagedir}"

  step "validating bundle"

  [[ -f "${stagedir}/roster.conf" ]]      || fatal "bundle missing roster.conf"
  [[ -f "${stagedir}/mesh_export.conf" ]] || fatal "bundle missing mesh_export.conf"
  [[ -f "${stagedir}/tls.cert" ]]         || fatal "bundle missing tls.cert"

  if find "${stagedir}" -name "*.private.key" | grep -q .; then
    fatal "bundle contains a private key — do not use this bundle"
  fi

  status_ok "roster.conf"      "present"
  status_ok "mesh_export.conf" "present"
  status_ok "tls.cert"         "present"

  local import_file="${stagedir}/mesh_export.conf"
  local key val
  while IFS='=' read -r key val; do
    val="${val%\"}"
    val="${val#\"}"
    case "${key}" in
      CZAR_IP)         CZAR_IP="${val}" ;;
      CZAR_TUNNEL_IP)  CZAR_TUNNEL_IP="${val}" ;;
      LDOWN_PORT)      LDOWN_PORT="${val}" ;;
      WG_PORT)         WG_PORT="${val}" ;;
      SUBNET)          SUBNET="${val}" ;;
      EXPORTED_BY)     EXPORTED_BY="${val}" ;;
      EXPORTED_AT)     EXPORTED_AT="${val}" ;;
    esac
  done < "${import_file}"
  printf '\n'
  info "exported by: ${EXPORTED_BY:-unknown}"
  info "exported at: ${EXPORTED_AT:-unknown}"
  info "czar:        ${CZAR_IP:-unknown}"
  info "subnet:      ${SUBNET:-unknown}"
  printf '\n'

  confirm "install this bundle to ${CONFIG_DIR}?" || { info "import cancelled"; exit 0; }

  step "installing bundle"

  must "create config dir" mkdir -p "${CONFIG_DIR}"

  must "install roster.conf" cp "${stagedir}/roster.conf" "${ROSTER_CONF}"
  must "secure roster.conf"  chmod 640 "${ROSTER_CONF}"
  status_ok "installed" "${ROSTER_CONF}"

  must "install tls.cert" cp "${stagedir}/tls.cert" "${CONFIG_DIR}/peer-bootstrap.cert"
  status_ok "installed" "${CONFIG_DIR}/peer-bootstrap.cert"

  local bundle_czar_pub="${stagedir}/cluster.pub"
  if [[ -f "${bundle_czar_pub}" ]]; then
    mkdir -p /etc/ldown/keys || fatal "cannot create /etc/ldown/keys"
    cp "${bundle_czar_pub}" /etc/ldown/keys/czar-control.pub
    chmod 644 /etc/ldown/keys/czar-control.pub
    local czar_fp
    czar_fp="$(openssl pkey \
      -in /etc/ldown/keys/czar-control.pub \
      -pubin -outform DER 2>/dev/null \
      | sha256sum | awk '{print $1}')"
    status_ok "czar signing key installed" "${czar_fp}"
  else
    fatal "cluster.pub missing from bundle — export bundle is incomplete"
  fi

  must "install mesh_export.conf" cp "${stagedir}/mesh_export.conf" \
    "${CONFIG_DIR}/mesh_export.conf"
  status_ok "installed" "${CONFIG_DIR}/mesh_export.conf"

  printf '\n'
  success "bundle imported successfully"
  printf '\n'
  info "next steps:"
  printf '  1. ldown mesh init\n'
  printf '  2. ldown mesh join\n'
  printf '\n'
}

# =============================================================================
# cmd_mesh_reset
# =============================================================================
# nuclear option — wipe all ldown state from this node
# tears down the interface, removes /etc/ldown/*, removes logs
#
# keys, TLS certs, roster, mesh.conf — everything goes
# run init again to start fresh
# =============================================================================

cmd_mesh_reset() {
  banner
  require_root

  # ── show what will be destroyed ──────────────────────────
  printf '\n'
  warn "this will permanently delete all ldown state on this node:"
  printf '\n'
  printf '    %s\n' "${CONFIG_DIR}"
  printf '    %s\n' "${LOG_DIR}"
  printf '    %s (WireGuard interface)\n' "${WG_INTERFACE}"
  printf '\n'
  warn "this cannot be undone — keys and TLS certs will be gone"
  printf '\n'

  confirm "reset this node completely?" || { info "reset cancelled"; exit 0; }

  # double confirm — this is destructive
  confirm "are you sure? all keys will be lost" || { info "reset cancelled"; exit 0; }

  # ── tear down interface ──────────────────────────────────
  step "tearing down WireGuard interface"

  if is_valid_iface "${WG_INTERFACE}"; then
    wg-quick down "${WG_INTERFACE}" 2>/dev/null || \
      ip link delete "${WG_INTERFACE}" 2>/dev/null || true
    status_ok "interface down" "${WG_INTERFACE}"
  else
    status_warn "interface" "${WG_INTERFACE} was not up — skipped"
  fi

  # ── notify czar if we have state ────────────────────────
  if [[ -f "${MESH_CONF}" ]]; then
    source_if_exists "${MESH_CONF}"
    if [[ -n "${MY_NAME:-}" && -n "${CZAR_IP:-}" ]]; then
      step "notifying czar"
      local my_pubkey=""
      local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
      [[ -f "${pubfile}" ]] && read -r my_pubkey < "${pubfile}"
      local _reset_payload="LEAVE ${MY_NAME} ${MY_TUNNEL_IP:-} ${my_pubkey}"
      printf '%s\n' "$(sign_msg "${_reset_payload}") ${_reset_payload}" \
        | ncat "${CZAR_IP}" "${LDOWN_PORT}" 2>/dev/null || true
      status_ok "czar notified" "${CZAR_IP}"
    fi
  fi

  # ── wipe config dir ──────────────────────────────────────
  step "removing ${CONFIG_DIR}"

  if [[ -d "${CONFIG_DIR}" ]]; then
    must "remove config dir" rm -rf "${CONFIG_DIR}"
    status_ok "removed" "${CONFIG_DIR}"
  else
    status_warn "config dir" "not found — skipped"
  fi

  # ── wipe logs ────────────────────────────────────────────
  step "removing ${LOG_DIR}"

  if [[ -d "${LOG_DIR}" ]]; then
    must "remove log dir" rm -rf "${LOG_DIR}"
    status_ok "removed" "${LOG_DIR}"
  else
    status_warn "log dir" "not found — skipped"
  fi

  # ── done ─────────────────────────────────────────────────
  printf '\n'
  success "reset complete — this node has no ldown state"
  printf '\n'
  info "to rejoin a mesh: ldown mesh import <bundle> then ldown mesh init"
  printf '\n'
}

# =============================================================================
# cmd_mesh_watch
# =============================================================================
# live-updating terminal dashboard — cursor-positioned in-place redraw
# fixed UI redrawn at top, log events scroll naturally below
# =============================================================================

cmd_mesh_watch() {
  require_root
  check_dependency wg

  if [[ ! -f "${MESH_CONF}" ]]; then
    fatal "mesh.conf not found — run: ldown mesh init"
  fi
  source_if_exists "${MESH_CONF}"
  [[ -n "${MY_NAME:-}" ]] || fatal "mesh.conf missing MY_NAME"
  LDOWN_QUIET=true roster_load "${ROSTER_CONF}" >/dev/null 2>&1 || true

  # ── trans flag palette ───────────────────────────────────
  local T_BLUE=$'\033[38;5;117m'       # trans blue
  local T_PINK=$'\033[38;5;218m'       # trans pink
  local T_WHITE=$'\033[0;97m'          # bright white
  local T_HOT=$'\033[38;5;205m'        # hot pink accent
  local T_SKY=$'\033[38;5;153m'        # sky blue accent
  local T_LILAC=$'\033[38;5;183m'      # lavender highlight
  local T_ROSE=$'\033[38;5;211m'       # rose for warnings
  local T_DIM=$'\033[2m'
  local T_BOLD=$'\033[1m'
  local T_ITAL=$'\033[3m'
  local RESET=$'\033[0m'

  # ── constants ────────────────────────────────────────────
  local W=76
  local -a SPINNER_FRAMES=('◜' '◝' '◞' '◟')
  local -a SPINNER_COLORS=("${T_PINK}" "${T_WHITE}" "${T_BLUE}" "${T_WHITE}")
  local spinner_idx=0
  local watch_start_ts="${SECONDS}"
  local iface="${WG_INTERFACE:-wg0}"
  local sync_state_file="/run/ldown/sync.state"
  local listener_pid_file="/run/ldown/listener.pid"
  local sync_pid_file="/run/ldown/sync.pid"
  local listener_log="${LOG_LISTENER:-${LOG_DIR:-/var/log/ldown}/listener.log}"
  local sync_log="${LOG_SYNC:-${LOG_DIR:-/var/log/ldown}/sync.log}"
  local security_log="${LOG_SECURITY:-${LOG_DIR:-/var/log/ldown}/security.log}"
  local ping_cycle=0
  local czar_reachable=false

  # ── trans gradient separator ────────────────────────────
  _sep() {
    printf '\033[K  %s%s%s%s%s\n' \
      "${T_BLUE}$(printf '%0.s─' {1..14})${RESET}" \
      "${T_PINK}$(printf '%0.s─' {1..14})${RESET}" \
      "${T_WHITE}$(printf '%0.s─' {1..14})${RESET}" \
      "${T_PINK}$(printf '%0.s─' {1..14})${RESET}" \
      "${T_BLUE}$(printf '%0.s─' {1..14})${RESET}"
  }

  # line printer: erase to EOL then print indented colored content
  _wl() {
    printf '\033[K  %b\n' "$*"
  }

  _fmt_bytes() {
    local bytes="${1:-0}"
    [[ -z "${bytes}" || "${bytes}" == "0" ]] && printf '—' && return
    if (( bytes < 1024 )); then
      printf '%dB' "${bytes}"
    elif (( bytes < 1048576 )); then
      printf '%dKB' "$(( bytes / 1024 ))"
    elif (( bytes < 1073741824 )); then
      printf '%dMB' "$(( bytes / 1048576 ))"
    else
      printf '%dGB' "$(( bytes / 1073741824 ))"
    fi
  }

  _fmt_uptime() {
    local secs=$1
    if (( secs < 60 )); then
      printf '%ds' "${secs}"
    elif (( secs < 3600 )); then
      printf '%dm %ds' "$(( secs/60 ))" "$(( secs%60 ))"
    else
      printf '%dh %02dm %02ds' "$(( secs/3600 ))" "$(( (secs%3600)/60 ))" "$(( secs%60 ))"
    fi
  }

  _mode_color() {
    case "$1" in
      CALM)      printf '%s' "${T_BLUE}" ;;
      ALERT)     printf '%s' "${T_ROSE}" ;;
      REPAIR)    printf '%s' "${T_PINK}" ;;
      PARTITION) printf '%s' "${T_PINK}" ;;
      *)         printf '%s' "${T_WHITE}" ;;
    esac
  }

  # ── terminal setup ──────────────────────────────────────
  # capture stty state before any changes so trap can always restore it
  local old_stty
  old_stty=$(stty -g 2>/dev/null || true)

  # enter alternate screen buffer like Star Wars/vim/htop
  printf '\033[?1049h'
  printf '\033[2J\033[H'  # full clear once on entry
  printf '\033[?25l'      # hide cursor

  _watch_cleanup() {
    [[ -n "${old_stty}" ]] && stty "${old_stty}" 2>/dev/null || true
    printf '\033[?1049l'  # leave alternate screen, original returns
    printf '\033[?25h'    # show cursor
    printf '\033[0m'      # reset colors
    exit 0
  }
  trap _watch_cleanup EXIT INT TERM

  # raw mode: no echo, no line buffering — single-key input without Enter
  stty -echo -icanon min 0 time 0

  # ── data cache — initialized before loop, refreshed every 2s ──────────
  local data_cycle=0
  local sync_mode="CALM" fever="false" last_cycle=""
  local mcolor; mcolor=$(_mode_color "CALM")
  local sync_interval_hint="30s"
  local last_sync_str="unknown"
  local listener_pid="" listener_str="${T_DIM}checking...${RESET}"
  local sync_pid="" sync_str="${T_DIM}checking...${RESET}"
  local iface_str="${T_LILAC}✗ down${RESET}" iface_up=false
  local key_count=0 key_expected=$(( ${#PEER_NAMES[@]} + 1 )) key_str="—"
  local czar_key_str="${T_DIM}checking...${RESET}"
  local wg_dump=""
  local total_rx=0 total_tx=0
  local total_rx_str="—" total_tx_str="—"
  local fever_str="${T_BLUE}no fever${RESET}"
  local new_logs=""

  # ── main refresh loop ───────────────────────────────────
  while true; do
    # ── always: cheap per-cycle updates ──────────────────
    local spin="${SPINNER_COLORS[$spinner_idx]}${SPINNER_FRAMES[$spinner_idx]}${RESET}"
    spinner_idx=$(( (spinner_idx + 1) % 4 ))

    local now_str; now_str=$(date '+%H:%M:%S')
    local now_ts; now_ts=$(date +%s)
    local elapsed=$(( SECONDS - watch_start_ts ))
    local uptime_str; uptime_str=$(_fmt_uptime "${elapsed}")

    local role="peer"
    [[ "${MY_IS_CZAR:-false}" == "true" ]] && role="czar"

    # ── data refresh — every 4 cycles (2s) ───────────────
    data_cycle=$(( (data_cycle + 1) % 4 ))
    if (( data_cycle == 0 )); then
      # sync state
      sync_mode="CALM"; fever="false"; last_cycle=""
      if [[ -f "${sync_state_file}" ]]; then
        sync_mode=$(grep "^MODE=" "${sync_state_file}" 2>/dev/null | cut -d= -f2)
        fever=$(grep "^FEVER=" "${sync_state_file}" 2>/dev/null | cut -d= -f2)
        last_cycle=$(grep "^LAST_CYCLE=" "${sync_state_file}" 2>/dev/null | cut -d= -f2)
        [[ -z "${sync_mode}" ]] && sync_mode="CALM"
        [[ -z "${fever}" ]] && fever="false"
      fi
      mcolor=$(_mode_color "${sync_mode}")

      # sync interval hint
      sync_interval_hint="30s"
      case "${sync_mode}" in
        ALERT)            sync_interval_hint="15s" ;;
        REPAIR|PARTITION) sync_interval_hint="5s" ;;
      esac

      # last sync age
      last_sync_str="unknown"
      if [[ -n "${last_cycle}" && "${last_cycle}" =~ ^[0-9]+$ ]]; then
        local sync_age=$(( now_ts - last_cycle ))
        last_sync_str="${sync_age}s ago"
      elif kill -0 "$(cat "${sync_pid_file}" 2>/dev/null)" 2>/dev/null; then
        last_sync_str="loop active"
      fi

      # listener status
      listener_str="${T_LILAC}✗ stopped${RESET}"
      if [[ -f "${listener_pid_file}" ]]; then
        read -r listener_pid < "${listener_pid_file}" 2>/dev/null
        if kill -0 "${listener_pid}" 2>/dev/null; then
          listener_str="${T_BLUE}✓ running${RESET} ${T_DIM}pid ${listener_pid}${RESET}"
        fi
      fi

      # sync loop status
      sync_str="${T_LILAC}✗ stopped${RESET}"
      if [[ -f "${sync_pid_file}" ]]; then
        read -r sync_pid < "${sync_pid_file}" 2>/dev/null
        if kill -0 "${sync_pid}" 2>/dev/null; then
          sync_str="${T_BLUE}✓ running${RESET} ${T_DIM}pid ${sync_pid}${RESET}"
        fi
      fi

      # interface state
      iface_str="${T_LILAC}✗ down${RESET}"; iface_up=false
      if ip link show "${iface}" &>/dev/null 2>&1; then
        iface_up=true
        iface_str="${T_BLUE}✓ up${RESET} ${T_WHITE}${MY_TUNNEL_IP:-?}/24${RESET}"
      fi

      # node signing key count
      key_count=$(find "${KEY_DIR}" -name "*-node.pub" 2>/dev/null | wc -l | tr -d ' ')
      key_expected=$(( ${#PEER_NAMES[@]} + 1 ))
      key_str="${key_count}/${key_expected} stored"

      # czar pubkey status
      czar_key_str="${T_LILAC}✗ missing${RESET}"
      [[ -f "${KEY_DIR}/czar-control.pub" ]] && czar_key_str="${T_BLUE}✓ verified${RESET}"

      # wg dump — parse once
      wg_dump=""
      ${iface_up} && wg_dump=$(wg show "${iface}" dump 2>/dev/null)

      # total rx/tx
      total_rx=0; total_tx=0
      if [[ -n "${wg_dump}" ]]; then
        while IFS=$'\t' read -r f1 f2 f3 f4 f5 f6 f7 f8; do
          [[ "${f1}" =~ ^[a-zA-Z0-9+/=]{43,44}$ ]] || continue
          [[ "${f6}" =~ ^[0-9]+$ ]] && total_rx=$(( total_rx + f6 ))
          [[ "${f7}" =~ ^[0-9]+$ ]] && total_tx=$(( total_tx + f7 ))
        done <<< "${wg_dump}"
      fi
      total_rx_str=$(_fmt_bytes "${total_rx}")
      total_tx_str=$(_fmt_bytes "${total_tx}")

      # fever status
      fever_str="${T_BLUE}no fever${RESET}"
      [[ "${fever}" == "true" ]] && fever_str="${T_PINK}${T_BOLD}⚠ FEVER ACTIVE${RESET}"

      # new log events
      new_logs=""
      if [[ -f "${listener_log}" ]]; then
        new_logs=$(grep -v "PING\|PONG\|Ncat:\|Address already" \
          "${listener_log}" 2>/dev/null | \
          grep "\[INFO\]\|\[WARN\]\|\[DEBUG\]\|SECURITY" | \
          tail -10 | \
          sed 's/\[.*T\([0-9:]*\)\]/[\1]/')
      fi
    fi

    # czar reachability — only every 5th cycle
    ping_cycle=$(( (ping_cycle + 1) % 5 ))
    if (( ping_cycle == 0 )); then
      if ping -c1 -W1 "${CZAR_TUNNEL_IP:-${CZAR_IP:-127.0.0.1}}" &>/dev/null 2>&1; then
        czar_reachable=true
      else
        czar_reachable=false
      fi
    fi
    local czar_str
    if ${czar_reachable}; then
      czar_str="${T_BLUE}✓ reachable${RESET}"
    else
      czar_str="${T_PINK}✗ unreachable${RESET}"
    fi

    local healthy_count=0

    # ── MESH VIEW RENDERING ──────────────────────────────
    # pipe subshell output through cat — C-level buffering, one write per cycle
    (
        printf '\033[H'

        printf '\033[K  %s%s ✦ ldown v%s — MESH WATCH  %s%s%s\n' \
          "${T_PINK}${T_BOLD}" "${RESET}" "${LDOWN_VERSION:-0.1.0}" \
          "${T_DIM}" "${now_str}" "${RESET}"

        _sep

        printf '\033[K  %s%snode:%s %s%s%s%s  %s•%s  role: %s%s%s  %s•%s  tunnel: %s%s%s  %s•%s  uptime: %s%s%s\n' \
          "${T_WHITE}" "" "${RESET}" "${T_PINK}${T_BOLD}" "${RESET}" "${MY_NAME:-?}" "${RESET}" \
          "${T_DIM}" "${RESET}" "${T_SKY}" "${role}" "${RESET}" "${T_DIM}" "${RESET}" \
          "${T_WHITE}" "${MY_TUNNEL_IP:-?}" "${RESET}" "${T_DIM}" "${RESET}" \
          "${T_LILAC}" "${uptime_str}" "${RESET}"

        printf '\033[K  %s%sczar:%s %s%s%s %s(%s)%s  %s•%s  %s  %s•%s  mode: %s%s%s\n' \
          "${T_WHITE}" "" "${RESET}" "${T_PINK}" "${CZAR_IP:-?}" "${RESET}" \
          "${T_DIM}" "${CZAR_TUNNEL_IP:-?}" "${RESET}" "${T_DIM}" "${RESET}" \
          "${czar_str}" "${T_DIM}" "${RESET}" "${mcolor}" "${sync_mode}" "${RESET}"

        _sep

        printf '\033[K  %s%s✦ PEERS%s\n' "${T_BOLD}${T_PINK}" "" "${RESET}"

        printf '\033[K  %s%-8s %-12s %-22s %-9s%-6s %-11s%s\n' "${T_DIM}" \
          'NAME' 'TUNNEL IP' 'ENDPOINT' 'STATUS' 'AGE' 'IN / OUT' "${RESET}"

        # peer rows
        local row_alt=0
        for i in "${!PEER_NAMES[@]}"; do
          local pname="${PEER_NAMES[$i]}"
          local ptunnel="${PEER_TUNNEL_IPS[$i]}"
          local pip="${PEER_IPS[$i]}"
          local pport="${PEER_PORTS[$i]:-${WG_PORT:-51820}}"

          local peer_line_data=""
          if [[ -n "${wg_dump}" ]]; then
            peer_line_data=$(awk -F'\t' -v ip="${ptunnel}" '$4 ~ ip {print; exit}' <<< "${wg_dump}")
          fi

          local peer_ep="" peer_hs=0 peer_rx=0 peer_tx=0
          if [[ -n "${peer_line_data}" ]]; then
            peer_ep=$(cut -f3 <<< "${peer_line_data}")
            peer_hs=$(cut -f5 <<< "${peer_line_data}")
            peer_rx=$(cut -f6 <<< "${peer_line_data}")
            peer_tx=$(cut -f7 <<< "${peer_line_data}")
            [[ "${peer_ep}" == "(none)" ]] && peer_ep=""
            [[ ! "${peer_hs}" =~ ^[0-9]+$ ]] && peer_hs=0
            [[ ! "${peer_rx}" =~ ^[0-9]+$ ]] && peer_rx=0
            [[ ! "${peer_tx}" =~ ^[0-9]+$ ]] && peer_tx=0
          fi

          local ep_display="${peer_ep:-${pip}:${pport}}"

          local status_display row_color hs_str
          if ! ${iface_up} || [[ -z "${peer_line_data}" ]]; then
            status_display="${T_LILAC}✗ down   ${RESET}"
            row_color="${T_LILAC}"
            hs_str="—"
            peer_rx=0
            peer_tx=0
          elif [[ "${peer_hs}" == "0" ]]; then
            status_display="${T_WHITE}${spin} wait  ${RESET}"
            row_color="${T_WHITE}"
            hs_str="—"
          else
            local hs_age_int=$(( now_ts - peer_hs ))
            hs_str="${hs_age_int}s"
            if (( hs_age_int < 150 )); then
              status_display="${T_BLUE}✓ up     ${RESET}"
              row_color="${T_BLUE}"
              healthy_count=$(( healthy_count + 1 ))
            elif (( hs_age_int < 190 )); then
              status_display="${T_SKY}~ stale  ${RESET}"
              row_color="${T_SKY}"
            else
              status_display="${T_LILAC}✗ down   ${RESET}"
              row_color="${T_LILAC}"
            fi
          fi

          local prx_str; prx_str=$(_fmt_bytes "${peer_rx}")
          local ptx_str; ptx_str=$(_fmt_bytes "${peer_tx}")
          local rx_tx_str="${prx_str} / ${ptx_str}"

          local row_tint=""
          (( row_alt % 2 == 1 )) && row_tint="${T_DIM}"
          row_alt=$(( row_alt + 1 ))

          printf '\033[K  %b%-8s %-12s %-22s %s%-6s %-11s%b\n' \
            "${row_tint}${row_color}" \
            "${pname}" "${ptunnel}" "${ep_display}" \
            "${status_display}" \
            "${hs_str}" \
            "${rx_tx_str}" \
            "${RESET}"
        done

        _sep

        printf '\033[K  %s%s✦ SYSTEM%s\n' "${T_BOLD}${T_PINK}" "" "${RESET}"

        # build plain text values for width-correct column alignment
        local listener_plain="✗ stopped"
        if [[ -n "${listener_pid}" ]] && kill -0 "${listener_pid}" 2>/dev/null; then
          listener_plain="✓ running   pid ${listener_pid}"
        fi
        local iface_plain="✗ down"
        ${iface_up} && iface_plain="✓ up  ${MY_TUNNEL_IP:-?}/24"
        local sync_plain="✗ stopped"
        if [[ -n "${sync_pid}" ]] && kill -0 "${sync_pid}" 2>/dev/null; then
          sync_plain="✓ running   pid ${sync_pid}"
        fi
        local czar_key_plain="✗ missing"
        [[ -f "${KEY_DIR}/czar-control.pub" ]] && czar_key_plain="✓ verified"

        # line 1: listener / interface
        printf '\033[K  '
        printf '%b%-10s%b' "${T_BLUE}" "listener" "${RESET}"
        printf '%-28s' "${listener_plain}"
        printf '%b%-10s%b' "${T_BLUE}" "interface" "${RESET}"
        printf '%s\n' "${iface_plain}"

        # line 2: sync / czar key
        printf '\033[K  '
        printf '%b%-10s%b' "${T_BLUE}" "sync" "${RESET}"
        printf '%-28s' "${sync_plain}"
        printf '%b%-10s%b' "${T_BLUE}" "czar key" "${RESET}"
        printf '%s\n' "${czar_key_plain}"

        # line 3: keys / interval
        printf '\033[K  '
        printf '%b%-10s%b' "${T_BLUE}" "keys" "${RESET}"
        printf '%-28s' "${key_str}"
        printf '%b%-10s%b' "${T_BLUE}" "interval" "${RESET}"
        printf '%s\n' "${sync_interval_hint}"

        # line 4: traffic (full width)
        printf '\033[K  '
        printf '%b%-10s%b' "${T_BLUE}" "traffic" "${RESET}"
        printf '%b↓ %s rx%b   %b↑ %s tx%b\n' \
          "${T_BLUE}" "${total_rx_str}" "${RESET}" \
          "${T_PINK}" "${total_tx_str}" "${RESET}"

        _sep

        local heal_str=""
        (( healthy_count < ${#PEER_NAMES[@]} )) && heal_str=" ${T_DIM}— sync healing${RESET}"

        printf '\033[K  %s●%s %s%s%s  %s•%s  %s  %s•%s  %s%d/%d healthy%s%s  %s•%s  last sync: %s%s%s\n' \
          "${mcolor}" "${RESET}" "${mcolor}" "${sync_mode}" "${RESET}" \
          "${T_DIM}" "${RESET}" "${fever_str}" "${T_DIM}" "${RESET}" \
          "${T_WHITE}" "${healthy_count}" "${#PEER_NAMES[@]}" "${RESET}" "${heal_str}" \
          "${T_DIM}" "${RESET}" "${T_DIM}" "${last_sync_str}" "${RESET}"

        _sep

        printf '\033[K  %s[q]%s %squit%s  %s[l]%s %slive logs%s  %sCtrl+C%s\n' \
          "${T_SKY}" "${RESET}" "${T_DIM}" "${RESET}" \
          "${T_SKY}" "${RESET}" "${T_DIM}" "${RESET}" \
          "${T_DIM}" "${RESET}"

        _sep

        printf '\033[J'
    ) | cat

    # keyboard input — non-blocking, 0.5 second timeout
    local key=""
    if read -r -s -n1 -t 0.5 key 2>/dev/null; then
      case "${key}" in
        q|Q)
          break
          ;;
        l|L)
          # exit to log view, re-enter dashboard when it returns
          printf '\033[?1049l\033[?25h\033[0m\n'
          [[ -n "${old_stty}" ]] && stty "${old_stty}" 2>/dev/null || true
          cmd_mesh_watch_logs
          # re-enter dashboard
          stty -echo -icanon min 0 time 0
          printf '\033[?1049h\033[2J\033[H\033[?25l'
          ;;
        r|R)
          if [[ "${MY_IS_CZAR:-false}" != "true" ]]; then
            printf '\033[?25h\033[0m\n'
            cmd_mesh_recover &
            printf '\033[?25l'
          fi
          ;;
        p|P)
          if [[ "${MY_IS_CZAR:-false}" == "true" ]]; then
            printf '\033[?25h\033[0m\n'
            printf 'promote czar — enter new czar name: '
            read -r new_czar
            [[ -n "${new_czar}" ]] && printf 'ldown czar promote %s\n' "${new_czar}"
            printf '\033[?25l'
          fi
          ;;
      esac
    fi
  done

  printf '\033[?25h'
  printf '\033[0m\n'
}

# =============================================================================
# cmd_mesh_watch_logs
# =============================================================================
# simple scrollable log view with tail -f
# runs in normal terminal, not alternate buffer
# Ctrl+C returns to normal terminal (not back to dashboard)
# =============================================================================

cmd_mesh_watch_logs() {
  local listener_log="${LOG_LISTENER:-${LOG_DIR:-/var/log/ldown}/listener.log}"
  local T_BLUE=$'\033[38;5;117m'
  local T_PINK=$'\033[38;5;218m'
  local T_WHITE=$'\033[0;97m'
  local T_SKY=$'\033[38;5;153m'
  local T_LILAC=$'\033[38;5;183m'
  local T_DIM=$'\033[2m'
  local T_BOLD=$'\033[1m'
  local RESET=$'\033[0m'
  local seg=14

  local old_stty_logs
  old_stty_logs=$(stty -g 2>/dev/null || true)
  stty -echo -icanon min 0 time 0 2>/dev/null || true
  trap 'stty "${old_stty_logs}" 2>/dev/null; return 0' INT

  printf '\033[38;5;218m  ✦ ldown — LIVE LOGS\033[0m  '
  printf '\033[2m(last 10 + live • [l] or [q] returns)\033[0m\n'
  printf '  '
  printf '\033[38;5;153m%s' "$(printf '─%.0s' $(seq 1 ${seg}))"
  printf '\033[38;5;218m%s' "$(printf '─%.0s' $(seq 1 ${seg}))"
  printf '\033[0;97m%s'     "$(printf '─%.0s' $(seq 1 ${seg}))"
  printf '\033[38;5;218m%s' "$(printf '─%.0s' $(seq 1 ${seg}))"
  printf '\033[38;5;153m%s' "$(printf '─%.0s' $(seq 1 ${seg}))"
  printf '\033[0m\n'
  printf '\033[2m  — recent history —\033[0m\n'

  grep -v "PING\|PONG" "${listener_log}" 2>/dev/null | \
    tail -10 | while IFS= read -r line; do
      local color="${T_WHITE}"
      [[ "${line}" == *"SECURITY"* ]] && color="${T_LILAC}"
      [[ "${line}" == *"[WARN]"* ]]   && color="${T_SKY}"
      [[ "${line}" == *"[DEBUG]"* ]]  && color="${T_DIM}"
      [[ "${line}" == *"[INFO]"* ]]   && color="${T_BLUE}"
      [[ "${line}" == *"[HEAL]"* ]]   && color="${T_SKY}"
      [[ "${line}" == *"[FEVER]"* ]]  && color="${T_PINK}${T_BOLD}"
      printf '%s  %s%s\n' "${color}" "${line}" "${RESET}"
    done

  printf '\033[38;5;218m%s\033[0m\n' \
    "──────────────────────────────────────────────────────"
  printf '\033[2m  — live —\033[0m\n'

  tail -f "${listener_log}" 2>/dev/null | \
    grep --line-buffered -v "PING\|PONG" | \
    while IFS= read -r line; do
      k=""
      read -r -s -n1 -t0 k 2>/dev/null
      if [[ "${k}" == "l" || "${k}" == "L" || \
            "${k}" == "q" || "${k}" == "Q" ]]; then
        break
      fi
      color="${T_WHITE}"
      [[ "${line}" == *"SECURITY"* ]] && color="${T_LILAC}"
      [[ "${line}" == *"[WARN]"* ]]   && color="${T_SKY}"
      [[ "${line}" == *"[DEBUG]"* ]]  && color="${T_DIM}"
      [[ "${line}" == *"[INFO]"* ]]   && color="${T_BLUE}"
      [[ "${line}" == *"[HEAL]"* ]]   && color="${T_SKY}"
      [[ "${line}" == *"[FEVER]"* ]]  && color="${T_PINK}${T_BOLD}"
      printf '%s  %s%s\n' "${color}" "${line}" "${RESET}"
    done

  stty "${old_stty_logs}" 2>/dev/null || true
}

# =============================================================================
# cmd_mesh_status
# =============================================================================
# show the state of every peer in the mesh
#
# for each peer in roster:
#   - is the WireGuard peer configured?
#   - when was the last handshake?
#   - rx/tx bytes
# =============================================================================

cmd_mesh_status() {
  if [[ "${1:-}" == "--watch" ]]; then
    cmd_mesh_watch
    return 0
  fi
  banner
  require_root
  check_dependency wg awk

  if [[ ! -f "${MESH_CONF}" ]]; then
    printf '\n  [!] this node has left the mesh or has not yet joined\n'
    printf '  [*] to rejoin:  ldown mesh join\n'
    printf '  [*] to start fresh: ldown mesh init\n\n'
    exit 0
  fi
  source_if_exists "${MESH_CONF}"
  [[ -n "${MY_NAME:-}" ]] || fatal "mesh.conf missing MY_NAME"

  roster_load "${ROSTER_CONF}" || fatal "roster failed to load"

  printf '\n'
  if is_valid_iface "${WG_INTERFACE}"; then
    status_ok "interface" "${WG_INTERFACE} — ${MY_TUNNEL_IP}/24"
  else
    status_fail "interface" "${WG_INTERFACE} is down"
    printf '\n'
    fatal "WireGuard interface is not up — run: ldown mesh start"
  fi

  printf '\n'
  printf '  %-20s %-16s %-10s %-28s %-14s\n' \
    "NAME" "TUNNEL IP" "STATUS" "LAST HANDSHAKE" "RX/TX"
  divider

  local wg_peers
  wg_peers="$(wg show "${WG_INTERFACE}" latest-handshakes 2>/dev/null || true)"

  local wg_transfer
  wg_transfer="$(wg show "${WG_INTERFACE}" transfer 2>/dev/null || true)"

  local now
  printf -v now '%(%s)T' -1

  local i
  for i in $(_mesh_sorted_peer_indices); do
    local peer_name="${PEER_NAMES[$i]}"
    local peer_tunnel="${PEER_TUNNEL_IPS[$i]}"
    local peer_conf="${PEER_DIR}/peer-${peer_tunnel}.conf"

    # get pubkey from peer config file
    local peer_pubkey=""
    [[ -f "${peer_conf}" ]] && \
      peer_pubkey="$(awk '/^PublicKey/{print $3}' "${peer_conf}")"

    # handshake timestamp
    local hs_ts="0"
    [[ -n "${peer_pubkey}" ]] && \
      hs_ts="$(awk -v k="${peer_pubkey}" '$1==k {print $2}' <<< "${wg_peers}")"
    hs_ts="${hs_ts:-0}"

    # handshake age display
    local hs_display="never"
    if [[ "${hs_ts}" != "0" ]]; then
      local age=$(( now - hs_ts ))
      (( age < 0 )) && age=0
      if   (( age < 60    )); then hs_display="${age}s ago"
      elif (( age < 3600  )); then hs_display="$(( age / 60 ))m ago"
      elif (( age < 86400 )); then hs_display="$(( age / 3600 ))h ago"
      else                         hs_display="$(( age / 86400 ))d ago"
      fi
    fi

    # rx/tx
    local transfer_display="-"
    if [[ -n "${peer_pubkey}" ]]; then
      local transfer_line
      transfer_line="$(awk -v k="${peer_pubkey}" '$1==k {print $2, $3}' <<< "${wg_transfer}")"
      if [[ -n "${transfer_line}" ]]; then
        local rx tx
        read -r rx tx <<< "${transfer_line}"
        local rx_h tx_h
        rx_h="$(numfmt --to=iec --suffix=B "${rx}" 2>/dev/null || printf '%sB' "${rx}")"
        tx_h="$(numfmt --to=iec --suffix=B "${tx}" 2>/dev/null || printf '%sB' "${tx}")"
        transfer_display="↓${rx_h} ↑${tx_h}"
      fi
    fi

    # status
    local status_display
    if [[ -z "${peer_pubkey}" ]]; then
      status_display="not configured"
    elif [[ "${hs_ts}" == "0" ]]; then
      status_display="down"
    elif (( now - hs_ts < 180 )); then
      status_display="up"
    else
      status_display="stale"
    fi

    printf '  %-20s %-16s %-10s %-28s %-14s\n' \
      "${peer_name}" \
      "${peer_tunnel}" \
      "${status_display}" \
      "${hs_display}" \
      "${transfer_display}"
  done

  divider
  printf '\n'
  info "node: ${MY_NAME} — ${MY_TUNNEL_IP}"
  info "czar: ${CZAR_IP} (${CZAR_TUNNEL_IP})"
  printf '\n'
}

# =============================================================================
# cmd_mesh_doctor
# =============================================================================
# diagnose the health of this node's mesh participation
#
# checks:
#   1. mesh.conf exists and is valid
#   2. keys exist
#   3. TLS cert valid + fingerprint matches mesh.conf
#   4. WireGuard interface is up
#   5. roster parses + hash matches mesh.conf
#   6. peer configs + handshake ages
#   7. czar reachability
#   8. listener process
# =============================================================================

cmd_mesh_doctor() {
  banner
  require_root
  check_dependency wg awk
  command -v ping >/dev/null || fatal "ping not found"

  local errors=0
  local warnings=0

  # ── mesh.conf ────────────────────────────────────────────
  step "checking mesh.conf"

  if [[ ! -f "${MESH_CONF}" ]]; then
    status_fail "mesh.conf" "not found — run: ldown mesh init"
    errors=$((errors + 1))
    printf '\n'
    status_fail "doctor" "${errors} error(s) — cannot continue without mesh.conf"
    return 1
  fi

  source_if_exists "${MESH_CONF}"

  if [[ -z "${MY_NAME:-}" ]]; then
    status_fail "mesh.conf" "missing MY_NAME — re-run: ldown mesh init"
    errors=$((errors + 1))
    return 1
  fi

  status_ok "mesh.conf" "${MESH_CONF}"
  status_ok "node" "${MY_NAME} — ${MY_TUNNEL_IP}"

  # ── keys ─────────────────────────────────────────────────
  step "checking keys"

  local privfile="${KEY_DIR}/${MY_NAME}.private.key"
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"

  if [[ ! -f "${privfile}" ]]; then
    status_fail "private key" "not found: ${privfile}"
    errors=$((errors + 1))
  else
    status_ok "private key" "${privfile}"
  fi

  if [[ ! -f "${pubfile}" ]]; then
    status_fail "public key" "not found: ${pubfile}"
    errors=$((errors + 1))
  else
    status_ok "public key" "${pubfile}"
  fi

  # ── TLS cert ─────────────────────────────────────────────
  step "checking TLS cert"

  if [[ ! -f "${TLS_CERT}" ]]; then
    status_fail "TLS cert" "not found — run: ldown mesh init"
    errors=$((errors + 1))
  else
    local expiry
    expiry="$(openssl x509 -in "${TLS_CERT}" -noout -enddate 2>/dev/null | cut -d= -f2)"
    local fp
    fp="$(openssl x509 -in "${TLS_CERT}" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    status_ok "TLS cert" "expires ${expiry}"

    if [[ -n "${TLS_FINGERPRINT:-}" && "${fp}" != "${TLS_FINGERPRINT}" ]]; then
      status_fail "TLS fingerprint" "mismatch — cert rotated without updating mesh.conf"
      errors=$((errors + 1))
    else
      status_ok "TLS fingerprint" "matches mesh.conf"
    fi
  fi

  # ── WireGuard interface ──────────────────────────────────
  step "checking WireGuard interface"

  local iface_up=false
  if ! is_valid_iface "${WG_INTERFACE}"; then
    status_fail "interface" "${WG_INTERFACE} is not up"
    errors=$((errors + 1))
  else
    local wg_ip
    wg_ip="$(ip -4 addr show "${WG_INTERFACE}" 2>/dev/null \
      | awk '/inet /{print $2}' | head -1)"
    status_ok "interface" "${WG_INTERFACE} — ${wg_ip:-unknown}"
    iface_up=true
  fi

  # ── roster ───────────────────────────────────────────────
  step "checking roster"

  if [[ ! -f "${ROSTER_CONF}" ]]; then
    status_fail "roster.conf" "not found: ${ROSTER_CONF}"
    errors=$((errors + 1))
    return 1
  fi

  roster_load "${ROSTER_CONF}" || {
    status_fail "roster.conf" "failed to parse"
    errors=$((errors + 1))
    return 1
  }

  status_ok "roster.conf" "${ROSTER_CONF}"
  status_ok "peers in roster" "${#PEER_IPS[@]}"

  local current_hash="${ROSTER_HASH:-}"
  local init_hash="${ROSTER_HASH_INIT:-}"
  if [[ -n "${init_hash}" && -n "${current_hash}" ]]; then
    if [[ "${current_hash}" != "${init_hash}" ]]; then
      status_warn "roster hash" "roster changed since init — re-run: ldown mesh start"
      warnings=$((warnings + 1))
    else
      status_ok "roster hash" "${current_hash}"
    fi
  else
    status_ok "roster hash" "${current_hash}"
  fi

  # ── peer configs + handshakes ────────────────────────────
  step "checking peer configs"

  local wg_peers=""
  "${iface_up}" && \
    wg_peers="$(wg show "${WG_INTERFACE}" latest-handshakes 2>/dev/null || true)"

  local now
  printf -v now '%(%s)T' -1

  local i
  for i in $(_mesh_sorted_peer_indices); do
    local peer_name="${PEER_NAMES[$i]}"
    local peer_tunnel="${PEER_TUNNEL_IPS[$i]}"
    local peer_conf="${PEER_DIR}/peer-${peer_tunnel}.conf"

    local peer_pubkey=""
    [[ -f "${peer_conf}" ]] && \
      peer_pubkey="$(awk '/^PublicKey/{print $3}' "${peer_conf}")"

    if [[ -z "${peer_pubkey}" ]]; then
      status_fail "${peer_name}" "no peer config — re-run: ldown mesh start"
      errors=$((errors + 1))
      continue
    fi

    if ! "${iface_up}"; then
      status_warn "${peer_name}" "configured but interface is down"
      warnings=$((warnings + 1))
      continue
    fi

    local hs_ts
    hs_ts="$(awk -v k="${peer_pubkey}" '$1==k {print $2}' <<< "${wg_peers}")"
    hs_ts="${hs_ts:-0}"

    if [[ "${hs_ts}" == "0" ]]; then
      status_warn "${peer_name}" "configured but no handshake yet"
      warnings=$((warnings + 1))
    else
      local age=$(( now - hs_ts ))
      (( age < 0 )) && age=0
      if (( age < 180 )); then
        status_ok "${peer_name}" "handshake ${age}s ago"
      else
        local age_display
        if   (( age < 3600  )); then age_display="$(( age / 60 ))m ago"
        elif (( age < 86400 )); then age_display="$(( age / 3600 ))h ago"
        else                         age_display="$(( age / 86400 ))d ago"
        fi
        status_warn "${peer_name}" "stale handshake — ${age_display}"
        warnings=$((warnings + 1))
      fi
    fi
  done

  # ── czar reachability ────────────────────────────────────
  step "checking czar"

  if [[ -z "${CZAR_IP:-}" ]]; then
    status_warn "czar" "not set in mesh.conf"
    warnings=$((warnings + 1))
  else
    if ping -c1 -W2 "${CZAR_IP}" &>/dev/null; then
      status_ok "czar ping" "${CZAR_IP} reachable"
    else
      status_warn "czar ping" "${CZAR_IP} not responding"
      warnings=$((warnings + 1))
    fi

    if echo PING | ncat --wait 2 --send-only "${CZAR_IP}" "${LDOWN_PORT}" &>/dev/null; then
      status_ok "czar port" "${LDOWN_PORT} open"
    else
      status_warn "czar port" "${LDOWN_PORT} not reachable — listener may be down"
      warnings=$((warnings + 1))
    fi
  fi

  # ── listener process ─────────────────────────────────────
  step "checking listener"

  if pgrep -f "listener.sh" &>/dev/null; then
    status_ok "listener" "running"
  else
    status_warn "listener" "not running (phase 3 — not yet implemented)"
    warnings=$((warnings + 1))
  fi

  # ── summary ──────────────────────────────────────────────
  printf '\n'
  divider
  if (( errors == 0 && warnings == 0 )); then
    success "all checks passed — node looks healthy"
  elif (( errors == 0 )); then
    status_warn "doctor" "${warnings} warning(s) — node is functional, review above"
  else
    status_fail "doctor" "${errors} error(s), ${warnings} warning(s) — node needs attention"
  fi
  divider
  printf '\n'
}

# =============================================================================
# cmd_mesh_diff
# =============================================================================
# compare what the roster expects vs what WireGuard actually has configured
#
# three possible states per peer:
#   ok        — in roster and in wg
#   missing   — in roster but not in wg (needs start/recover)
#   rogue     — in wg but not in roster (stale or unknown peer)
# =============================================================================

cmd_mesh_diff() {
  banner
  require_root
  check_dependency wg awk grep

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — run: ldown mesh init"
  source_if_exists "${MESH_CONF}"
  [[ -n "${MY_NAME:-}" ]] || fatal "mesh.conf missing MY_NAME"

  roster_load "${ROSTER_CONF}" || fatal "roster failed to load"

  is_valid_iface "${WG_INTERFACE}" || \
    fatal "${WG_INTERFACE} is not up — run: ldown mesh start"

  # ── fetch all wg data once ───────────────────────────────
  local wg_pubkeys
  wg_pubkeys="$(wg show "${WG_INTERFACE}" peers 2>/dev/null || true)"

  local wg_allowed
  wg_allowed="$(wg show "${WG_INTERFACE}" allowed-ips 2>/dev/null || true)"

  if [[ -z "${wg_pubkeys}" ]]; then
    warn "no peers currently configured in WireGuard"
  fi

  # build lookup: pubkey → first allowed-ip (tunnel IP)
  declare -A _wg_peer_tunnels
  local pubkey
  while IFS= read -r pubkey; do
    [[ -z "${pubkey}" ]] && continue
    local allowed
    allowed="$(awk -v k="${pubkey}" '$1==k {print $2}' <<< "${wg_allowed}" \
      | cut -d, -f1 | head -1)"
    _wg_peer_tunnels["${pubkey}"]="${allowed:-unknown}"
  done <<< "${wg_pubkeys}"

  # ── compare roster vs wg ─────────────────────────────────
  printf '\n'
  printf '  %-20s %-16s %-10s\n' "NAME" "TUNNEL IP" "STATE"
  divider

  local missing=0
  local ok=0
  declare -A _matched_pubkeys

  local i
  for i in $(_mesh_sorted_peer_indices); do
    local peer_name="${PEER_NAMES[$i]}"
    local peer_tunnel="${PEER_TUNNEL_IPS[$i]}"
    local peer_conf="${PEER_DIR}/peer-${peer_tunnel}.conf"

    local peer_pubkey=""
    [[ -f "${peer_conf}" ]] && \
      peer_pubkey="$(awk -F' = ' '/^PublicKey/{print $2}' "${peer_conf}")"

    if [[ -z "${peer_pubkey}" ]]; then
      printf '  %-20s %-16s %-10s\n' "${peer_name}" "${peer_tunnel}" "missing"
      missing=$((missing + 1))
      continue
    fi

    if [[ -n "${_wg_peer_tunnels["${peer_pubkey}"]:-}" ]]; then
      printf '  %-20s %-16s %-10s\n' "${peer_name}" "${peer_tunnel}" "ok"
      _matched_pubkeys["${peer_pubkey}"]=1
      ok=$((ok + 1))
    else
      printf '  %-20s %-16s %-10s\n' "${peer_name}" "${peer_tunnel}" "missing"
      missing=$((missing + 1))
    fi
  done

  # ── find rogue peers in wg not in roster ─────────────────
  local rogue=0
  for pubkey in "${!_wg_peer_tunnels[@]}"; do
    [[ -n "${_matched_pubkeys["${pubkey}"]:-}" ]] && continue
    local tunnel="${_wg_peer_tunnels[$pubkey]}"
    printf '  %-20s %-16s %-10s\n' "${pubkey:0:16}..." "${tunnel}" "rogue"
    rogue=$((rogue + 1))
  done

  divider
  printf '\n'
  status_ok "ok"      "${ok}"
  [[ "${missing}" -gt 0 ]] && \
    status_warn "missing" "${missing} — run: ldown mesh recover"
  [[ "${rogue}" -gt 0 ]] && \
    status_warn "rogue"   "${rogue} — peers in wg not in roster (remove manually with: wg set ${WG_INTERFACE} peer <pubkey> remove)"
  printf '\n'
}

# =============================================================================
# cmd_mesh_neighbors
# =============================================================================
# show reachability table for all peers
#
# for each peer:
#   - ping the tunnel IP to check reachability + latency
#   - classify as: direct / relayed / unreachable
#   - show handshake age
#
# direct    — peer has a handshake and tunnel ping responds
# stale     — peer has a handshake but tunnel ping fails
# unreachable — no handshake, no ping response
# =============================================================================

cmd_mesh_neighbors() {
  banner
  require_root
  check_dependency wg awk
  command -v ping >/dev/null || fatal "ping not found"

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — run: ldown mesh init"
  source_if_exists "${MESH_CONF}"
  [[ -n "${MY_NAME:-}" ]] || fatal "mesh.conf missing MY_NAME"

  roster_load "${ROSTER_CONF}" || fatal "roster failed to load"

  is_valid_iface "${WG_INTERFACE}" || \
    fatal "${WG_INTERFACE} is not up — run: ldown mesh start"

  # ── fetch wg data once ───────────────────────────────────
  local wg_peers
  wg_peers="$(wg show "${WG_INTERFACE}" latest-handshakes 2>/dev/null || true)"

  declare -A _wg_handshakes
  while read -r _hs_key _hs_ts; do
    [[ -z "${_hs_key}" ]] && continue
    _wg_handshakes["${_hs_key}"]="${_hs_ts}"
  done <<< "${wg_peers}"

  local now
  printf -v now '%(%s)T' -1

  # ── table header ─────────────────────────────────────────
  printf '\n'
  printf '  %-20s %-16s %-14s %-16s %-10s\n' \
    "NAME" "TUNNEL IP" "STATUS" "LATENCY" "HANDSHAKE"
  divider

  local direct=0
  local stale=0
  local unreachable=0

  local i
  for i in $(_mesh_sorted_peer_indices); do
    local peer_name="${PEER_NAMES[$i]}"
    local peer_tunnel="${PEER_TUNNEL_IPS[$i]}"
    local peer_conf="${PEER_DIR}/peer-${peer_tunnel}.conf"
    local is_relay="${PEER_IS_RELAY[$i]:-0}"

    # get pubkey
    local peer_pubkey=""
    [[ -f "${peer_conf}" ]] && \
      peer_pubkey="$(awk -F' = ' '/^PublicKey/{print $2}' "${peer_conf}")"

    # handshake age
    local hs_ts="0"
    [[ -n "${peer_pubkey}" ]] && hs_ts="${_wg_handshakes[${peer_pubkey}]:-0}"

    local hs_display="never"
    if [[ "${hs_ts}" != "0" ]]; then
      local age=$(( now - hs_ts ))
      (( age < 0 )) && age=0
      if   (( age < 60    )); then hs_display="${age}s ago"
      elif (( age < 3600  )); then hs_display="$(( age / 60 ))m ago"
      elif (( age < 86400 )); then hs_display="$(( age / 3600 ))h ago"
      else                         hs_display="$(( age / 86400 ))d ago"
      fi
    fi

    # ping tunnel IP for latency
    local latency_display="-"
    local status_display="unreachable"
    local ping_output

    if ping_output="$(ping -c3 -W1 -q "${peer_tunnel}" 2>/dev/null)"; then
      local avg_ms
      avg_ms="$(awk -F'/' '/rtt/{print $5}' <<< "${ping_output}")"
      if [[ -n "${avg_ms}" ]]; then
        latency_display="${avg_ms}ms"
      else
        latency_display="<1ms"
      fi

      if [[ "${hs_ts}" != "0" ]]; then
        local age=$(( now - hs_ts ))
        (( age < 0 )) && age=0
        if (( age < 180 )); then
          status_display="direct"
          [[ "${is_relay}" == "1" ]] && status_display="via relay"
          direct=$((direct + 1))
        else
          status_display="stale"
          stale=$((stale + 1))
        fi
      else
        status_display="stale"
        stale=$((stale + 1))
      fi
    else
      latency_display="timeout"
      status_display="unreachable"
      unreachable=$((unreachable + 1))
    fi

    printf '  %-20s %-16s %-14s %-16s %-10s\n' \
      "${peer_name}" \
      "${peer_tunnel}" \
      "${status_display}" \
      "${latency_display}" \
      "${hs_display}"
  done

  divider
  printf '\n'
  status_ok  "direct"      "${direct}"
  [[ "${stale}" -gt 0 ]] && \
    status_warn "stale"    "${stale} — handshake old, tunnel may still work"
  [[ "${unreachable}" -gt 0 ]] && \
    status_fail "unreachable" "${unreachable} — run: ldown mesh recover"
  printf '\n'
  info "relay rules: direct preferred — relay fallback — relay→relay forbidden"
  printf '\n'
}