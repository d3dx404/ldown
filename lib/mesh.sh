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

# sign a control plane message with the cluster token
# usage: sign_msg <payload>  →  sha256(payload + CLUSTER_TOKEN)
# the token never appears on the wire; the sig is bound to this exact message
sign_msg() {
  local msg="$1"
  printf '%s' "${msg}${CLUSTER_TOKEN}" | sha256sum | awk '{print $1}'
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
  
  info "peers to connect: ${#PEER_IPS[@]}"

  step "serving public key for bootstrap"
  local serve_pid
  local pubfile="${KEY_DIR}/${MY_NAME}.public.key"
  ncat -l "${MY_IP}" "${LDOWN_PORT}" -k --sh-exec "cat ${pubfile}" \
    &>/tmp/ldown_serve.out &
  serve_pid=$!
  trap 'kill "${serve_pid}" 2>/dev/null || true' EXIT
  sleep 0.5
  if ! kill -0 "${serve_pid}" 2>/dev/null; then
    warn "key server failed to start — check /tmp/ldown_serve.out"
    cat /tmp/ldown_serve.out
    fatal "cannot continue without bootstrap key server"
  fi
  status_ok "key server started" "pid ${serve_pid} on ${MY_IP}:${LDOWN_PORT}"

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

  step "connecting to peers"

  local failed=0
  declare -A _connected_pubkeys

  local i
  for i in $(_mesh_sorted_peer_indices); do
    local peer_ip="${PEER_IPS[$i]}"
    local peer_tunnel="${PEER_TUNNEL_IPS[$i]}"
    local peer_name="${PEER_NAMES[$i]}"
    local peer_port="${PEER_PORTS[$i]}"
    local peer_keepalive="${PEER_KEEPALIVES[$i]:-}"

    printf '\n'
    info "connecting to ${peer_name} (${peer_ip})"

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
    _connected_pubkeys[$i]="${peer_pubkey}"
    status_ok "${peer_name}" "${peer_tunnel} via ${peer_ip}:${peer_port}"
  done

  kill "${serve_pid}" 2>/dev/null || true
  wait "${serve_pid}" 2>/dev/null || true

  step "assembling final config"
  wg_assemble_config "${WG_DIR}" "${WG_INTERFACE}"
  status_ok "config written" "${WG_DIR}/${WG_INTERFACE}.conf"

step "verifying handshakes"
  local confirmed=0
  local pids=()
  local tmpdir
  tmpdir=$(mktemp -d)

  for i in "${!_connected_pubkeys[@]}"; do
    local peer_name="${PEER_NAMES[$i]}"
    local peer_pubkey="${_connected_pubkeys[$i]}"
    (
      for (( attempt = 1; attempt <= 20; attempt++ )); do
        if _mesh_check_peer_handshake "${WG_INTERFACE}" "${peer_pubkey}"; then
          echo "ok" > "${tmpdir}/${peer_name}"
          exit 0
        fi
        sleep 1
      done
      echo "fail" > "${tmpdir}/${peer_name}"
    ) &
    pids+=($!)
  done

  # wait for all background checks
  for pid in "${pids[@]}"; do
    wait "${pid}" 2>/dev/null || true
  done

  for i in "${!_connected_pubkeys[@]}"; do
    local peer_name="${PEER_NAMES[$i]}"
    if [[ "$(cat "${tmpdir}/${peer_name}" 2>/dev/null)" == "ok" ]]; then
      status_ok "${peer_name}" "handshake confirmed"
      confirmed=$(( confirmed + 1 ))
    else
      status_warn "${peer_name}" "no handshake after 20s"
    fi
  done
  rm -rf "${tmpdir}"

  printf '\n'
  divider
  status_ok "peers connected" "${confirmed}/${#PEER_IPS[@]}"
  [[ "${failed}" -gt 0 ]] && status_warn "peers unreachable" "${failed}"
  divider
  printf '\n'

  (( confirmed == 0 && ${#PEER_IPS[@]} > 0 )) && \
    fatal "no peers connected — check all nodes have run: ldown mesh init"

  # ── register pubkeys with czar ───────────────────────────────────────
  # mesh start does p2p bootstrap — czar doesn't know pubkeys yet.
  # non-czar nodes send JOIN so the czar can build its peer list.
  # czar stores all bootstrapped pubkeys it just exchanged directly.
  if [[ "${MY_IS_CZAR}" != "true" ]]; then
    local my_pub
    read -r my_pub < "${pubfile}"
    local join_payload="JOIN ${MY_NAME} ${MY_TUNNEL_IP} ${MY_IP} ${my_pub}"
    local join_sig
    join_sig="$(sign_msg "${join_payload}")"
    printf '%s\n' "${join_sig} ${join_payload}" \
      | ncat --wait 2 "${CZAR_IP}" "${LDOWN_PORT}" >/dev/null 2>&1 || \
      warn "could not register pubkey with czar — sync will retry"
  else
    for i in "${!_connected_pubkeys[@]}"; do
      local pname="${PEER_NAMES[$i]}"
      local ppub="${_connected_pubkeys[$i]}"
      printf '%s\n' "${ppub}" > "${KEY_DIR}/${pname}.public.key"
    done
  fi

  source "${BASH_SOURCE[0]%/*}/listener.sh"
  cmd_listener_start
  source "${BASH_SOURCE[0]%/*}/sync.sh"
  cmd_sync_start
  success "mesh started — ${MY_NAME} is live"
  printf '\n'
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

  local peer_list
  local _join_payload="JOIN ${MY_NAME} ${MY_TUNNEL_IP} ${MY_IP} ${my_pubkey}"
  peer_list="$(printf '%s\n' "$(sign_msg "${_join_payload}") ${_join_payload}" \
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

    local peer_name peer_tunnel peer_endpoint peer_pubkey peer_keepalive
    read -r peer_name peer_tunnel peer_endpoint peer_pubkey peer_keepalive \
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
    [[ $attempt -gt 20 ]] && status_warn "${peer_name}" "no handshake after 20s — may still converge"
  done

  printf '\n'
  divider
  status_ok "peers connected" "${confirmed}"
  [[ "${failed}" -gt 0 ]] && status_warn "peers skipped" "${failed}"
  divider
  printf '\n'

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
  response="$(printf '%s\n' "$(sign_msg "${_leave_payload}") ${_leave_payload}" | ncat "${CZAR_IP}" "${LDOWN_PORT}" 2>/dev/null)" || true
  
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

  if [[ -f "${CLUSTER_PUB}" ]]; then
    must "copy cluster.pub" cp "${CLUSTER_PUB}" "${stagedir}/cluster.pub"
    status_ok "included" "cluster.pub"
  else
    status_warn "cluster.pub" "not found — skipped"
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

  if [[ -f "${stagedir}/cluster.pub" ]]; then
    must "install cluster.pub" cp "${stagedir}/cluster.pub" "${CLUSTER_PUB}"
    must "secure cluster.pub"  chmod 644 "${CLUSTER_PUB}"
    status_ok "installed" "${CLUSTER_PUB}"
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