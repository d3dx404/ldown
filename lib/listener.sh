#!/usr/bin/env bash
# =============================================================================
# listener.sh — persistent ldown listener daemon
# =============================================================================
# Runs on every node after mesh start. Handles:
#
#   PUBKEY                           → respond with this node's WireGuard pubkey
#   JOIN <n> <tunnel_ip> <public_ip> <pubkey> → czar only: store key, return peer list
#   LEAVE <n> <tunnel_ip> <pubkey>→ czar only: remove peer from mesh
#   PING                             → respond PONG (health check)
#
# Architecture:
#   A handler script is written via mktemp at daemon start.
#   ncat loops with --sh-exec pointing to that script.
#   Each connection gets a fresh handler invocation with full context.
#
# PID file:  /run/ldown/listener.pid
# Log:       /var/log/ldown/listener.log
# =============================================================================

[[ "${_LISTENER_SH_LOADED:-}" == "1" ]] && return 0
_LISTENER_SH_LOADED=1

# ---------------------------------------------------------------------------
# _listener_log
# ---------------------------------------------------------------------------
_listener_log() {
  local level="$1"; shift
  printf '[%s] [%s] %s\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S')" \
    "${level}" \
    "$*" >> "${LOG_LISTENER:-/var/log/ldown/listener.log}"
}

# ---------------------------------------------------------------------------
# _listener_write_handler
# Writes a self-contained handler script called by ncat --sh-exec per connection
# ---------------------------------------------------------------------------
_listener_write_handler() {
  local handler_path="$1"
  local script_dir="${SCRIPT_DIR}"
  local mesh_conf="${MESH_CONF}"
  local roster_conf="${ROSTER_CONF}"
  local log_listener="${LOG_LISTENER}"
  local key_dir="${KEY_DIR}"
  local peer_dir="${PEER_DIR}"
  local wg_interface="${WG_INTERFACE}"
  local wg_port="${WG_PORT}"
  local ldown_port="${LDOWN_PORT}"

  cat > "${handler_path}" << HANDLER_EOF
#!/usr/bin/env bash
# auto-generated ldown handler — $(date)

source "${script_dir}/../conf/defaults.conf" 2>/dev/null
source "${script_dir}/../lib/common.sh"      2>/dev/null
source "${script_dir}/../lib/wireguard.sh"   2>/dev/null
source "${script_dir}/../lib/roster.sh"      2>/dev/null
source "${mesh_conf}"                         2>/dev/null
roster_load "${roster_conf}"                  2>/dev/null

LOG_LISTENER="${log_listener}"
KEY_DIR="${key_dir}"
PEER_DIR="${peer_dir}"
WG_INTERFACE="${wg_interface}"
WG_PORT="${wg_port}"
LDOWN_PORT="${ldown_port}"

_llog() {
  printf '[%s] [%s] %s\n' "\$(date '+%Y-%m-%dT%H:%M:%S')" "\$1" "\$2" \
    >> "\${LOG_LISTENER}"
}

_peer_list() {
  local i
  for i in "\${!PEER_NAMES[@]}"; do
    local pname="\${PEER_NAMES[\$i]}"
    local ptunnel="\${PEER_TUNNEL_IPS[\$i]}"
    local pip="\${PEER_IPS[\$i]}"
    local pport="\${PEER_PORTS[\$i]:-\${WG_PORT}}"
    local pkeepalive="\${PEER_KEEPALIVES[\$i]:-}"
    local pubfile="\${KEY_DIR}/\${pname}.public.key"
    [[ -f "\${pubfile}" ]] || continue
    local ppubkey
    { read -r ppubkey < "\${pubfile}"; } 2>/dev/null || continue
    [[ -n "\${ppubkey}" ]] || continue
    if [[ -n "\${pkeepalive}" ]]; then
      printf '%s %s %s:%s %s %s\n' "\${pname}" "\${ptunnel}" "\${pip}" "\${pport}" "\${ppubkey}" "\${pkeepalive}"
    else
      printf '%s %s %s:%s %s\n' "\${pname}" "\${ptunnel}" "\${pip}" "\${pport}" "\${ppubkey}"
    fi
  done
}

_do_join() {
  local name="\$1" tunnel_ip="\$2" public_ip="\$3" pubkey="\$4"
  _llog "INFO" "JOIN \${name} (\${tunnel_ip}) from \${public_ip}"
  [[ -n "\${name}" && -n "\${tunnel_ip}" && -n "\${public_ip}" && -n "\${pubkey}" ]] || {
    printf 'ERROR missing fields\n'; return 1; }
  is_valid_wg_key "\${pubkey}" || {
    _llog "WARN" "bad pubkey from \${name}"
    printf 'ERROR invalid pubkey\n'; return 1; }
  local found=0 i
  for i in "\${!PEER_NAMES[@]}"; do
    [[ "\${PEER_NAMES[\$i]}" == "\${name}" ]] && { found=1; break; }
  done
  [[ "\${name}" == "\${MY_NAME}" ]] && found=1
  [[ "\${found}" -eq 1 ]] || {
    _llog "WARN" "\${name} not in roster"
    printf 'ERROR not in roster\n'; return 1; }
  printf '%s\n' "\${pubkey}" > "\${KEY_DIR}/\${name}.public.key"
  _llog "INFO" "stored pubkey for \${name}"

  # czar adds the joining node to its own WireGuard interface
  # every other node gets a PEER_ADD message — czar processes the JOIN directly
  # so it must do the wg set itself or the joining node is never in czar's peers
  ip link show "\${WG_INTERFACE}" &>/dev/null && \
    wg set "\${WG_INTERFACE}" peer "\${pubkey}" \
      allowed-ips "\${tunnel_ip}/32" \
      endpoint "\${public_ip}:\${WG_PORT}" 2>/dev/null && \
    _llog "INFO" "czar added \${name} to WireGuard" || \
    _llog "WARN" "czar wg set failed for \${name}"
  wg_write_peer "\${PEER_DIR}/peer-\${tunnel_ip}.conf" \
    "\${pubkey}" "\${tunnel_ip}/32" "\${public_ip}:\${WG_PORT}" ""
  ping -c1 -W1 "\${tunnel_ip}" &>/dev/null || true

  local czar_pub
  { read -r czar_pub < "${KEY_DIR}/${MY_NAME}.public.key"; } 2>/dev/null
  [[ -n "\${czar_pub}" ]] && \
    printf '%s %s %s:%s %s\n' "\${MY_NAME}" "\${MY_TUNNEL_IP}" "\${MY_IP}" "\${WG_PORT}" "\${czar_pub}"
  _peer_list
  _llog "INFO" "JOIN complete \${name}"

  # notify all existing peers about the new node
  # skip self, skip the joining node (they already have the list)
  local i
  for i in "\${!PEER_NAMES[@]}"; do
    local pname="\${PEER_NAMES[\$i]}"
    local pip="\${PEER_IPS[\$i]}"
    local pkeepalive="\${PEER_KEEPALIVES[\$i]:-}"
    [[ "\${pname}" == "\${MY_NAME}" ]] && continue
    [[ "\${pname}" == "\${name}" ]] && continue
    local ppub
    { read -r ppub < "${KEY_DIR}/${pname}.public.key"; } 2>/dev/null
    [[ -z "\${ppub}" ]] && continue
    local payload="PEER_ADD \${name} \${tunnel_ip} \${public_ip}:\${WG_PORT} \${pubkey} \${pkeepalive}"
    local notify="\$(sign_msg "\${payload}") \${payload}"
    # send with one retry
    if ! printf '%s\n' "\${notify}" | ncat --wait 2 "\${pip}" "\${LDOWN_PORT}" >/dev/null 2>&1; then
      sleep 2
      printf '%s\n' "\${notify}" | ncat --wait 2 "\${pip}" "\${LDOWN_PORT}" >/dev/null 2>&1 || \
        _llog "WARN" "PEER_ADD failed for \${pname} (\${pip}) after retry"
    else
      _llog "DEBUG" "PEER_ADD sent to \${pname}"
    fi
  done
}

_do_leave() {
  local name="\$1" tunnel_ip="\$2" pubkey="\$3"
  _llog "INFO" "LEAVE \${name} (\${tunnel_ip})"
  local pubfile="\${KEY_DIR}/\${name}.public.key"
  if [[ -f "\${pubfile}" ]]; then
    local stored; { read -r stored < "${pubfile}"; } 2>/dev/null
    [[ "\${stored}" == "\${pubkey}" ]] || {
      _llog "WARN" "pubkey mismatch for \${name}"
      printf 'ERROR pubkey mismatch\n'; return 1; }
  fi
  if ip link show "\${WG_INTERFACE}" &>/dev/null 2>&1; then
    wg set "\${WG_INTERFACE}" peer "\${pubkey}" remove 2>/dev/null
  fi
  rm -f "\${PEER_DIR}/peer-\${tunnel_ip}.conf"
  printf 'OK\n'
  _llog "INFO" "LEAVE complete \${name}"

  # notify all peers to remove this node
  local i
  for i in "\${!PEER_NAMES[@]}"; do
    local pname="\${PEER_NAMES[\$i]}"
    local pip="\${PEER_IPS[\$i]}"
    [[ "\${pname}" == "\${MY_NAME}" ]] && continue
    [[ "\${pname}" == "\${name}" ]] && continue
    local rm_payload="PEER_REMOVE \${name} \${tunnel_ip} \${pubkey}"
    local remove_msg="\$(sign_msg "\${rm_payload}") \${rm_payload}"
    printf '%s\n' "\${remove_msg}" | ncat --wait 2 "\${pip}" "\${LDOWN_PORT}" >/dev/null 2>&1 || \
      _llog "WARN" "PEER_REMOVE failed for \${pname}"
  done
}

line=""
read -r -t 5 line || exit 0
line="\${line%%\$'\r'}"
[[ -z "\${line}" ]] && exit 0

# ---------------------------------------------------------------------------
# message signing — sign_msg / verify_msg
# sign_msg <payload>  → sha256(payload + CLUSTER_TOKEN)
# the token never appears on the wire; the sig is bound to this exact message
# so a captured sig cannot be replayed for a different message type or content
# ---------------------------------------------------------------------------
sign_msg() {
  printf '%s' "\$1\${CLUSTER_TOKEN}" | sha256sum | awk '{print \$1}'
}

verify_msg() {
  local received_sig="\$1"
  local payload="\$2"
  if [[ -z "\${CLUSTER_TOKEN}" ]]; then
    _llog "WARN" "CLUSTER_TOKEN not loaded — rejecting message"
    return 1
  fi
  local expected
  expected="\$(sign_msg "\${payload}")"
  [[ "\${received_sig}" == "\${expected}" ]]
}

# wire format: <sig> <ACTION> <args...>
# sig is field 0, action is field 1, args start at field 2
# PUBKEY and PING are exempt — they run before any token is available (bootstrap)
read -ra p <<< "\${line}"
sig="\${p[0]:-}"
action="\${p[1]:-}"
payload="\${line#* }"   # everything after the sig — the exact string that was signed

_llog "DEBUG" "recv action=\${action} sig=\${sig:0:16}..."

if [[ "\${action}" != "PUBKEY" && "\${action}" != "PING" ]]; then
  verify_msg "\${sig}" "\${payload}" || {
    _llog "WARN" "sig verify failed for \${action} — dropping"
    exit 1
  }
fi

case "\${action}" in
  PUBKEY)
    pubfile="\${KEY_DIR}/\${MY_NAME}.public.key"
    [[ -f "\${pubfile}" ]] && cat "\${pubfile}" || printf 'ERROR pubkey not found\n'
    ;;
  JOIN)
    [[ "\${MY_IS_CZAR}" == "true" ]] || { printf 'ERROR not czar\n'; exit 1; }
    # payload: JOIN name tunnel_ip public_ip pubkey
    # p[0]=sig p[1]=JOIN p[2]=name p[3]=tunnel_ip p[4]=public_ip p[5]=pubkey
    _do_join "\${p[2]:-}" "\${p[3]:-}" "\${p[4]:-}" "\${p[5]:-}"
    ;;
  LEAVE)
    [[ "\${MY_IS_CZAR}" == "true" ]] || { printf 'ERROR not czar\n'; exit 1; }
    # p[0]=sig p[1]=LEAVE p[2]=name p[3]=tunnel_ip p[4]=pubkey
    _do_leave "\${p[2]:-}" "\${p[3]:-}" "\${p[4]:-}"
    ;;
  PEER_ADD)
    # p[0]=sig p[1]=PEER_ADD p[2]=name p[3]=tunnel p[4]=endpoint p[5]=pubkey p[6]=keepalive
    pname="\${p[2]:-}" ptunnel="\${p[3]:-}" pendpoint="\${p[4]:-}"
    ppubkey="\${p[5]:-}" pkeepalive="\${p[6]:-}"
    is_valid_wg_key "\${ppubkey}" || { printf 'ERROR invalid pubkey\n'; exit 1; }
    wg_args=(wg set "\${WG_INTERFACE}" peer "\${ppubkey}" allowed-ips "\${ptunnel}/32" endpoint "\${pendpoint}")
    [[ -n "\${pkeepalive}" ]] && wg_args+=(persistent-keepalive "\${pkeepalive}")
    "\${wg_args[@]}" 2>/dev/null && printf 'OK\n' || printf 'ERROR wg set failed\n'
    wg_write_peer "\${PEER_DIR}/peer-\${ptunnel}.conf" "\${ppubkey}" "\${ptunnel}/32" "\${pendpoint}" "\${pkeepalive}"
    _llog "INFO" "PEER_ADD \${pname} (\${ptunnel}) persisted"
    ;;
  PEER_REMOVE)
    # p[0]=sig p[1]=PEER_REMOVE p[2]=name p[3]=tunnel_ip p[4]=pubkey
    ppubkey="\${p[4]:-}"
    is_valid_wg_key "\${ppubkey}" || { printf 'ERROR invalid pubkey\n'; exit 1; }
    ip link show "\${WG_INTERFACE}" &>/dev/null && wg set "\${WG_INTERFACE}" peer "\${ppubkey}" remove 2>/dev/null
    rm -f "\${PEER_DIR}/peer-\${p[3]:-}.conf" 2>/dev/null
    printf 'OK\n'
    _llog "INFO" "PEER_REMOVE \${p[2]:-}"
    ;;
  PING)
    printf 'PONG\n'
    ;;
  *)
    _llog "WARN" "unknown action: \${action}"
    printf 'ERROR unknown action\n'
    ;;
esac
HANDLER_EOF

  chmod 700 "${handler_path}"
}

# ---------------------------------------------------------------------------
# cmd_listener_start
# ---------------------------------------------------------------------------
cmd_listener_start() {
  require_root
  check_dependency ncat wg fuser

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — run: ldown mesh init"
  source_if_exists "${MESH_CONF}"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load"

  # ensure PID dir exists
  mkdir -p /run/ldown
  local pidfile="/run/ldown/listener.pid"

  # already running? check if handler is stale (listener.sh newer than handler)
  if [[ -f "${pidfile}" ]]; then
    local existing_pid
    { read -r existing_pid < "${pidfile}"; } 2>/dev/null
    if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
      local handler_file
      { read -r handler_file < /run/ldown/listener.handler; } 2>/dev/null
      if [[ -n "${handler_file}" && -f "${handler_file}" ]] && \
         [[ "${BASH_SOURCE[0]}" -nt "${handler_file}" ]]; then
        info "listener.sh updated — restarting to regenerate handler"
        kill "${existing_pid}" 2>/dev/null || true
        sleep 1
        rm -f "${pidfile}" /tmp/ldown-handler.* 2>/dev/null || true
      else
        info "listener already running (pid ${existing_pid})"
        return 0
      fi
    else
      rm -f "${pidfile}"
    fi
  fi

  # write handler to secure temp file
  local handler
  handler="$(mktemp /tmp/ldown-handler.XXXXXX)"
  _listener_write_handler "${handler}"
  echo "${handler}" > /run/ldown/listener.handler

  _listener_log "INFO" "starting on ${MY_IP}:${LDOWN_PORT} (czar=${MY_IS_CZAR})"

  (
    trap 'rm -f "${handler}"' EXIT
    while true; do
      ncat -l "${MY_IP}" "${LDOWN_PORT}" \
        --sh-exec "bash ${handler}" \
        --idle-timeout 5 \
        2>>"${LOG_LISTENER}" || true
      sleep 3
    done
  ) &

  local lpid=$!
  echo "${lpid}" > "${pidfile}"
  _listener_log "INFO" "started (pid ${lpid})"
  status_ok "listener" "pid ${lpid} on ${MY_IP}:${LDOWN_PORT}"
}

# ---------------------------------------------------------------------------
# cmd_listener_stop
# ---------------------------------------------------------------------------
cmd_listener_stop() {
  require_root
  local pidfile="/run/ldown/listener.pid"
  local pid=""

  if [[ -f "${pidfile}" ]]; then
    { read -r pid < "${pidfile}"; } 2>/dev/null
    if [[ -n "${pid}" ]]; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
    rm -f "${pidfile}"
  fi

  # clean up handler scripts and stray ncat
  rm -f /tmp/ldown-handler.* 2>/dev/null || true
  source_if_exists "${MESH_CONF}"
  local port="${LDOWN_PORT:-51821}"
  fuser -k "${port}/tcp" 2>/dev/null || true

  status_ok "listener stopped" "${pid:+pid ${pid}}"
  _listener_log "INFO" "stopped"
}

# ---------------------------------------------------------------------------
# cmd_listener_status
# ---------------------------------------------------------------------------
cmd_listener_status() {
  local pidfile="/run/ldown/listener.pid"
  if [[ -f "${pidfile}" ]]; then
    local pid
    { read -r pid < "${pidfile}"; } 2>/dev/null
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      status_ok "listener" "running (pid ${pid})"
      return 0
    fi
  fi
  status_warn "listener" "not running"
  return 1
}