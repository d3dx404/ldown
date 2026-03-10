#!/usr/bin/env bash
# =============================================================================
# listener.sh — persistent ldown listener daemon
# =============================================================================
# Runs on every node after mesh start. Handles:
#
#   PUBKEY                           → respond with this node's WireGuard pubkey
#   JOIN <n> <tunnel_ip> <pubkey> → czar only: store key, return peer list
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
    ppubkey="\$(cat "\${pubfile}" 2>/dev/null)" || continue
    [[ -n "\${ppubkey}" ]] || continue
    if [[ -n "\${pkeepalive}" ]]; then
      printf '%s %s %s:%s %s %s\n' "\${pname}" "\${ptunnel}" "\${pip}" "\${pport}" "\${ppubkey}" "\${pkeepalive}"
    else
      printf '%s %s %s:%s %s\n' "\${pname}" "\${ptunnel}" "\${pip}" "\${pport}" "\${ppubkey}"
    fi
  done
}

_do_join() {
  local name="\$1" tunnel_ip="\$2" pubkey="\$3"
  _llog "INFO" "JOIN \${name} (\${tunnel_ip})"
  [[ -n "\${name}" && -n "\${tunnel_ip}" && -n "\${pubkey}" ]] || {
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
  local czar_pub
  czar_pub="\$(cat "\${KEY_DIR}/\${MY_NAME}.public.key" 2>/dev/null)"
  [[ -n "\${czar_pub}" ]] && \
    printf '%s %s %s:%s %s\n' "\${MY_NAME}" "\${MY_TUNNEL_IP}" "\${MY_IP}" "\${WG_PORT}" "\${czar_pub}"
  _peer_list
  _llog "INFO" "JOIN complete \${name}"
}

_do_leave() {
  local name="\$1" tunnel_ip="\$2" pubkey="\$3"
  _llog "INFO" "LEAVE \${name} (\${tunnel_ip})"
  local pubfile="\${KEY_DIR}/\${name}.public.key"
  if [[ -f "\${pubfile}" ]]; then
    local stored="\$(cat "\${pubfile}" 2>/dev/null)"
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
}

line=""
read -r -t 5 line || exit 0
line="\${line%%\$'\r'}"
[[ -z "\${line}" ]] && exit 0
action="\${line%% *}"
_llog "DEBUG" "recv: \${line:0:80}"

case "\${action}" in
  PUBKEY)
    pubfile="\${KEY_DIR}/\${MY_NAME}.public.key"
    [[ -f "\${pubfile}" ]] && cat "\${pubfile}" || printf 'ERROR pubkey not found\n'
    ;;
  JOIN)
    [[ "\${MY_IS_CZAR}" == "true" ]] || { printf 'ERROR not czar\n'; exit 1; }
    read -ra p <<< "\${line}"
    _do_join "\${p[1]:-}" "\${p[2]:-}" "\${p[3]:-}"
    ;;
  LEAVE)
    [[ "\${MY_IS_CZAR}" == "true" ]] || { printf 'ERROR not czar\n'; exit 1; }
    read -ra p <<< "\${line}"
    _do_leave "\${p[1]:-}" "\${p[2]:-}" "\${p[3]:-}"
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

  # already running?
  if [[ -f "${pidfile}" ]]; then
    local existing_pid
    existing_pid="$(cat "${pidfile}" 2>/dev/null)"
    if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
      info "listener already running (pid ${existing_pid})"
      return 0
    fi
    rm -f "${pidfile}"
  fi

  # write handler to secure temp file
  local handler
  handler="$(mktemp /tmp/ldown-handler.XXXXXX)"
  _listener_write_handler "${handler}"

  _listener_log "INFO" "starting on ${MY_IP}:${LDOWN_PORT} (czar=${MY_IS_CZAR})"

  (
    trap 'rm -f "${handler}"' EXIT
    while true; do
      ncat -l "${MY_IP}" "${LDOWN_PORT}" \
        --sh-exec "bash ${handler}" \
        --idle-timeout 5 \
        2>>"${LOG_LISTENER}" || true
      sleep 1
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
    pid="$(cat "${pidfile}" 2>/dev/null)"
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
    pid="$(cat "${pidfile}" 2>/dev/null)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      status_ok "listener" "running (pid ${pid})"
      return 0
    fi
  fi
  status_warn "listener" "not running"
  return 1
}