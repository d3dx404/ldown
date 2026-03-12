#!/usr/bin/env bash
# =============================================================================
# sync.sh — ldown self-healing background loop
# runs on every node, checks mesh health every SYNC_INTERVAL seconds
# =============================================================================

SYNC_INTERVAL="${SYNC_INTERVAL:-30}"
SYNC_PIDFILE="/run/ldown/sync.pid"
# honour the global PEER_STALE_AFTER from defaults.conf; fall back if not set
SYNC_STALE_THRESHOLD="${PEER_STALE_AFTER:-180}"

# =============================================================================
# internal logging
# =============================================================================
_slog() {
  local level="$1" msg="$2"
  printf '[%(%Y-%m-%dT%H:%M:%S)T] [%s] %s\n' -1 "${level}" "${msg}" \
    >> "${LOG_SYNC:-/var/log/ldown/sync.log}"
}

# =============================================================================
# sign_msg — sha256(payload + CLUSTER_TOKEN), same impl as mesh.sh
# CLUSTER_TOKEN is loaded from roster.conf by roster_load each cycle
# =============================================================================
sign_msg() {
  printf '%s' "$1${CLUSTER_TOKEN}" | sha256sum | awk '{print $1}'
}

# =============================================================================
# _sync_check_listener
# restart listener if it's dead
# =============================================================================
_sync_check_listener() {
  local pidfile="/run/ldown/listener.pid"
  local pid=""
  { read -r pid < "${pidfile}"; } 2>/dev/null || true
  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    _slog "WARN" "listener dead — restarting"
    # run in a subshell so any fatal/exit inside cmd_listener_start
    # cannot kill the sync loop
    ( cmd_listener_start ) 2>/dev/null \
      && _slog "INFO" "listener restarted" \
      || _slog "WARN" "listener restart failed — will retry next cycle"
  fi
}

# =============================================================================
# _sync_check_peer
# check a single peer's handshake age, re-add if stale/missing
# =============================================================================
_sync_check_peer() {
  local peer_name="$1"
  local peer_ip="$2"
  local peer_tunnel="$3"
  local peer_port="$4"
  local peer_keepalive="$5"

  local pubfile="${KEY_DIR}/${peer_name}.public.key"
  local peer_conf="${PEER_DIR}/peer-${peer_tunnel}.conf"

  # fetch pubkey if missing
  if [[ ! -f "${pubfile}" ]]; then
    _slog "INFO" "no pubkey for ${peer_name} — fetching from czar"
    local czar_ip="${CZAR_IP}"
    local fetched
    fetched="$(_sync_fetch_pubkey_from_czar "${peer_name}" "${czar_ip}")" || {
      _slog "WARN" "could not fetch pubkey for ${peer_name} from czar"
      return 1
    }
    printf '%s\n' "${fetched}" > "${pubfile}"
    _slog "INFO" "stored pubkey for ${peer_name}"
  fi

  local pubkey
  { read -r pubkey < "${pubfile}"; } 2>/dev/null || return 1
  is_valid_wg_key "${pubkey}" || {
    _slog "WARN" "invalid pubkey for ${peer_name} — skipping"
    return 1
  }

  # check handshake age
  local hs_ts
  hs_ts=$(wg show "${WG_INTERFACE}" latest-handshakes 2>/dev/null \
    | awk -v key="${pubkey}" '$1==key{print $2}')

  local now
  printf -v now '%(%s)T' -1
  local age=$(( now - ${hs_ts:-0} ))

  # peer is fresh — nothing to do
  if [[ -n "${hs_ts}" && "${hs_ts}" != "0" && "${age}" -lt "${SYNC_STALE_THRESHOLD}" ]]; then
    return 0
  fi

  # stale or never connected — re-add
  _slog "WARN" "peer ${peer_name} stale (${age}s) — re-adding"

  local wg_args=(
    wg set "${WG_INTERFACE}"
    peer "${pubkey}"
    allowed-ips "${peer_tunnel}/32"
    endpoint "${peer_ip}:${peer_port}"
  )
  [[ -n "${peer_keepalive}" ]] && wg_args+=(persistent-keepalive "${peer_keepalive}")
  "${wg_args[@]}" 2>/dev/null || {
    _slog "WARN" "wg set failed for ${peer_name}"
    return 1
  }

  # write peer conf if missing
  if [[ ! -f "${peer_conf}" ]]; then
    # run in a subshell so fatal inside wg_write_peer cannot kill the loop
    ( wg_write_peer "${peer_conf}" "${pubkey}" "${peer_tunnel}/32" \
        "${peer_ip}:${peer_port}" "${peer_keepalive}" ) 2>/dev/null \
      || _slog "WARN" "wg_write_peer failed for ${peer_name} — conf not persisted"
  fi

  # poke the peer to trigger handshake
  ping -c1 -W2 "${peer_tunnel}" &>/dev/null || true
  _slog "INFO" "re-added ${peer_name} (${peer_tunnel})"
}

# =============================================================================
# _sync_fetch_pubkey_from_czar
# ask czar for a specific node's pubkey via signed PUBKEY request
# =============================================================================
_sync_fetch_pubkey_from_czar() {
  local peer_name="$1"
  local czar_ip="$2"
  local payload="PUBKEY ${peer_name}"
  local sig
  sig=$(sign_msg "${payload}")
  local result
  result=$(printf '%s\n' "${sig} ${payload}" \
    | ncat --wait 5 "${czar_ip}" "${LDOWN_PORT}" 2>/dev/null) || return 1
  is_valid_wg_key "${result}" || return 1
  printf '%s\n' "${result}"
}

# =============================================================================
# _sync_rejoin_if_needed
# re-send JOIN to czar if our pubkey isn't registered
# =============================================================================
_sync_rejoin_if_needed() {
  local czar_ip="${CZAR_IP}"
  local my_pub
  { read -r my_pub < "${KEY_DIR}/${MY_NAME}.public.key"; } 2>/dev/null || return 1

  # send PING to czar to check if we're known
  local payload="PING ${MY_NAME}"
  local sig
  sig=$(sign_msg "${payload}")
  local response
  response=$(printf '%s\n' "${sig} ${payload}" \
    | ncat --wait 5 "${czar_ip}" "${LDOWN_PORT}" 2>/dev/null) || true

  if [[ "${response}" != "PONG"* ]]; then
    _slog "WARN" "czar doesn't know us — re-joining"
    local join_payload="JOIN ${MY_NAME} ${MY_TUNNEL_IP} ${MY_IP} ${my_pub}"
    local join_sig
    join_sig=$(sign_msg "${join_payload}")
    printf '%s\n' "${join_sig} ${join_payload}" \
      | ncat --wait 5 "${czar_ip}" "${LDOWN_PORT}" &>/dev/null || true
    _slog "INFO" "re-JOIN sent to czar"
  fi
}

# =============================================================================
# _sync_check_czar
# returns 0 if czar reachable, 1 if not
# =============================================================================
_sync_check_czar() {
  local czar_ip="${CZAR_IP}"
  ping -c1 -W3 "${czar_ip}" &>/dev/null && return 0
  # try tunnel IP too
  ping -c1 -W3 "${CZAR_TUNNEL_IP:-10.10.0.1}" &>/dev/null && return 0
  return 1
}

# =============================================================================
# cmd_sync_start — start the background sync loop
# =============================================================================
cmd_sync_start() {
  require_root
  check_dependency wg ncat ping ip

  [[ -f "${MESH_CONF}" ]] || fatal "mesh.conf not found — run: ldown mesh init"
  source_if_exists "${MESH_CONF}"
  roster_load "${ROSTER_CONF}" || fatal "roster failed to load"

  mkdir -p /run/ldown

  # check if already running
  local existing_pid=""
  { read -r existing_pid < "${SYNC_PIDFILE}"; } 2>/dev/null || true
  if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
    info "sync already running (pid ${existing_pid})"
    return 0
  fi

    set +e
    trap - ERR EXIT
  (
    _slog "INFO" "sync loop started (interval ${SYNC_INTERVAL}s)"

    while true; do
      sleep "${SYNC_INTERVAL}"

      # source fresh mesh state each cycle
      source_if_exists "${MESH_CONF}" 2>/dev/null || continue
      roster_load "${ROSTER_CONF}" 2>/dev/null || continue

      # skip if WG interface is down
      ip link show "${WG_INTERFACE}" &>/dev/null || {
        _slog "WARN" "interface ${WG_INTERFACE} down — skipping cycle"
        continue
      }

      # 1. check listener
      _sync_check_listener

      # 2. check czar reachable
      if ! _sync_check_czar; then
        _slog "WARN" "czar unreachable — regent mode not yet implemented"
        # TODO v0.1.3: regent election
      else
        # 3. re-join if czar doesn't know us (non-czar nodes only)
        [[ "${MY_IS_CZAR:-false}" == "true" ]] || _sync_rejoin_if_needed
      fi

      # 4. check all peers
      for i in "${!PEER_NAMES[@]}"; do
        _sync_check_peer \
          "${PEER_NAMES[$i]}" \
          "${PEER_IPS[$i]}" \
          "${PEER_TUNNEL_IPS[$i]}" \
          "${PEER_PORTS[$i]:-${WG_PORT}}" \
          "${PEER_KEEPALIVES[$i]:-}"
      done

    done
  ) &

  disown $!
  printf '%s\n' "$!" > "${SYNC_PIDFILE}"
  status_ok "sync loop started" "pid $! — every ${SYNC_INTERVAL}s"
}

# =============================================================================
# cmd_sync_stop
# =============================================================================
cmd_sync_stop() {
  local pid=""
  { read -r pid < "${SYNC_PIDFILE}"; } 2>/dev/null || true
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null
    rm -f "${SYNC_PIDFILE}"
    status_ok "sync stopped" "pid ${pid}"
  else
    status_warn "sync" "not running"
  fi
}

# =============================================================================
# cmd_sync_status
# =============================================================================
cmd_sync_status() {
  local pid=""
  { read -r pid < "${SYNC_PIDFILE}"; } 2>/dev/null || true
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    status_ok "sync" "pid ${pid} running"
  else
    status_warn "sync" "not running"
  fi
}