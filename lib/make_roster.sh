#!/usr/bin/env bash
# =============================================================================
# make_roster.sh — interactive roster builder
# part of ldown — deterministic self-healing WireGuard mesh orchestrator
# =============================================================================
#
# sourced by bin/ldown — never run directly
# requires: common.sh already sourced
# =============================================================================

[[ -n "${_MAKE_ROSTER_SH_LOADED:-}" ]] && return 0
_MAKE_ROSTER_SH_LOADED=1

# =============================================================================
# cmd_make_roster
# =============================================================================
# interactive wizard to build /etc/ldown/roster.conf
#
# collects:
#   - global subnet + ports
#   - per-node: public IP, name, tunnel IP, czar, relay, keepalive
#
# validates:
#   - unique names, IPs, tunnel IPs
#   - exactly one czar
#   - valid IP format
#   - valid port + keepalive values
#
# writes: /etc/ldown/roster.conf (atomic via mktemp)
# =============================================================================

cmd_make_roster() {
  banner
  require_root
  check_dependency mktemp date

  # ── parallel arrays — one entry per node ─────────────────
  local -a NAMES=()
  local -a IPS=()
  local -a TUNNELS=()
  local -a IS_CZAR=()
  local -a IS_RELAY=()
  local -a KEEPALIVES=()

  local czar_count=0

  # ── global settings ──────────────────────────────────────
  step "global settings"

  local subnet wg_port ldown_port

  printf '\n'
  read -rp "  subnet prefix (default: 10.10.0): " subnet
  subnet="${subnet:-10.10.0}"
  [[ "${subnet}" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]] || fatal "invalid subnet prefix: ${subnet}"

  read -rp "  WireGuard port (default: 51820): " wg_port
  wg_port="${wg_port:-51820}"
  [[ "${wg_port}" =~ ^[0-9]+$ ]] || fatal "invalid WireGuard port: ${wg_port}"

  read -rp "  ldown port (default: 51821): " ldown_port
  ldown_port="${ldown_port:-51821}"
  [[ "${ldown_port}" =~ ^[0-9]+$ ]] || fatal "invalid ldown port: ${ldown_port}"

  status_ok "subnet"      "${subnet}.0/24"
  status_ok "wg port"     "${wg_port}"
  status_ok "ldown port"  "${ldown_port}"

  # ── node count ───────────────────────────────────────────
  printf '\n'
  local count
  read -rp "  how many nodes: " count
  [[ "${count}" =~ ^[0-9]+$ ]] || fatal "invalid node count"
  (( count > 0 ))               || fatal "must have at least one node"

  # ── collect nodes ────────────────────────────────────────
  local i
  for (( i = 0; i < count; i++ )); do
    printf '\n'
    step "node $(( i + 1 )) of ${count}"
    printf '\n'

    # name
    local name
    while true; do
      read -rp "  node name: " name
      [[ -n "${name}" ]] || { warn "name cannot be empty"; continue; }
      [[ "${name}" =~ ^[a-zA-Z0-9_-]+$ ]] || { warn "name must be alphanumeric (hyphens/underscores ok)"; continue; }
      _make_roster_unique "${name}" "${NAMES[@]+"${NAMES[@]}"}" || { warn "duplicate name: ${name}"; continue; }
      break
    done

    # public IP
    local ip
    while true; do
      read -rp "  public IP: " ip
      _make_roster_valid_ip "${ip}" || { warn "invalid IP: ${ip}"; continue; }
      _make_roster_unique "${ip}" "${IPS[@]+"${IPS[@]}"}" || { warn "duplicate IP: ${ip}"; continue; }
      break
    done

    # tunnel IP — auto-assign default
    local default_tunnel="${subnet}.$(( i + 1 ))"
    local tunnel
    while true; do
      read -rp "  tunnel IP (default: ${default_tunnel}): " tunnel
      tunnel="${tunnel:-${default_tunnel}}"
      _make_roster_valid_ip "${tunnel}" || { warn "invalid tunnel IP: ${tunnel}"; continue; }
      [[ "${tunnel}" == "${subnet}."* ]] || { warn "tunnel IP must be within subnet ${subnet}.0/24"; continue; }
      _make_roster_unique "${tunnel}" "${TUNNELS[@]+"${TUNNELS[@]}"}" || { warn "duplicate tunnel IP: ${tunnel}"; continue; }
      [[ "${tunnel}" != "${ip}" ]] || { warn "tunnel IP cannot match public IP"; continue; }
      break
    done

    # czar
    local czar=0
    local czar_ans
    read -rp "  is this the czar? [y/N]: " czar_ans
    if [[ "${czar_ans}" =~ ^[Yy]$ ]]; then
      czar=1
      (( czar_count++ )) || true
    fi

    # relay
    local relay=0
    local relay_ans
    read -rp "  is this a relay node? [y/N]: " relay_ans
    [[ "${relay_ans}" =~ ^[Yy]$ ]] && relay=1

    # keepalive — only prompt if not a server (servers don't need it)
    local keepalive=""
    local ka_ans
    read -rp "  persistent keepalive seconds [optional]: " ka_ans
    if [[ -n "${ka_ans}" ]]; then
      [[ "${ka_ans}" =~ ^[0-9]+$ ]] || fatal "invalid keepalive: ${ka_ans}"
      keepalive="${ka_ans}"
    fi

    # store
    NAMES+=("${name}")
    IPS+=("${ip}")
    TUNNELS+=("${tunnel}")
    IS_CZAR+=("${czar}")
    IS_RELAY+=("${relay}")
    KEEPALIVES+=("${keepalive}")

    # confirm
    printf '\n'
    local flags=""
    (( czar   == 1 )) && flags+=" --czar"
    (( relay  == 1 )) && flags+=" --relay"
    [[ -n "${keepalive}" ]] && flags+=" --keepalive ${keepalive}"
    status_ok "${name}" "${ip} → tunnel ${tunnel}${flags}"
  done

  # ── validate exactly one czar ────────────────────────────
  printf '\n'
  step "validating roster"

  (( czar_count == 1 )) || fatal "exactly one node must be czar — got ${czar_count}"
  status_ok "czar check" "exactly one czar"
  status_ok "nodes"      "${count}"

  # ── preview ──────────────────────────────────────────────
  printf '\n'
  step "roster preview"
  printf '\n'

  printf '  SUBNET=%s\n'      "${subnet}"
  printf '  WG_PORT=%s\n'     "${wg_port}"
  printf '  LDOWN_PORT=%s\n'  "${ldown_port}"
  printf '\n'

  for (( i = 0; i < count; i++ )); do
    local line="  ${IPS[$i]}"
    [[ -n "${NAMES[$i]}" ]]     && line+=" --name ${NAMES[$i]}"
    [[ "${IS_CZAR[$i]}" == 1 ]] && line+=" --czar"
    [[ "${IS_RELAY[$i]}" == 1 ]] && line+=" --relay"
    local tun_default="${subnet}.$(( i + 1 ))"
    [[ "${TUNNELS[$i]}" != "${tun_default}" ]] && line+=" --tunnel ${TUNNELS[$i]}"
    [[ -n "${KEEPALIVES[$i]}" ]] && line+=" --keepalive ${KEEPALIVES[$i]}"
    printf '%s\n' "${line}"
  done

  printf '\n'

  # ── confirm write ────────────────────────────────────────
  confirm "write roster to ${ROSTER_CONF}?" || { info "cancelled — nothing written"; return 0; }

  # ── write ────────────────────────────────────────────────
  step "writing roster"

  must "create config dir" mkdir -p "${CONFIG_DIR}"

  local tmpfile
  tmpfile="$(mktemp)" || fatal "cannot create temp file"

  {
    printf '# ldown roster — generated by ldown make_roster\n'
    printf '# %s\n' "$(date)"
    printf '\n'
    printf 'SUBNET=%s\n'     "${subnet}"
    printf 'WG_PORT=%s\n'    "${wg_port}"
    printf 'LDOWN_PORT=%s\n' "${ldown_port}"
    printf '\n'

    for (( i = 0; i < count; i++ )); do
      local entry="${IPS[$i]}"
      [[ -n "${NAMES[$i]}" ]]      && entry+=" --name ${NAMES[$i]}"
      [[ "${IS_CZAR[$i]}" == 1 ]]  && entry+=" --czar"
      [[ "${IS_RELAY[$i]}" == 1 ]] && entry+=" --relay"
      local tun_default="${subnet}.$(( i + 1 ))"
      [[ "${TUNNELS[$i]}" != "${tun_default}" ]] && entry+=" --tunnel ${TUNNELS[$i]}"
      [[ -n "${KEEPALIVES[$i]}" ]]  && entry+=" --keepalive ${KEEPALIVES[$i]}"
      printf '%s\n' "${entry}"
    done
  } > "${tmpfile}"

  must "install roster" mv "${tmpfile}" "${ROSTER_CONF}"
  must "secure roster"  chmod 640 "${ROSTER_CONF}"

  status_ok "roster written" "${ROSTER_CONF}"

  # ── done ─────────────────────────────────────────────────
  printf '\n'
  success "roster complete — ${count} nodes"
  printf '\n'
  info "next step: run on each node: ldown mesh init"
  printf '\n'
}

# =============================================================================
# internal helpers
# =============================================================================

# check if value is a valid IPv4 address
_make_roster_valid_ip() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  local -a octets=( ${ip} )
  local o
  for o in "${octets[@]}"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

# check if value is unique among the rest of the arguments
# usage: _make_roster_unique <value> [existing...]
_make_roster_unique() {
  local val="$1"
  shift
  local existing
  for existing in "$@"; do
    [[ "${existing}" == "${val}" ]] && return 1
  done
  return 0
}