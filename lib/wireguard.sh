#!/usr/bin/env bash
# lib/wireguard.sh — WireGuard key generation, config writing, and interface control
#
# depends on lib/common.sh being sourced first.
# does not handle firewall or routing — those belong in network.sh.

# ── guard against double-sourcing ─────────────────────────
[[ -n "${_LDOWN_WG_LOADED:-}" ]] && return 0
_LDOWN_WG_LOADED=1

# ── dependency check ───────────────────────────────────────
[[ -n "${_LDOWN_COMMON_LOADED:-}" ]] \
  || { printf 'wireguard.sh requires common.sh to be sourced first\n' >&2; return 1; }

_wg_require_cmd() {
  [[ -n "${_LDOWN_WG_CMD_CHECKED:-}" ]] && return 0
  has_cmd wg       || fatal "wireguard-tools not installed — 'wg' not found"
  has_cmd wg-quick || fatal "wireguard-tools not installed — 'wg-quick' not found"
  _LDOWN_WG_CMD_CHECKED=1
}
# ── key helpers ────────────────────────────────────────────

# derive public key from private — never logs the private key
wg_pubkey() {
  _wg_require_cmd
  local priv="$1"
  printf '%s' "$priv" | wg pubkey
}

# generate a new keypair.
# output: two lines — private key, then public key.
# usage:  read -r priv pub < <(wg_generate_keypair)
wg_generate_keypair() {
  _wg_require_cmd

  local priv pub
  priv=$(wg genkey)                      || fatal "wg genkey failed"
  pub=$(printf '%s' "$priv" | wg pubkey) || fatal "wg pubkey failed"

  debug "wireguard keypair generated"
  printf '%s\n%s\n' "$priv" "$pub"
}

# generate a named keypair and write to files
# usage: wg_generate_keypair_named <name> <keydir>
wg_generate_keypair_named() {
  local name="$1"
  local keydir="$2"
  local priv pub
  read -r priv pub < <(wg_generate_keypair)
  mkdir -p "${keydir}"
  printf '%s\n' "${priv}" > "${keydir}/${name}.private.key"
  chmod 600 "${keydir}/${name}.private.key"
  printf '%s\n' "${pub}" > "${keydir}/${name}.public.key"
  chmod 644 "${keydir}/${name}.public.key"
  debug "named keypair written for ${name}"
}

# ── atomic config writers ──────────────────────────────────
# all writers use mktemp + chmod 600 + mv — never partial writes.
# private key is written but never logged.

wg_write_interface() {
  local file="$1"
  local address="$2"
  local port="$3"
  local privkey="$4"

  is_valid_cidr   "${address}"  || fatal "wg_write_interface: invalid address '${address}'"
  [[ "${port}" =~ ^[0-9]+$ ]]  || fatal "wg_write_interface: invalid port '${port}'"
  is_valid_wg_key "${privkey}"  || fatal "wg_write_interface: invalid private key"

  local tmp
  tmp=$(mktemp) || fatal "wg_write_interface: mktemp failed"

  cat > "$tmp" <<EOF
[Interface]
Address = ${address}
ListenPort = ${port}
PrivateKey = ${privkey}
EOF

  chmod 600 "$tmp"
  mkdir -p "$(dirname "${file}")"
  mv "$tmp" "${file}" || fatal "wg_write_interface: failed to write ${file}"
  debug "interface config written → ${file}"
}

# write a single [Peer] block to its own file.
# endpoint is required for server-to-server tunnels — must include port.
# keepalive is optional — pass empty string or 0 to omit.
wg_write_peer() {
  local file="$1"
  local pubkey="$2"
  local allowed="$3"
  local endpoint="$4"
  local keepalive="${5:-}"

  is_valid_wg_key "${pubkey}"  || fatal "wg_write_peer: invalid public key"
  is_valid_cidr   "${allowed}" || fatal "wg_write_peer: invalid AllowedIPs '${allowed}'"
  [[ -n "${endpoint}" ]]       || fatal "wg_write_peer: endpoint is required"
  [[ "${endpoint}" =~ :[0-9]+$ ]] \
    || fatal "wg_write_peer: endpoint must include port (e.g. host:51820)"

  local tmp
  tmp=$(mktemp) || fatal "wg_write_peer: mktemp failed"

  cat > "$tmp" <<EOF
[Peer]
PublicKey = ${pubkey}
Endpoint = ${endpoint}
AllowedIPs = ${allowed}
EOF

  if [[ -n "${keepalive}" && "${keepalive}" != "0" ]]; then
    printf 'PersistentKeepalive = %s\n' "${keepalive}" >> "$tmp"
  fi
  local psk_file="${KEY_DIR:-/etc/ldown/keys}/mesh.psk"
  if [[ -f "${psk_file}" ]]; then
    printf 'PresharedKey = %s\n' "$(cat "${psk_file}")" >> "$tmp"
  fi

  chmod 600 "$tmp"
  mkdir -p "$(dirname "${file}")"
  mv "$tmp" "${file}" || fatal "wg_write_peer: failed to write ${file}"
  debug "peer config written → ${file} (pub=${pubkey})"
}

# ── peer utilities ─────────────────────────────────────────

# returns the path of any peer file containing this public key.
# anchored match prevents partial key collisions.
wg_peer_exists() {
  local pub="$1"
  local dir="$2"
  [[ -d "${dir}" ]] || return 1
  grep -rl "^PublicKey = ${pub}$" -- "${dir}" 2>/dev/null
}

# ── config assembly ────────────────────────────────────────

# assemble interface.conf + peers/*.conf into a single wg config.
# output filename is derived from the interface name (e.g. wg0 → wg0.conf).
# never partially writes — atomic mv at the end.
wg_assemble_config() {
  local dir="$1"
  local iface="${2:-wg0}"
  local out="${dir}/${iface}.conf"

  [[ -r "${dir}/interface.conf" ]] \
    || fatal "wg_assemble_config: cannot read ${dir}/interface.conf"

  [[ -d "${dir}/peers" ]] || mkdir -p "${dir}/peers"

  local tmp
  tmp=$(mktemp) || fatal "wg_assemble_config: mktemp failed"

  cat "${dir}/interface.conf" > "$tmp"
  printf '\n' >> "$tmp"

  local p
  for p in "${dir}/peers/"*.conf; do
    [[ -f "$p" ]] || continue
    cat "$p"    >> "$tmp"
    printf '\n' >> "$tmp"
  done

  chmod 600 "$tmp"
  mv "$tmp" "${out}" || fatal "wg_assemble_config: failed to write ${out}"
  debug "assembled config → ${out}"
}

# ── interface control ──────────────────────────────────────

# sync a running interface without tearing it down.
# if the interface doesn't exist yet, brings it up fresh.
# uses a temp file to avoid piping through bash -c.
wg_sync() {
  local iface="$1"
  local conf="$2"

  _wg_require_cmd
  [[ -f "${conf}" ]] || fatal "wg_sync: config not found: ${conf}"

  if is_valid_iface "${iface}"; then
    local stripped
    stripped=$(mktemp) || fatal "wg_sync: mktemp failed"

    wg-quick strip "${conf}" > "${stripped}" \
      || { rm -f "${stripped}"; fatal "wg_sync: wg-quick strip failed"; }

    if ! wg syncconf "${iface}" "${stripped}"; then
      rm -f "${stripped}"
      fatal "wg_sync: wg syncconf failed"
    fi

    rm -f "${stripped}"
  else
    must "bring up wireguard interface ${iface}" \
      wg-quick up "${conf}"
  fi
}

wg_up() {
  local conf="$1"
  _wg_require_cmd
  [[ -f "${conf}" ]] || fatal "wg_up: config not found: ${conf}"
  must "bring up wireguard interface" wg-quick up "${conf}"
}

wg_down() {
  local iface="$1"
  _wg_require_cmd
  must "bring down wireguard interface ${iface}" wg-quick down "${iface}"
}

# ── inspection helpers ─────────────────────────────────────

wg_show() {
  local iface="${1:-}"
  _wg_require_cmd
  if [[ -n "${iface}" ]]; then
    drun "show wireguard status for ${iface}" wg show "${iface}"
  else
    drun "show all wireguard interfaces" wg show
  fi
}

# returns raw tab-separated: pubkey  timestamp
wg_last_handshake() {
  local iface="$1"
  _wg_require_cmd
  wg show "${iface}" latest-handshakes
}

# returns seconds since last handshake for a specific peer.
# returns 1 if peer has never handshaked.
# usage: age=$(wg_handshake_age wg0 "$pub") && (( age < 120 ))
wg_handshake_age() {
  local iface="$1"
  local pub="$2"
  _wg_require_cmd

  local now ts
  printf -v now '%(%s)T' -1

  ts=$(wg show "${iface}" latest-handshakes \
    | awk -v k="${pub}" '$1 == k { print $2 }')

  [[ -z "${ts}" || "${ts}" == "0" ]] && return 1

  printf '%s\n' "$(( now - ts ))"
}

# ── diagnostics ────────────────────────────────────────────
# pure return codes — no UI, no printing

check_interface() {
  local iface="$1"
  ip link show "${iface}" &>/dev/null
}

check_wireguard_running() {
  local iface="$1"
  wg show "${iface}" &>/dev/null
}

check_peer_configured() {
  local iface="$1"
  wg show "${iface}" peers 2>/dev/null | grep -q .
}

check_handshake() {
  local iface="$1"
  wg show "${iface}" latest-handshakes 2>/dev/null \
    | awk '{print $2}' \
    | grep -q '[1-9]'
}

check_recent_handshake() {
  local iface="$1"
  local max_age="${2:-60}"

  local now ts peer
  printf -v now '%(%s)T' -1

  while read -r peer ts < <(wg show "${iface}" latest-handshakes 2>/dev/null); do
    [[ "${ts}" -eq 0 ]] && continue
    (( now - ts <= max_age )) && return 0
  done

  return 1
}

wait_for_handshake() {
  local iface="$1"
  local timeout="${2:-20}"

  local i
  for (( i = 0; i < timeout; i++ )); do
    check_handshake "${iface}" && return 0
    sleep 1
  done

  return 1
}