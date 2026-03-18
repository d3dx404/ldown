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
roster_load "${roster_conf}" >/dev/null 2>&1

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
  local skip_name="\${1:-}"
  local i
  for i in "\${!PEER_NAMES[@]}"; do
    local pname="\${PEER_NAMES[\$i]}"
    [[ "\${pname}" == "\${skip_name}" ]] && continue
    local ptunnel="\${PEER_TUNNEL_IPS[\$i]}"
    local pip="\${PEER_IPS[\$i]}"
    local pport="\${PEER_PORTS[\$i]:-\${WG_PORT}}"
    local pkeepalive="\${PEER_KEEPALIVES[\$i]:-}"
    local pubfile="\${KEY_DIR}/\${pname}.public.key"
    [[ -f "\${pubfile}" ]] || continue
    local ppubkey
    { read -r ppubkey < "\${pubfile}"; } 2>/dev/null || continue
    [[ -n "\${ppubkey}" ]] || continue
    local pnode_pub_b64=""
    local pnode_pub_file="\${KEY_DIR}/\${pname}-node.pub"
    if [[ -f "\${pnode_pub_file}" ]]; then
      pnode_pub_b64="\$(openssl pkey \
        -in "\${pnode_pub_file}" \
        -pubin -outform DER 2>/dev/null | base64 -w0)"
    fi
    printf '%s %s %s:%s %s %s %s\n' \
      "\${pname}" "\${ptunnel}" "\${pip}" "\${pport}" \
      "\${ppubkey}" "\${pkeepalive:-0}" "\${pnode_pub_b64}"
  done
}

_do_join() {
  local name="\$1" tunnel_ip="\$2" public_ip="\$3" pubkey="\$4" node_pub="\$5" csr_b64="\${6:-}" ticket="\${7:-}"
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

  # verify admission ticket
  local ticket_dir="/etc/ldown/tickets"
  local ticket_file="\${ticket_dir}/\${name}"
  if [[ -f "\${ticket_file}" ]]; then
    local expected_ticket
    { read -r expected_ticket < "\${ticket_file}"; } 2>/dev/null
    if [[ "\${ticket}" != "\${expected_ticket}" ]]; then
      _llog "WARN" "[SECURITY] JOIN rejected \u2014 invalid ticket for \${name}"
      printf 'ERROR invalid ticket\n'
      return 1
    fi
    rm -f "\${ticket_file}"
    _llog "INFO" "ticket consumed for \${name}"
  elif [[ -d "\${ticket_dir}" ]] && ls "\${ticket_dir}"/* &>/dev/null 2>&1; then
    _llog "WARN" "[SECURITY] JOIN rejected \u2014 \${name} has no ticket (tickets required)"
    printf 'ERROR ticket required\n'
    return 1
  fi

  printf '%s\n' "\${pubkey}" > "\${KEY_DIR}/\${name}.public.key"
  _llog "INFO" "stored pubkey for \${name}"

  if [[ -n "\${node_pub}" ]]; then
    printf '%s' "\${node_pub}" | base64 -d | \
      openssl pkey -pubin -inform DER -outform PEM \
      -out "\${KEY_DIR}/\${name}-node.pub" 2>/dev/null
    chmod 644 "\${KEY_DIR}/\${name}-node.pub"
    _llog "INFO" "stored node signing pubkey for \${name}"
  fi
  # clear left status on rejoin
  if [[ -f /run/ldown/left_peers ]]; then
    sed -i "/^\${name}\$/d" /run/ldown/left_peers 2>/dev/null || true
  fi

  # czar adds the joining node to its own WireGuard interface
  # every other node gets a PEER_ADD message — czar processes the JOIN directly
  # so it must do the wg set itself or the joining node is never in czar's peers
  psk_arg=""
  [[ -f "\${KEY_DIR}/mesh.psk" ]] && psk_arg="preshared-key \${KEY_DIR}/mesh.psk"
  ip link show "\${WG_INTERFACE}" &>/dev/null && \
    wg set "\${WG_INTERFACE}" peer "\${pubkey}" \
      allowed-ips "\${tunnel_ip}/32" \
      endpoint "\${public_ip}:\${WG_PORT}" \${psk_arg} 2>/dev/null && \
    _llog "INFO" "czar added \${name} to WireGuard" || \
    _llog "WARN" "czar wg set failed for \${name}"
  wg_write_peer "\${PEER_DIR}/peer-\${tunnel_ip}.conf" \
    "\${pubkey}" "\${tunnel_ip}/32" "\${public_ip}:\${WG_PORT}" ""
  ping -c1 -W1 "\${tunnel_ip}" &>/dev/null || true

  # sign node CSR with CA if available
  if [[ -n "\${csr_b64}" && -f "\${KEY_DIR}/ca.key" && -f "\${KEY_DIR}/ca.cert" ]]; then
    local _csr_tmp="\$(mktemp)"
    local _cert_tmp="\$(mktemp)"
    printf '%s' "\${csr_b64}" | base64 -d > "\${_csr_tmp}" 2>/dev/null
    if openssl x509 -req \
      -in "\${_csr_tmp}" \
      -CA "\${KEY_DIR}/ca.cert" \
      -CAkey "\${KEY_DIR}/ca.key" \
      -CAcreateserial \
      -out "\${_cert_tmp}" \
      -days 7 2>/dev/null; then
      local _signed_b64
      _signed_b64="\$(base64 -w0 < "\${_cert_tmp}")"
      printf 'CERT:%s\n' "\${_signed_b64}"
      local _ca_b64
      _ca_b64="\$(base64 -w0 < "\${KEY_DIR}/ca.cert")"
      printf 'CA:%s\n' "\${_ca_b64}"
      # also store a copy for czar's records
      cp "\${_cert_tmp}" "\${KEY_DIR}/\${name}-tls.cert" 2>/dev/null
      _llog "INFO" "signed TLS cert for \${name} (7-day)"
    else
      _llog "WARN" "failed to sign CSR for \${name}"
    fi
    rm -f "\${_csr_tmp}" "\${_cert_tmp}"
  fi

  local czar_pub
  { read -r czar_pub < "\${KEY_DIR}/\${MY_NAME}.public.key"; } 2>/dev/null
  if [[ -n "\${czar_pub}" && -n "\${MY_NAME}" && -n "\${MY_TUNNEL_IP}" && -n "\${MY_IP}" ]]; then
    local czar_node_pub_b64=""
    if [[ -f "\${KEY_DIR}/\${MY_NAME}-node.pub" ]]; then
      czar_node_pub_b64="\$(openssl pkey \
        -in "\${KEY_DIR}/\${MY_NAME}-node.pub" \
        -pubin -outform DER 2>/dev/null | base64 -w0)"
    fi
    printf '%s %s %s:%s %s %s %s\n' "\${MY_NAME}" "\${MY_TUNNEL_IP}" \
      "\${MY_IP}" "\${WG_PORT}" "\${czar_pub}" "0" "\${czar_node_pub_b64}"
  fi
  _peer_list "\${MY_NAME}"
  _llog "INFO" "JOIN complete \${name}"
  # track for bootstrap progress
  if [[ -f /run/ldown/bootstrap_joined ]]; then
    printf '%s\n' "\${name}" >> /run/ldown/bootstrap_joined
  fi

  # notify all existing peers about the new node
  # skip self, skip the joining node (they already have the list)
  local i
  for i in "\${!PEER_NAMES[@]}"; do
    local pname="\${PEER_NAMES[\$i]}"
    [[ "\${pname}" == "\${skip_name}" ]] && continue
    local pip="\${PEER_IPS[\$i]}"
    local pkeepalive="\${PEER_KEEPALIVES[\$i]:-}"
    [[ "\${pname}" == "\${MY_NAME}" ]] && continue
    [[ "\${pname}" == "\${name}" ]] && continue
    local ppub
    { read -r ppub < "\${KEY_DIR}/\${pname}.public.key"; } 2>/dev/null
    [[ -z "\${ppub}" ]] && continue
    local node_pub_b64=""
    if [[ -f "\${KEY_DIR}/\${name}-node.pub" ]]; then
      node_pub_b64="\$(openssl pkey \
        -in "\${KEY_DIR}/\${name}-node.pub" \
        -pubin -outform DER 2>/dev/null | base64 -w0)"
    fi
    local raw_payload="PEER_ADD \${name} \${tunnel_ip} \${public_ip}:\${WG_PORT} \${pubkey} \${pkeepalive:-0} \${node_pub_b64}"
    local payload="\$(make_payload "\${raw_payload}")"
    local notify="\$(sign_msg "\${payload}") \${payload}"
    # send with one retry
    if ! printf '%s\n' "\${notify}" | ncat --ssl --wait 2 "\${pip}" "\${LDOWN_PORT}" >/dev/null 2>&1; then
      sleep 2
      printf '%s\n' "\${notify}" | ncat --ssl --wait 2 "\${pip}" "\${LDOWN_PORT}" >/dev/null 2>&1 || \
        _llog "WARN" "PEER_ADD failed for \${pname} (\${pip}) after retry"
    else
      _llog "DEBUG" "PEER_ADD sent to \${pname}"
    fi
  done
}

_do_leave() {
  local name="\$1" tunnel_ip="\$2" pubkey="\$3"
  local skip_name="\${name}"
  _llog "INFO" "LEAVE \${name} (\${tunnel_ip})"
  local pubfile="\${KEY_DIR}/\${name}.public.key"
  if [[ -f "\${pubfile}" ]]; then
    local stored; { read -r stored < "\${pubfile}"; } 2>/dev/null
    [[ "\${stored}" == "\${pubkey}" ]] || {
      _llog "WARN" "pubkey mismatch for \${name}"
      printf 'ERROR pubkey mismatch\n'; return 1; }
  fi
  if ip link show "\${WG_INTERFACE}" &>/dev/null 2>&1; then
    wg set "\${WG_INTERFACE}" peer "\${pubkey}" remove 2>/dev/null
  fi
  rm -f "\${PEER_DIR}/peer-\${tunnel_ip}.conf"
  mkdir -p /run/ldown 2>/dev/null || true
  printf '%s\n' "\${name}" >> /run/ldown/left_peers
  printf 'OK\n'
  _llog "INFO" "LEAVE complete \${name}"

  # notify all peers to remove this node
  local i
  for i in "\${!PEER_NAMES[@]}"; do
    local pname="\${PEER_NAMES[\$i]}"
    [[ "\${pname}" == "\${skip_name}" ]] && continue
    local pip="\${PEER_IPS[\$i]}"
    [[ "\${pname}" == "\${MY_NAME}" ]] && continue
    [[ "\${pname}" == "\${name}" ]] && continue
    local rm_raw="PEER_REMOVE \${name} \${tunnel_ip} \${pubkey}"
    local rm_payload="\$(make_payload "\${rm_raw}")"
    local remove_msg="\$(sign_msg "\${rm_payload}") \${rm_payload}"
    printf '%s\n' "\${remove_msg}" | ncat --ssl --wait 2 "\${pip}" "\${LDOWN_PORT}" >/dev/null 2>&1 || \
      _llog "WARN" "PEER_REMOVE failed for \${pname}"
  done
}

line=""
read -r -t 5 line || exit 0
line="\${line%%\$'\r'}"
[[ -z "\${line}" ]] && exit 0

# ---------------------------------------------------------------------------
# canonical message envelope — V1|timestamp|nonce|payload
# ---------------------------------------------------------------------------
make_payload() {
  local raw="\$1"
  local ts
  ts="\$(date +%s)"
  local nonce
  nonce="\$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf '%s|%s|%s|%s' "V1" "\${ts}" "\${nonce}" "\${raw}"
}

parse_payload() {
  local envelope="\$1"
  local version ts nonce raw
  version="\${envelope%%|*}"
  local rest="\${envelope#*|}"
  ts="\${rest%%|*}"
  rest="\${rest#*|}"
  nonce="\${rest%%|*}"
  raw="\${rest#*|}"
  if [[ "\${version}" != "V1" ]]; then
    _llog "WARN" "bad proto version: \${version}"
    return 1
  fi
  local now
  now="\$(date +%s)"
  local age=\$(( now - ts ))
  if (( age < 0 )); then age=\$(( -age )); fi
  if (( age > 60 )); then
    _llog "WARN" "stale message: \${age}s old"
    return 1
  fi
  mkdir -p /run/ldown/nonces 2>/dev/null || true
  if [[ -f "/run/ldown/nonces/\${nonce}" ]]; then
    _llog "WARN" "replay detected: nonce \${nonce}"
    return 1
  fi
  printf '%s' "\${ts}" > "/run/ldown/nonces/\${nonce}" 2>/dev/null || true
  find /run/ldown/nonces -type f -mmin +2 -delete 2>/dev/null || true
  printf '%s' "\${raw}"
}

# ---------------------------------------------------------------------------
# message signing — sign_msg / verify_msg
# sign_msg <payload>  → Ed25519 signature using czar control key
# the signature is bound to this exact message and cannot be forged
# without possession of the czar private key
# ---------------------------------------------------------------------------
sign_msg() {
  local payload="\$1"
  local privkey="\${KEY_DIR}/czar-control.key"
  if [[ ! -f "\${privkey}" ]]; then
    _llog "ERROR" "czar signing key not found: \${privkey}"
    return 1
  fi
  local tmpf="\$(mktemp)"
  printf '%s' "\${payload}" > "\${tmpf}"
  openssl pkeyutl -sign -inkey "\${privkey}" \
    -in "\${tmpf}" | base64 -w0
  rm -f "\${tmpf}"
}

verify_msg() {
  local received_sig="\$1"
  local payload="\$2"
  local sender_name="\$3"
  local sender_pub="\${KEY_DIR}/\${sender_name}-node.pub"
  local czar_pub="\${KEY_DIR}/czar-control.pub"
  local pubkey_to_use=""
  
  # czar-sourced messages always verify with czar-control.pub
  if [[ "\${sender_name}" == "czar" ]]; then
    pubkey_to_use="\${czar_pub}"
  # try sender's node public key
  elif [[ -n "\${sender_name}" && -f "\${sender_pub}" ]]; then
    pubkey_to_use="\${sender_pub}"
  # fall back to czar key for czar-signed messages
  elif [[ -f "\${czar_pub}" ]]; then
    pubkey_to_use="\${czar_pub}"
  else
    _llog "WARN" "no public key available for verification (sender_name=\${sender_name})"
    return 1
  fi
  
  local tmpdir_sig
  tmpdir_sig="\$(mktemp)"
  printf '%s' "\${received_sig}" | base64 -d > "\${tmpdir_sig}" 2>/dev/null
  _verify_tmppay="\$(mktemp)"
  printf '%s' "\${payload}" > "\${_verify_tmppay}"
  openssl pkeyutl -verify -pubin -inkey "\${pubkey_to_use}" \
    -sigfile "\${tmpdir_sig}" -in "\${_verify_tmppay}" >/dev/null 2>&1
  local result=\$?
  rm -f "\${tmpdir_sig}" "\${_verify_tmppay}"
  return \${result}
}

# wire format: <sig> <ACTION> <args...>
# sig is field 0, action is field 1, args start at field 2
# PUBKEY and PING are exempt — they run before any token is available (bootstrap)

# early-exit for bare PUBKEY without signature
if [[ "\${line}" == "PUBKEY" ]]; then
  if [[ -f "\${KEY_DIR}/\${MY_NAME}.public.key" ]]; then
    cat "\${KEY_DIR}/\${MY_NAME}.public.key"
  else
    printf 'ERROR pubkey not found\n'
  fi
  exit 0
fi

# early-exit for bare PING without signature
if [[ "\${line}" == "PING" ]]; then
  printf 'PONG\n'
  exit 0
fi

read -ra p <<< "\${line}"
sig="\${p[0]:-}"
envelope="\${line#* }"   # everything after the sig — the signed envelope

# extract action from envelope: V1|ts|nonce|ACTION field1...
_env_token="\${p[1]:-}"
if [[ "\${_env_token}" == *"|"* ]]; then
  action="\${_env_token##*|}"
else
  action="\${_env_token}"
fi

_llog "DEBUG" "recv action=\${action} sig=\${sig:0:16}..."

if [[ "\${action}" == "JOIN" ]]; then
  # self-authenticating: verify sig against the pubkey embedded in the message
  _join_npub="\${p[6]:-}"
  if [[ -z "\${_join_npub}" ]]; then
    _llog "WARN" "JOIN from \${p[2]:-unknown} missing node_pub_b64 — dropping"
    exit 1
  fi
  _join_tmpkey="\$(mktemp)"
  _join_tmpsig="\$(mktemp)"
  if ! printf '%s' "\${_join_npub}" | base64 -d | \
    openssl pkey -pubin -inform DER -outform PEM \
    -out "\${_join_tmpkey}" 2>/dev/null; then
    _llog "WARN" "JOIN from \${p[2]:-unknown} invalid node pubkey — dropping"
    rm -f "\${_join_tmpkey}" "\${_join_tmpsig}"
    exit 1
  fi
  printf '%s' "\${sig}" | base64 -d > "\${_join_tmpsig}" 2>/dev/null
  _join_tmppay="\$(mktemp)"
  printf '%s' "\${envelope}" > "\${_join_tmppay}"
  openssl pkeyutl -verify -pubin -inkey "\${_join_tmpkey}" \
    -sigfile "\${_join_tmpsig}" -in "\${_join_tmppay}" >/dev/null 2>&1 || {
    _llog "WARN" "JOIN sig verify failed for \${p[2]:-unknown} — dropping"
    rm -f "\${_join_tmpkey}" "\${_join_tmpsig}" "\${_join_tmppay}"
    exit 1
  }
  rm -f "\${_join_tmpkey}" "\${_join_tmpsig}" "\${_join_tmppay}"
elif [[ "\${action}" == "LEAVE" ]]; then
  # verify against stored node pubkey
  _leave_name="\${p[2]:-}"
  _leave_pub="\${KEY_DIR}/\${_leave_name}-node.pub"
  if [[ ! -f "\${_leave_pub}" ]]; then
    _llog "WARN" "LEAVE from \${_leave_name} — no stored pubkey, dropping"
    exit 1
  fi
  _leave_tmpsig="\$(mktemp)"
  printf '%s' "\${sig}" | base64 -d > "\${_leave_tmpsig}" 2>/dev/null
  _leave_tmppay="\$(mktemp)"
  printf '%s' "\${envelope}" > "\${_leave_tmppay}"
  openssl pkeyutl -verify -pubin -inkey "\${_leave_pub}" \
    -sigfile "\${_leave_tmpsig}" -in "\${_leave_tmppay}" >/dev/null 2>&1 || {
    _llog "WARN" "LEAVE sig verify failed for \${_leave_name} — dropping"
    rm -f "\${_leave_tmpsig}" "\${_leave_tmppay}"
    exit 1
  }
  rm -f "\${_leave_tmpsig}" "\${_leave_tmppay}"
elif [[ "\${action}" != "PUBKEY" && "\${action}" != "PING" ]]; then
  if [[ "\${action}" == "PEER_ADD" || \
        "\${action}" == "PEER_REMOVE" || \
        "\${action}" == "RECONNECT" || \
        "\${action}" == "REVIVE" ]]; then
    sender_name="czar"
  else
    sender_name="\${p[2]:-}"
  fi
  verify_msg "\${sig}" "\${envelope}" "\${sender_name}" || {
    _llog "WARN" "sig verify failed for \${action} from \${sender_name} — dropping"
    exit 1
  }
fi

# unwrap envelope — validate timestamp, nonce, version
if [[ "\${action}" != "PUBKEY" && "\${action}" != "PING" ]]; then
  raw_payload="\$(parse_payload "\${envelope}")" || {
    _llog "WARN" "envelope rejected for \${action} — dropping"
    exit 1
  }
  # re-split raw payload so field indices match: p[1]=ACTION p[2]=field1 etc
  read -ra p <<< "NOSIG \${raw_payload}"
  action="\${p[1]:-}"
fi

# source-IP check for czar-only messages
CZAR_ONLY_ACTIONS="PEER_ADD PEER_REMOVE RECONNECT REVIVE"
if [[ "\${CZAR_ONLY_ACTIONS}" == *"\${action}"* ]]; then
  if [[ "\${NCAT_REMOTE_ADDR}" != "\${CZAR_IP}" ]]; then
    _llog "WARN" "[SECURITY] \${action} rejected — sender \${NCAT_REMOTE_ADDR} is not czar \${CZAR_IP}"
    printf 'ERROR unauthorized\n'
    exit 1
  fi
fi

case "\${action}" in
  PUBKEY)
    pubfile="\${KEY_DIR}/\${MY_NAME}.public.key"
    if [[ -f "\${pubfile}" ]]; then
      cat "\${pubfile}"
    else
      printf 'ERROR pubkey not found\n'
    fi
    ;;
  JOIN)
    [[ "\${MY_IS_CZAR}" == "true" ]] || { printf 'ERROR not czar\n'; exit 1; }
    # payload: JOIN name tunnel_ip public_ip pubkey node_signing_pubkey csr_b64 ticket
    # p[0]=sig p[1]=JOIN p[2]=name p[3]=tunnel_ip p[4]=public_ip p[5]=pubkey p[6]=node_signing_pubkey p[7]=csr_b64 p[8]=ticket
    _ticket="\${p[8]:-}"
    [[ "\${_ticket}" == "NONE" ]] && _ticket=""
    _do_join "\${p[2]:-}" "\${p[3]:-}" "\${p[4]:-}" "\${p[5]:-}" "\${p[6]:-}" "\${p[7]:-}" "\${_ticket}"
    ;;
  LEAVE)
    [[ "\${MY_IS_CZAR}" == "true" ]] || { printf 'ERROR not czar\n'; exit 1; }
    # p[0]=sig p[1]=LEAVE p[2]=name p[3]=tunnel_ip p[4]=pubkey
    _do_leave "\${p[2]:-}" "\${p[3]:-}" "\${p[4]:-}"
    ;;
  PEER_ADD)
    # p[0]=sig p[1]=PEER_ADD p[2]=name p[3]=tunnel p[4]=endpoint p[5]=pubkey p[6]=keepalive p[7]=node_pub_b64
    pname="\${p[2]:-}" ptunnel="\${p[3]:-}" pendpoint="\${p[4]:-}"
    ppubkey="\${p[5]:-}"
    pkeepalive="\${p[6]:-}"
    pnode_pub="\${p[7]:-}"
    
    # roster-pin: reject if name+tunnel not in roster
    _roster_match=false
    _ri=""
    for _ri in "\${!PEER_NAMES[@]}"; do
      if [[ "\${PEER_NAMES[\$_ri]}" == "\${pname}" && "\${PEER_TUNNEL_IPS[\$_ri]}" == "\${ptunnel}" ]]; then
        _roster_match=true
        break
      fi
    done
    if [[ "\${_roster_match}" != "true" ]]; then
      _llog "WARN" "[SECURITY] PEER_ADD rejected — \${pname} (\${ptunnel}) not in roster"
      printf 'ERROR not in roster\n'
      exit 1
    fi

    # treat 0 keepalive as empty
    [[  "\${pkeepalive}" == "0" ]] && pkeepalive=""
    
    is_valid_wg_key "\${ppubkey}" || { printf 'ERROR invalid pubkey\n'; exit 1; }
    wg_args=(wg set "\${WG_INTERFACE}" peer "\${ppubkey}" allowed-ips "\${ptunnel}/32" endpoint "\${pendpoint}")
    [[ -n "\${pkeepalive}" ]] && wg_args+=(persistent-keepalive "\${pkeepalive}")
    [[ -f "\${KEY_DIR}/mesh.psk" ]] && wg_args+=(preshared-key "\${KEY_DIR}/mesh.psk")
    "\${wg_args[@]}" 2>/dev/null && printf 'OK\n' || printf 'ERROR wg set failed\n'
    wg_write_peer "\${PEER_DIR}/peer-\${ptunnel}.conf" "\${ppubkey}" "\${ptunnel}/32" "\${pendpoint}" "\${pkeepalive}"
    
    if [[ -n "\${pnode_pub}" ]]; then
      printf '%s' "\${pnode_pub}" | base64 -d | \
        openssl pkey -pubin -inform DER -outform PEM \
        -out "\${KEY_DIR}/\${pname}-node.pub" 2>/dev/null
      chmod 644 "\${KEY_DIR}/\${pname}-node.pub"
      _llog "INFO" "stored node signing pubkey for \${pname} via PEER_ADD"
    fi
    _llog "INFO" "PEER_ADD \${pname} (\${ptunnel}) persisted"
    ;;
  PEER_REMOVE)
    # p[0]=sig p[1]=PEER_REMOVE p[2]=name p[3]=tunnel_ip p[4]=pubkey
    ppubkey="\${p[4]:-}"
    # roster-pin: reject if name+tunnel not in roster
    _rr_name="\${p[2]:-}" _rr_tunnel="\${p[3]:-}"
    _roster_match=false
    for _ri in "\${!PEER_NAMES[@]}"; do
      if [[ "\${PEER_NAMES[\$_ri]}" == "\${_rr_name}" && "\${PEER_TUNNEL_IPS[\$_ri]}" == "\${_rr_tunnel}" ]]; then
        _roster_match=true
        break
      fi
    done
    if [[ "\${_roster_match}" != "true" ]]; then
      _llog "WARN" "[SECURITY] PEER_REMOVE rejected — \${_rr_name} (\${_rr_tunnel}) not in roster"
      printf 'ERROR not in roster\n'
      exit 1
    fi
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

  if [[ ! -f "${MESH_CONF}" ]]; then
    warn "mesh.conf not found — listener cannot load node identity"
    warn "missing: /etc/ldown/mesh.conf"
    warn "missing: MY_NAME, MY_IP, MY_TUNNEL_IP will be empty"
    warn "listener starting in degraded mode — PUBKEY requests will fail"
    _listener_log "WARN" "starting without mesh.conf — node identity unavailable"
  else
    source_if_exists "${MESH_CONF}"
    roster_load "${ROSTER_CONF}" || true
  fi

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

  if fuser "${LDOWN_PORT}"/tcp &>/dev/null 2>&1; then
    local port_pid
    port_pid=$(fuser "${LDOWN_PORT}"/tcp 2>/dev/null | tr -d ' ')
    local our_pid=""
    [[ -f "${pidfile}" ]] && read -r our_pid < "${pidfile}"
    if [[ "${port_pid}" == "${our_pid}" ]]; then
      # our listener is running fine — do nothing
      return 0
    else
      # something else has the port — kill it
      fuser -k "${LDOWN_PORT}"/tcp 2>/dev/null || true
      sleep 0.5
    fi
  fi

  _listener_log "INFO" "starting on ${MY_IP}:${LDOWN_PORT} (czar=${MY_IS_CZAR})"

  (
    trap 'rm -f "${handler}"' EXIT
    while true; do
      ncat -l --keep-open "${MY_IP}" "${LDOWN_PORT}" \
        --ssl --ssl-cert "${TLS_CERT}" --ssl-key "${TLS_KEY}" \
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