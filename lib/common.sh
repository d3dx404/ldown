#!/usr/bin/env bash
# lib/common.sh — logging, output, validation, and execution helpers
#
# verbosity levels:
#   0 = silent  — errors and fatals only
#   1 = normal  — info, warn, error, step        (default)
#   2 = verbose — + debug messages
#   3 = trace   — + set -x scoped inside drun/must only

# ── guard against double-sourcing ─────────────────────────
[[ -n "${_LDOWN_COMMON_LOADED:-}" ]] && return 0
_LDOWN_COMMON_LOADED=1

# ── internal state ─────────────────────────────────────────
_VERBOSITY=1
_LOGFILE=""
_LOG_MAX_BYTES=$(( 5 * 1024 * 1024 ))  # 5 MB before rotation
_STEP_START=0                           # timestamp for step timing
_IS_TTY=0                               # set in _init_colors
_CMD_SEQ=0                              # monotonic command ID for log tracing

# ── color setup ────────────────────────────────────────────
# trans flag truecolor palette — #55CDFC / #F7A8B8 / #FFFFFF
# only emits escape codes when stdout is a real terminal
_init_colors() {
  if [[ -t 1 ]]; then
    _IS_TTY=1
    # trans flag (truecolor)
    T_BLUE='\033[38;2;85;205;252m'     # #55CDFC
    T_PINK='\033[38;2;247;168;184m'    # #F7A8B8
    T_WHITE='\033[38;2;255;255;255m'   # #FFFFFF
    T_BLUE_BG='\033[48;2;85;205;252m'
    T_PINK_BG='\033[48;2;247;168;184m'
    # UI roles
    C_INFO="${T_BLUE}"
    C_SUCCESS="${T_PINK}"
    C_WARN='\033[0;33m'  # yellow
    C_ERR='\033[0;31m'
    C_FATAL='\033[1;31m'
    C_STEP="${T_BLUE}"
    C_DEBUG='\033[0;90m'
    C_STATUS_OK="${T_BLUE}"
    C_STATUS_FAIL='\033[0;31m'
    C_STATUS_WARN="${T_PINK}"
    C_DIVIDER="${T_PINK}"
    # referenced directly in drun / confirm / prompt
    C_YELLOW='\033[0;33m'
    C_CYAN='\033[0;36m'
    # general
    C_WHITE="${T_WHITE}"
    C_GRAY='\033[0;90m'
    C_DIM='\033[2m'
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
  else
    _IS_TTY=0
    T_BLUE='' T_PINK='' T_WHITE=''
    T_BLUE_BG='' T_PINK_BG=''
    C_INFO='' C_SUCCESS='' C_WARN='' C_ERR='' C_FATAL=''
    C_STEP='' C_DEBUG='' C_STATUS_OK='' C_STATUS_FAIL=''
    C_STATUS_WARN='' C_DIVIDER=''
    C_YELLOW='' C_CYAN=''
    C_WHITE='' C_GRAY='' C_DIM='' C_RESET='' C_BOLD=''
  fi
}
_init_colors

# ── failure trap — stack trace on unexpected exit ──────────
# installed by log_init. fires on any unhandled non-zero exit.
# prints the full function call chain with file and line numbers.
_trap_err() {
  local rc=$?
  local i=0
  local frame line func file

  printf '%b\n' "${C_ERR}[TRAP] command failed (exit ${rc})${C_RESET}" >&2

  while frame=$(caller "$i" 2>/dev/null); do
    set -- $frame
    line=$1
    func=${2:-main}
    file=${3:-unknown}
    printf '  [%d] %s:%s in %s()\n' "$i" "$file" "$line" "$func" >&2
    (( i++ ))
  done

  return 0
}

# ── log init ───────────────────────────────────────────────
# call once from main before any output functions.
# does NOT call set -x globally — trace is scoped inside drun/must only.
log_init() {
  set -o errtrace
  set -o pipefail
  trap '_trap_err' ERR
  local logfile="${1:-}"
  local verbosity="${2:-1}"

  _VERBOSITY="${verbosity}"

  if [[ -n "${logfile}" ]]; then
    local logdir
    logdir="$(dirname "${logfile}")"
    mkdir -p "${logdir}" 2>/dev/null || true

    if touch "${logfile}" 2>/dev/null; then
      _LOGFILE="${logfile}"
      _log_rotate
    else
      printf 'warning: cannot write to log file %q — stderr only\n' "${logfile}" >&2
      _LOGFILE=""
    fi
  fi
}

# ── log rotation ───────────────────────────────────────────
_log_rotate() {
  [[ -z "${_LOGFILE}" ]] && return
  [[ ! -f "${_LOGFILE}" ]] && return

  # wc -c is POSIX-portable; GNU stat -c%s is not
  local size
  size="$(wc -c < "${_LOGFILE}" 2>/dev/null || printf '0')"
  if (( size >= _LOG_MAX_BYTES )); then
    mv "${_LOGFILE}" "${_LOGFILE}.1" 2>/dev/null || true
    touch "${_LOGFILE}" 2>/dev/null || true
    _log_write "INFO" "log rotated — previous: ${_LOGFILE}.1"
  fi
}

# ── internal log writer ────────────────────────────────────
# structured key=value format.
# uses printf %(...)T to avoid spawning a date subprocess on every call.
_log_write() {
  [[ -z "${_LOGFILE}" ]] && return
  local level="$1"
  local msg="$2"
  local cmd_id="${3:-}"
  if [[ -n "${cmd_id}" ]]; then
    printf '%(%Y-%m-%d %H:%M:%S)T level=%-5s cmd_id=%s msg=%s\n' \
      -1 "${level}" "${cmd_id}" "${msg}" >> "${_LOGFILE}" 2>/dev/null || true
  else
    printf '%(%Y-%m-%d %H:%M:%S)T level=%-5s msg=%s\n' \
      -1 "${level}" "${msg}" >> "${_LOGFILE}" 2>/dev/null || true
  fi
}

# ── output functions ───────────────────────────────────────
# all use printf "%b\n" — portable, no echo -e

info() {
  local msg="$*"
  _log_write "INFO" "${msg}"
  [[ "${_VERBOSITY}" -ge 1 ]] || return 0
  printf '%b\n' "${C_INFO}[*]${C_RESET} ${msg}"
}

success() {
  local msg="$*"
  _log_write "OK" "${msg}"
  [[ "${_VERBOSITY}" -ge 1 ]] || return 0
  printf '%b\n' "${C_SUCCESS}[+]${C_RESET} ${C_SUCCESS}${msg}${C_RESET}"
}

warn() {
  local msg="$*"
  _log_write "WARN" "${msg}"
  [[ "${_VERBOSITY}" -ge 1 ]] || return 0
  printf '%b\n' "${C_WARN}[!]${C_RESET} ${C_WARN}${msg}${C_RESET}"
}

# err always goes to stderr regardless of verbosity
err() {
  local msg="$*"
  _log_write "ERROR" "${msg}"
  printf '%b\n' "${C_ERR}[ERROR]${C_RESET} ${C_ERR}${msg}${C_RESET}" >&2
}

# fatal — prints stack trace, logs, and exits immediately
fatal() {
  local msg="$*"
  _log_write "FATAL" "${msg}"
  printf '%b\n' "${C_FATAL}${C_BOLD}[FATAL]${C_RESET} ${C_FATAL}${msg}${C_RESET}" >&2

  local i=0
  local frame line func file
  while frame=$(caller "$i" 2>/dev/null); do
    set -- $frame
    line=$1
    func=${2:-main}
    file=${3:-unknown}
    printf '%b\n' "${C_GRAY}        at ${func}() ${file}:${line}${C_RESET}" >&2
    (( i++ ))
  done

  [[ -n "${_LOGFILE}" ]] && \
    printf '%b\n' "${C_GRAY}        see: ${_LOGFILE}${C_RESET}" >&2

  exit 1
}

debug() {
  local msg="$*"
  _log_write "DEBUG" "${msg}"
  [[ "${_VERBOSITY}" -ge 2 ]] || return 0
  printf '%b\n' "${C_DEBUG}[~] ${msg}${C_RESET}"
}

# step — major phase header, prints elapsed time from previous step
step() {
  local msg="$*"
  _log_write "STEP" "${msg}"
  [[ "${_VERBOSITY}" -ge 1 ]] || return 0

  if (( _STEP_START > 0 )); then
    local now elapsed
    printf -v now '%(%s)T' -1
    elapsed=$(( now - _STEP_START ))
    printf '%b\n' "${C_DIM}    done in ${elapsed}s${C_RESET}"
  fi

  printf -v _STEP_START '%(%s)T' -1
  printf '\n%b\n' "${C_STEP}${C_BOLD}── ${msg}${C_RESET}"
}

# ── status line helpers ────────────────────────────────────
# always printed regardless of verbosity

status_ok() {
  local label="$1"
  local value="${2:-}"
  printf "  ${C_STATUS_OK}✓${C_RESET} %-30s ${C_GRAY}%s${C_RESET}\n" "${label}" "${value}"
}

status_fail() {
  local label="$1"
  local value="${2:-}"
  printf "  ${C_STATUS_FAIL}✗${C_RESET} %-30s ${C_STATUS_FAIL}%s${C_RESET}\n" "${label}" "${value}"
}

status_warn() {
  local label="$1"
  local value="${2:-}"
  printf "  ${C_STATUS_WARN}~${C_RESET} %-30s ${C_STATUS_WARN}%s${C_RESET}\n" "${label}" "${value}"
}

divider() {
  printf '%b\n' "${C_DIVIDER}────────────────────────────────────────────${C_RESET}"
}

# ── banner ─────────────────────────────────────────────────
# striped in trans flag order: blue / pink / white / pink / blue
banner() {
  local ver="${LDOWN_VERSION:-dev}"
  printf '\n'
  printf '%b\n' "${T_BLUE}  _     _                                   ${C_RESET}"
  printf '%b\n' "${T_PINK} | | __| | _____      ___ __               ${C_RESET}"
  printf '%b\n' "${T_WHITE} | |/ _\` |/ _ \\ \\ /\\ / / '_ \\              ${C_RESET}"
  printf '%b\n' "${T_PINK} | | (_| | (_) \\ V  V /| | | |             ${C_RESET}"
  printf '%b\n' "${T_BLUE} |_|\\__,_|\\___/ \\_/\\_/ |_| |_|             ${C_RESET}"
  printf '\n'
  printf '%b\n' "${C_GRAY}  network lockdown and tunnel provisioning${C_RESET}"
  printf '%b\n' "${C_GRAY}  v${ver}${C_RESET}"
  printf '\n'
}

# ── execution helpers ──────────────────────────────────────

# drun — dry-run aware command executor
# usage: drun "description" cmd [args...]
#
# dry run  → prints what would run, no execution, returns 0
# live run → executes with monotonic cmd_id logged for tracing
# trace    → set -x scoped tightly around the command, cleaned up with { set +x; } 2>/dev/null
#
# returns the command's exit code. caller decides whether to fatal or continue.
drun() {
  local desc="$1"
  shift

  if [[ "${DRY_RUN:-}" =~ ^(1|true|yes)$ ]]; then
    [[ "${_VERBOSITY}" -ge 1 ]] && \
      printf '%b\n' "${C_YELLOW}  [dry]${C_RESET} ${desc}"
    [[ "${_VERBOSITY}" -ge 2 ]] && \
      printf '%b\n' "${C_GRAY}         → $*${C_RESET}"
    return 0
  fi

  (( _CMD_SEQ++ ))
  local cmd_id
  printf -v cmd_id 'cmd_%04d' "${_CMD_SEQ}"
  _log_write "EXEC" "$*" "${cmd_id}"

  local rc
  trap - ERR
  if (( _VERBOSITY >= 3 )); then
    set -x
    "$@"
    rc=$?
    { set +x; } 2>/dev/null
  else
    "$@"
    rc=$?
  fi
  trap '_trap_err' ERR

  if (( rc != 0 )); then
    err "${desc} failed (exit ${rc}) [${cmd_id}]"
    err "  cmd: $*"
    return "${rc}"
  fi

  return 0
}

# must — like drun but calls fatal() on failure, never returns on error
must() {
  local desc="$1"
  shift

  if [[ "${DRY_RUN:-}" =~ ^(1|true|yes)$ ]]; then
    [[ "${_VERBOSITY}" -ge 1 ]] && \
      printf '%b\n' "${C_YELLOW}  [dry]${C_RESET} ${desc} ${C_GRAY}(required)${C_RESET}"
    return 0
  fi

  _CMD_SEQ=$((_CMD_SEQ + 1))
  local cmd_id
  printf -v cmd_id 'cmd_%04d' "${_CMD_SEQ}"
  debug "must [${cmd_id}]: ${desc}"
  _log_write "EXEC" "$*" "${cmd_id}"

  local rc
  trap - ERR
  if (( _VERBOSITY >= 3 )); then
    set -x
    "$@"
    rc=$?
    { set +x; } 2>/dev/null
  else
    "$@"
    rc=$?
  fi
  trap '_trap_err' ERR

  if (( rc != 0 )); then
    fatal "${desc} [${cmd_id}]\n  command: $*"
  fi
}

# run — timed execution wrapper for functions or commands
# usage: run "description" func_or_cmd [args...]
#
# logs start, captures exit code, prints duration and pass/fail.
# use this to wrap major phases; use drun for individual commands.
run() {
  local name="$1"
  shift

  local start end elapsed rc
  printf -v start '%(%s)T' -1

  debug "run: ${name}"
  _log_write "INFO" "phase=\"${name}\" event=start"

  "$@"
  rc=$?

  printf -v end '%(%s)T' -1
  elapsed=$(( end - start ))

  if (( rc == 0 )); then
    _log_write "INFO" "phase=\"${name}\" event=complete duration=${elapsed}"
    success "${name} completed in ${elapsed}s"
  else
    _log_write "ERROR" "phase=\"${name}\" event=failed duration=${elapsed}"
    err "${name} failed after ${elapsed}s (exit ${rc})"
  fi

  return "$rc"
}
# ── interactive helpers ────────────────────────────────────

# confirm — y/N prompt
# non-TTY: defaults NO with warning, does not hang
confirm() {
  local msg="${1:-continue?}"

  if [[ "${_IS_TTY}" -eq 0 ]]; then
    warn "non-interactive session — defaulting NO for: ${msg}"
    return 1
  fi

  local answer
  printf '%b' "${C_YELLOW}[?]${C_RESET} ${msg} ${C_DIM}[y/N]${C_RESET} "
  read -r answer || return 1
  [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

# prompt — read a value with optional default
# non-TTY: returns default silently, or fatals if no default
prompt() {
  local msg="$1"
  local default="${2:-}"

  if [[ "${_IS_TTY}" -eq 0 ]]; then
    if [[ -n "${default}" ]]; then
      debug "non-interactive prompt '${msg}' — using default: ${default}"
      printf '%s\n' "${default}"
      return 0
    else
      fatal "non-interactive session — no default for prompt: ${msg}"
    fi
  fi

  local value
  if [[ -n "${default}" ]]; then
    printf '%b' "${C_CYAN}[?]${C_RESET} ${msg} ${C_DIM}[${default}]${C_RESET}: "
  else
    printf '%b' "${C_CYAN}[?]${C_RESET} ${msg}: "
  fi
  read -r value || return 1
  printf '%s\n' "${value:-${default}}"
}

# ── validation ─────────────────────────────────────────────

# WireGuard public key: base64, exactly 44 chars, ends with =
is_valid_wg_key() {
  local key="$1"
  [[ "${#key}" -eq 44 ]]                   || return 1
  [[ "${key}" =~ ^[A-Za-z0-9+/]{43}=$ ]]  || return 1
  return 0
}

# CIDR: validates each octet 0-255, prefix 0-32
is_valid_cidr() {
  local cidr="$1"
  local ip="${cidr%/*}"
  local prefix="${cidr#*/}"

  [[ "${prefix}" =~ ^[0-9]+$ ]]       || return 1
  (( prefix >= 0 && prefix <= 32 ))   || return 1

  IFS='.' read -ra octets <<< "${ip}"
  [[ "${#octets[@]}" -eq 4 ]]         || return 1

  local octet
  for octet in "${octets[@]}"; do
    [[ "${octet}" =~ ^[0-9]+$ ]]      || return 1
    (( octet >= 0 && octet <= 255 ))  || return 1
  done

  return 0
}

is_valid_iface() {
  [[ -n "${1:-}" ]] || return 1
  ip link show "$1" &>/dev/null 2>&1
}

has_cmd() {
  command -v "$1" &>/dev/null
}

is_dry() {
  [[ "${DRY_RUN:-}" =~ ^(1|true|yes)$ ]]
}

# ── CIDR decomposition ─────────────────────────────────────

cidr_ip() {
  printf '%s\n' "${1%/*}"
}

cidr_prefix() {
  printf '%s\n' "${1#*/}"
}

# derive network address from host CIDR
# explicit handling for /0 and /32 edge cases
# e.g. 192.168.99.2/24 → 192.168.99.0/24
cidr_network() {
  local cidr="$1"
  local ip prefix
  ip="$(cidr_ip "${cidr}")"
  prefix="$(cidr_prefix "${cidr}")"

  (( prefix == 0 ))  && { printf '0.0.0.0/0\n'; return 0; }
  (( prefix == 32 )) && { printf '%s/32\n' "${ip}"; return 0; }

  IFS='.' read -ra o <<< "${ip}"

  local full partial
  local net=()
  local i

  full=$(( prefix / 8 ))
  partial=$(( prefix % 8 ))

  for (( i = 0; i < 4; i++ )); do
    if (( i < full )); then
      net+=("${o[$i]}")
    elif (( i == full )); then
      local mask=$(( 256 - (1 << (8 - partial)) ))
      net+=("$(( ${o[i]} & mask ))")
    else
      net+=("0")
    fi
  done

  printf '%s\n' "${net[0]}.${net[1]}.${net[2]}.${net[3]}/${prefix}"
}
# ── require root ───────────────────────────────────────────
require_root() {
  [[ "${EUID}" -eq 0 ]] || fatal "this command must be run as root"
}

# ── dependency check ───────────────────────────────────────
# usage: check_dependency wg ncat openssl
check_dependency() {
  local missing=()
  for cmd in "$@"; do
    has_cmd "${cmd}" || missing+=("${cmd}")
  done
  if (( ${#missing[@]} > 0 )); then
    fatal "missing required dependencies: ${missing[*]}"
  fi
}

# ── atomic config write ────────────────────────────────────
# usage: write_conf /etc/ldown/mesh.conf "$content"
write_conf() {
  local path="$1"
  local content="$2"
  local dir; dir="$(dirname "${path}")"
  mkdir -p "${dir}" || fatal "cannot create directory: ${dir}"
  local tmp; tmp="$(mktemp "${path}.XXXXXX")" || fatal "cannot create temp file in: ${dir}"
  printf '%s\n' "${content}" > "${tmp}" || { rm -f "${tmp}"; fatal "write failed: ${path}"; }
  mv "${tmp}" "${path}" || { rm -f "${tmp}"; fatal "rename failed: ${path}"; }
  debug "wrote ${path}"
}

# ── source if exists ───────────────────────────────────────
# usage: source_if_exists /etc/ldown/mesh.conf
source_if_exists() {
  local file="$1"
  [[ -f "${file}" && -r "${file}" ]] || return 0
  # shellcheck source=/dev/null
  source "${file}"
  debug "sourced ${file}"
}

# ── message signing using node Ed25519 keys ────────────────
# usage: sign_msg <payload> [use_hmac]
# signs with CLUSTER_TOKEN HMAC if use_hmac=true, otherwise Ed25519 with node key
# falls back to HMAC if node key is unavailable
sign_msg() {
  local payload="$1"
  local use_hmac="${2:-false}"
  local node_key="${KEY_DIR}/${MY_NAME}-node.key"
  if [[ "${use_hmac}" == "true" || ! -f "${node_key}" ]]; then
    printf '%s' "${payload}${CLUSTER_TOKEN}" | \
      sha256sum | awk '{print $1}'
  else
    printf '%s' "${payload}" | \
      openssl pkeyutl -sign -inkey "${node_key}" | \
      base64 -w0
  fi
}

# ── message verification using node Ed25519 keys ────────────
# usage: verify_msg <signature> <payload> <sender_name>
# verifies signature using sender's node public key if available, falls back to CLUSTER_TOKEN HMAC
verify_msg() {
  local received_sig="$1"
  local payload="$2"
  local sender_name="$3"
  local sender_pub="${KEY_DIR}/${sender_name}-node.pub"
  if [[ -n "${sender_name}" && -f "${sender_pub}" ]]; then
    local tmpsig
    tmpsig="$(mktemp)"
    printf '%s' "${received_sig}" | base64 -d > "${tmpsig}" 2>/dev/null
    printf '%s' "${payload}" | \
      openssl pkeyutl -verify -pubin -inkey "${sender_pub}" \
      -sigfile "${tmpsig}" >/dev/null 2>&1
    local result=$?
    rm -f "${tmpsig}"
    return ${result}
  elif [[ -n "${CLUSTER_TOKEN}" ]]; then
    local expected
    expected="$(printf '%s' "${payload}${CLUSTER_TOKEN}" | \
      sha256sum | awk '{print $1}')"
    [[ "${received_sig}" == "${expected}" ]]
  else
    return 1
  fi
}
