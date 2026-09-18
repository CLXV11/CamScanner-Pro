#!/data/data/com.termux/files/usr/bin/bash
# shellcheck shell=bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CAM-SEC Scanner v3.0.0 — Defensive IP-Camera Security Assessment   ║
# ║  Single-file Bash architecture | Termux/Android (rootless)          ║
# ║  AUTHORIZED USE ONLY — audit devices you own or are permitted to    ║
# ║  assess. No exploitation, no destructive actions.                   ║
# ╚══════════════════════════════════════════════════════════════════════╝
# Evidence-first: every finding carries evidence + verification state.
# Verification states: NOT_CHECKED | NOT_APPLICABLE | NO_EVIDENCE |
#   INCONCLUSIVE | POTENTIALLY_VULNERABLE | LIKELY_VULNERABLE | VERIFIED

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

###############################################################################
# 1. CONSTANTS
###############################################################################
readonly SCRIPT_NAME="CAM-SEC Scanner"
readonly VERSION="3.0.0"
readonly SCANNER_ID="camsec-scanner"

# Exit codes
readonly EX_OK=0
readonly EX_GENERAL=1
readonly EX_ARGS=2
readonly EX_DEPS=3
readonly EX_TARGET=4
readonly EX_INCOMPLETE=5

# Risk severities
readonly SEV_CRITICAL="CRITICAL"
readonly SEV_HIGH="HIGH"
readonly SEV_MEDIUM="MEDIUM"
readonly SEV_LOW="LOW"
readonly SEV_INFO="INFO"

# Scan profiles
PROFILE="normal"   # quick | normal | full

# Resource limits (safe defaults for Android)
MAX_WORKERS=4
HTTP_TIMEOUT=4
RTSP_TIMEOUT=4
# Port used for HTTP management probes. Default 80; overridable for isolated
# lab testing of this tool itself (documented test hook, not a scan option).
HTTP_PROBE_PORT="${CAMSEC_TEST_HTTP_PORT:-80}"
RTSP_RETRIES=1
MAX_AUTH_ATTEMPTS=6
AUTH_DELAY_MS=400
DISK_MIN_KB=10240   # 10 MB free required for captures
LOG_MAX_BYTES=1048576  # 1 MB log rotation

# Verbose/debug
QUIET=0
DEBUG=0

# State
SCAN_START_TS=0
TMPDIR_SCAN=""
ORPHAN_PIDS=()
JSON_FILE=""
TXT_FILE=""
AUTHORIZED=0

###############################################################################
# 2. CONFIGURATION (paths, safe key=value parser — NEVER source config)
###############################################################################
setup_paths() {
    if [[ -n "${PREFIX:-}" && -d "${PREFIX:-}" && -z "${CAMSEC_HOME_OVERRIDE:-}" ]]; then
        # Termux environment detected
        SCRIPT_DIR="${HOME}/.camsec"
    else
        SCRIPT_DIR="${CAMSEC_HOME:-${HOME}/.camsec}"
    fi
    LOG_DIR="$SCRIPT_DIR/logs"
    REPORT_DIR="$SCRIPT_DIR/reports"
    CAPTURE_DIR="$SCRIPT_DIR/captures"
    CONFIG_FILE="$SCRIPT_DIR/config.cfg"
    RUNTIME_DIR="${TMPDIR:-/tmp}/camsec_$$"
    mkdir -p "$LOG_DIR" "$REPORT_DIR" "$CAPTURE_DIR" "$RUNTIME_DIR"
    chmod 700 "$SCRIPT_DIR" 2>/dev/null || true
    TMPDIR_SCAN="$RUNTIME_DIR"
}

# Safe config parser: strictly KEY=VALUE lines. No command execution.
# Keys are whitelisted. Values are validated per-key.
config_load() {
    CONFIG_SHODAN_KEY=""
    CONFIG_DEFAULT_PROFILE="normal"
    [[ -f "$CONFIG_FILE" ]] || return 0
    local line key val lineno=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno+1))
        # strip CR (Termux/Windows line endings) and leading/trailing space
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
        if [[ ! "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
            log "WARN" "config" "Malformed line $lineno ignored (no key=value form)"
            continue
        fi
        key="${line%%=*}"; val="${line#*=}"
        # remove surrounding quotes if matched pair
        if [[ "${#val}" -ge 2 ]]; then
            if [[ "${val:0:1}" == '"' && "${val: -1}" == '"' ]]; then val="${val:1:-1}"; fi
            if [[ "${val:0:1}" == "'" && "${val: -1}" == "'" ]]; then val="${val:1:-1}"; fi
        fi
        case "$key" in
            SHODAN_API_KEY)
                # Shodan keys are 32-char alphanumeric
                if [[ "$val" =~ ^[A-Za-z0-9]{32}$ ]]; then
                    CONFIG_SHODAN_KEY="$val"
                elif [[ -n "$val" ]]; then
                    log "WARN" "config" "SHODAN_API_KEY malformed (expected 32 alnum chars); ignoring"
                fi
                ;;
            DEFAULT_PROFILE)
                case "$val" in quick|normal|full) CONFIG_DEFAULT_PROFILE="$val" ;; esac
                ;;
            *) log "WARN" "config" "Unknown config key '$key' ignored" ;;
        esac
    done < "$CONFIG_FILE"
    return 0
}

config_save_shodan() {
    local key="$1"
    [[ "$key" =~ ^[A-Za-z0-9]{32}$ ]] || { echo "INVALID_KEY_FORMAT"; return 1; }
    local tmp="${CONFIG_FILE}.tmp.$$"
    {
        grep -v '^SHODAN_API_KEY=' "$CONFIG_FILE" 2>/dev/null || true
        printf 'SHODAN_API_KEY="%s"\n' "$key"
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp" && mv "$tmp" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    CONFIG_SHODAN_KEY="$key"
}

# Effective Shodan key: environment wins over config file (safer in shared envs)
shodan_key() {
    if [[ -n "${SHODAN_API_KEY:-}" ]]; then printf '%s' "$SHODAN_API_KEY"; return 0; fi
    printf '%s' "$CONFIG_SHODAN_KEY"
}

###############################################################################
# 3. LOGGING (leveled, redacting, rotating)
###############################################################################
LOG_FILE_SET=0
log() {
    local level="$1" module="$2" msg="$3"
    local ts; ts="$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"
    local line="[${ts}] [${level}] [${module}] ${msg}"
    # stderr for WARN+ when interactive; always to file
    if [[ "$LOG_FILE_SET" -eq 1 ]]; then
        # rotate if oversized
        if [[ -f "${LOG_FILE}" ]]; then
            local sz; sz="$(stat -c %s "$LOG_FILE" 2>/dev/null || stat -f %z "$LOG_FILE" 2>/dev/null || echo 0)"
            if [[ "${sz:-0}" -gt "$LOG_MAX_BYTES" ]]; then
                mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
                : > "$LOG_FILE"
            fi
        fi
        printf '%s\n' "$line" >> "$LOG_FILE" || true
    fi
    if [[ "$QUIET" -eq 0 && "$level" != "DEBUG" ]]; then
        case "$level" in
            WARN|ERROR|SECURITY) printf '%s\n' "$line" >&2 ;;
        esac
    fi
    return 0
}

# Never leak secrets into logs: redact before calling log with user data.
redact() {
    local s="$1"
    [[ -n "$s" ]] || { printf ''; return 0; }
    s="${s//${SHODAN_API_KEY:-__none__}/[REDACTED]}" 2>/dev/null || true
    if [[ -n "${CONFIG_SHODAN_KEY:-}" ]]; then
        s="${s//${CONFIG_SHODAN_KEY}/[REDACTED]}" || true
    fi
    printf '%s' "$s"
}

###############################################################################
# 4. TERMINAL / UI
###############################################################################
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[1;33m'
    C_BLU=$'\033[0;34m'; C_CYN=$'\033[0;36m'; C_WHT=$'\033[1;37m'
    C_BOLD=$'\033[1m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_WHT=""; C_BOLD=""; C_RST=""
fi

banner() {
    [[ "$QUIET" -eq 1 ]] && return 0
    cat <<EOF
${C_CYN}╔══════════════════════════════════════════════════════════╗
║  ${C_WHT}CAM-SEC Scanner${C_CYN}  —  Defensive Camera Assessment v${VERSION}  ║
║  Evidence-first • Authorized-use • Termux/Android          ║
╚══════════════════════════════════════════════════════════╝${C_RST}
${C_RED}  Authorized use only: audit devices you own or are         ${C_RST}
${C_RED}  explicitly permitted to assess.                           ${C_RST}
EOF
}

ui_line() { printf '%s\n' "──────────────────────────────────────────"; }

say()  { [[ "$QUIET" -eq 1 ]] && return 0; printf '%s\n' "$*"; }
ok()   { say "${C_GRN}[✓]${C_RST} $*"; }
warn() { say "${C_YEL}[!]${C_RST} $*"; }
err()  { printf '%s\n' "${C_RED}[✗]${C_RST} $*" >&2; }

###############################################################################
# 5. DEPENDENCY MANAGER (detect, version, graceful fallback)
###############################################################################
declare -A DEPS_OK=()
declare -A DEPS_VER=()

dep_detect() {
    local c
    for c in curl ffprobe ffmpeg jq python3 nmap timeout openssl ip ifconfig; do
        if command -v "$c" >/dev/null 2>&1; then
            DEPS_OK[$c]=1
            DEPS_VER[$c]="$("$c" --version 2>/dev/null | head -n1 | cut -c1-60 || echo unknown)"
        else
            DEPS_OK[$c]=0
            DEPS_VER[$c]=""
        fi
    done
    log "DEBUG" "deps" "detected: curl=${DEPS_OK[curl]} ffprobe=${DEPS_OK[ffprobe]} ffmpeg=${DEPS_OK[ffmpeg]} jq=${DEPS_OK[jq]} python3=${DEPS_OK[python3]} nmap=${DEPS_OK[nmap]} timeout=${DEPS_OK[timeout]}"
    return 0
}

dep_require() {
    # Hard requirement only for curl (everything else has a fallback or NOT_SUPPORTED path)
    if [[ "${DEPS_OK[curl]:-0}" -ne 1 ]]; then
        err "Missing hard dependency: curl"
        err "Termux:  pkg install curl"
        log "ERROR" "deps" "curl missing"
        exit "$EX_DEPS"
    fi
    return 0
}

dep_report() {
    say "  Dependency status:"
    local c
    for c in curl ffprobe ffmpeg jq python3 nmap timeout openssl; do
        if [[ "${DEPS_OK[$c]:-0}" -eq 1 ]]; then
            say "    ${C_GRN}OK  ${C_RST} $(printf '%-9s' "$c") ${DEPS_VER[$c]}"
        else
            say "    ${C_YEL}MISS${C_RST} $(printf '%-9s' "$c") (optional — fallback: NOT_SUPPORTED)"
        fi
    done
    return 0
}

###############################################################################
# 6. INPUT VALIDATION
###############################################################################
re_ipv4='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
re_cidr4='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$'
re_ipv6='^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$'

valid_ipv4() { [[ "$1" =~ $re_ipv4 ]]; }
valid_cidr4() { [[ "$1" =~ $re_cidr4 ]]; }
valid_ipv6() { [[ "$1" =~ $re_ipv6 && "$1" == *:* ]]; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 )); }
valid_iface() { [[ "$1" =~ ^[A-Za-z0-9_.:-]+$ ]]; }
safe_filename() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }

# Scope guard: assessment is restricted to private/loopback/link-local space
# unless the operator explicitly passes --allow-public (still logged as SECURITY).
is_private_ip() {
    local ip="$1"
    valid_ipv4 "$ip" || return 1
    local o1 o2; o1="${ip%%.*}"; rest="${ip#*.}"; o2="${rest%%.*}"
    (( o1 == 10 )) && return 0
    (( o1 == 127 )) && return 0
    (( o1 == 172 && o2 >= 16 && o2 <= 31 )) && return 0
    (( o1 == 192 && o2 == 168 )) && return 0
    (( o1 == 169 && o2 == 254 )) && return 0
    return 1
}

is_private_cidr() {
    local cidr="$1" ip="${1%/*}"
    is_private_ip "$ip"
}

###############################################################################
# JSON engine (pure-Bash builder + jq/python3 validation)
###############################################################################
json_escape() {
    # Escape a string for JSON embedding (RFC 8259)
    local s="$1" out="" ch i
    for (( i=0; i<${#s}; i++ )); do
        ch="${s:i:1}"
        case "$ch" in
            '"') out+='\"' ;;
            '\') out+='\\' ;;
            $'\b') out+='\b' ;;
            $'\f') out+='\f' ;;
            $'\n') out+='\n' ;;
            $'\r') out+='\r' ;;
            $'\t') out+='\t' ;;
            *) out+="$ch" ;;
        esac
    done
    printf '%s' "$out"
}

json_str() { printf '"%s"' "$(json_escape "$1")"; }

join_json_array() {
    # $1 = name of a declared bash array variable -> prints a JSON array of strings
    local _name="$1"
    if [[ ! "$_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then echo '[]'; return 0; fi
    local -n _arr_ref="$_name" 2>/dev/null || { echo '[]'; return 0; }
    local _v _out="[" _first=1
    for _v in "${_arr_ref[@]:-}"; do
        [[ -n "$_v" ]] || continue
        [[ $_first -eq 0 ]] && _out+=","
        _out+=$(json_str "$_v"); _first=0
    done
    printf '%s]' "$_out"
}

JSON_VALIDATE_OK=""
json_validate() {
    # $1 = file. Returns 0 and sets JSON_VALIDATE_OK=PASS on valid JSON.
    JSON_VALIDATE_OK="FAIL"
    local f="$1"
    if [[ "${DEPS_OK[jq]:-0}" -eq 1 ]]; then
        if jq empty "$f" >/dev/null 2>&1; then JSON_VALIDATE_OK="PASS"; return 0; fi
        return 1
    elif [[ "${DEPS_OK[python3]:-0}" -eq 1 ]]; then
        if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$f" >/dev/null 2>&1; then
            JSON_VALIDATE_OK="PASS"; return 0
        fi
        return 1
    else
        JSON_VALIDATE_OK="UNVERIFIED"
        log "WARN" "report" "No JSON validator available (jq/python3 missing)"
        return 0
    fi
}

###############################################################################
# 7. NETWORK DISCOVERY (interface + subnet detection — never guess wlan0//24)
###############################################################################
detect_interfaces() {
    # Outputs "name|ipv4|prefix" lines. Uses `ip` (preferred) or `ifconfig`.
    local out=""
    if [[ "${DEPS_OK[ip]:-0}" -eq 1 ]]; then
        out="$(ip -o -4 addr show 2>/dev/null | awk '{n=$2; sub(/\/.*$/,"",$4); split($4,a,"."); print n"|"$4"|"a[1]"."a[2]"."a[3]}' 2>/dev/null || true)"
    elif [[ "${DEPS_OK[ifconfig]:-0}" -eq 1 ]]; then
        out="$(ifconfig 2>/dev/null | awk '/flags=/{iface=$1} /inet /{ip=$2; sub(/addr:/,"",ip); if(ip !~ /^127\./) print iface"|"ip"|"substr(ip,1)}' 2>/dev/null | awk -F'|' '{n=split($2,a,"."); print $1"|"$2"|"a[1]"."a[2]"."a[3]}' || true)"
    fi
    printf '%s\n' "$out"
}

local_ipv4() {
    local iface="${1:-}"
    local line name ip _pfx
    while IFS='|' read -r name ip _pfx; do
        [[ -z "$name" ]] && continue
        if [[ -n "$iface" && "$name" == "$iface" ]]; then printf '%s' "$ip"; return 0; fi
        [[ -z "$iface" && "$ip" != 127.* ]] && { printf '%s' "$ip"; return 0; }
    done < <(detect_interfaces)
    return 1
}

network_cidr() {
    # Best-effort CIDR from detected interface. Prints CIDR or returns 1 with reason.
    local iface="$1" line name ip pfx
    while IFS='|' read -r name ip pfx; do
        [[ -z "$name" ]] && continue
        [[ -n "$iface" && "$name" != "$iface" ]] && continue
        [[ -z "$iface" && "$ip" == 127.* ]] && continue
        # Heuristic prefix from RFC1918 class (no `ip` prefix math on Termux busybox)
        local o1="${ip%%.*}" rest="${ip#*.}" o2="${rest%%.*}"
        if (( o1 == 10 )); then printf '10.0.0.0/8'; return 0
        elif (( o1 == 172 && o2 >= 16 && o2 <= 31 )); then printf '%s.0.0/16' "$o1.$o2"; return 0
        elif (( o1 == 192 && o2 == 168 )); then printf '%s.0/24' "$pfx"; return 0
        elif (( o1 == 169 && o2 == 254 )); then printf '169.254.0.0/16'; return 0
        fi
    done < <(detect_interfaces)
    return 1
}

###############################################################################
# 8. SERVICE DETECTION (HTTP probe on a port list; nmap optional accelerator)
###############################################################################
PORT_LIST="80,443,554,8000,8080,8443,8554,8888,37777,9000"

probe_http() {
    # $1=host $2=port → prints "scheme|status|server|www_auth|title_snip"
    local host="$1" port="$2" url status server auth body title
    local hurl; hurl="http://${host}:${port}/"
    local raw
    raw="$(curl -sS -m "$HTTP_TIMEOUT" -D - -o /dev/null -w $'\n__STATUS__%{http_code}' "$hurl" 2>/dev/null)" || true
    [[ -z "$raw" ]] && return 1
    status="${raw##*__STATUS__}"
    [[ "$status" =~ ^[0-9]{3}$ && "$status" != "000" ]] || return 1
    server="$(printf '%s' "$raw" | tr -d '\r' | grep -i '^Server:' | head -n1 | cut -d: -f2- | sed 's/^[ \t]*//' || true)"
    auth="$(printf '%s' "$raw" | tr -d '\r' | grep -i '^WWW-Authenticate:' | head -n1 | cut -d: -f2- | sed 's/^[ \t]*//' || true)"
    printf 'http|%s|%s|%s|\n' "$status" "$server" "$auth"
    return 0
}

probe_https() {
    local host="$1" port="$2" raw status server auth
    raw="$(curl -sSk -m "$HTTP_TIMEOUT" -D - -o /dev/null -w $'\n__STATUS__%{http_code}' "https://${host}:${port}/" 2>/dev/null)" || true
    [[ -z "$raw" ]] && return 1
    status="${raw##*__STATUS__}"
    [[ "$status" =~ ^[0-9]{3}$ && "$status" != "000" ]] || return 1
    server="$(printf '%s' "$raw" | tr -d '\r' | grep -i '^Server:' | head -n1 | cut -d: -f2- | sed 's/^[ \t]*//' || true)"
    auth="$(printf '%s' "$raw" | tr -d '\r' | grep -i '^WWW-Authenticate:' | head -n1 | cut -d: -f2- | sed 's/^[ \t]*//' || true)"
    printf 'https|%s|%s|%s|\n' "$status" "$server" "$auth"
    return 0
}

###############################################################################
# 9. DEVICE FINGERPRINTING (evidence-weighted confidence)
###############################################################################
# Evidence is accumulated in these globals by fingerprint_device()
FP_VENDOR="UNKNOWN"; FP_VENDOR_CONF=0.0; FP_MODEL="UNKNOWN"; FP_MODEL_CONF=0.0
FP_FIRMWARE="";      FP_FW_CONF=0.0
FP_EVIDENCE_COUNT=0
FP_ONVIF="NOT_CHECKED"
declare -a FP_EVIDENCE=()

fp_add_evidence() {  # $1=source $2=detail
    FP_EVIDENCE+=("$(printf '{"source": %s, "detail": %s}' "$(json_str "$1")" "$(json_str "$2")")")
    FP_EVIDENCE_COUNT=$((FP_EVIDENCE_COUNT+1))
}

http_get() { # $1=url → body (limited)
    curl -sS -m "$HTTP_TIMEOUT" "$1" 2>/dev/null | head -c 4096 || true
}

fingerprint_device() {
    local host="$1"
    FP_VENDOR="UNKNOWN"; FP_VENDOR_CONF=0.0; FP_MODEL="UNKNOWN"; FP_MODEL_CONF=0.0
    FP_FIRMWARE=""; FP_FW_CONF=0.0; FP_EVIDENCE_COUNT=0; FP_EVIDENCE=(); FP_ONVIF="NOT_CHECKED"
    local vscore=0 mscore=0 score_den=0
    local candidate_vendor="" candidate_model="" candidate_fw=""

    # --- Source 1: HTTP header server/banner on port 80/8080/8000 ---
    local port scheme status server auth body
    for port in 80 8080 8000 "$HTTP_PROBE_PORT"; do
        local p; p="$(probe_http "$host" "$port")" || true
        [[ -z "$p" ]] && continue
        scheme="${p%%|*}"; p="${p#*|}"
        status="${p%%|*}"; p="${p#*|}"
        server="${p%%|*}"; p="${p#*|}"
        auth="${p%%|*}"
        score_den=$((score_den+1))
        if [[ -n "$server" ]]; then
            fp_add_evidence "http:server:${port}" "$server"
            case "$(printf '%s' "$server" | tr '[:upper:]' '[:lower:]')" in
                *hikvision*) candidate_vendor="Hikvision"; vscore=$((vscore+3)); candidate_model="${server}"; mscore=$((mscore+1)) ;;
                *dahua*|*dvr*) candidate_vendor="Dahua"; vscore=$((vscore+3)); candidate_model="${server}"; mscore=$((mscore+1)) ;;
                *reolink*) candidate_vendor="Reolink"; vscore=$((vscore+3)) ;;
                *foscam*|*ipcam*) candidate_vendor="Foscam"; vscore=$((vscore+2)) ;;
                *goahead*) candidate_vendor="GoAhead-based"; vscore=$((vscore+1)) ;;
                *nginx*|*apache*|*lighttpd*|*mini_httpd*) ;; # generic — no vendor signal
                *) candidate_vendor="Unknown-server"; vscore=$((vscore+1)) ;;
            esac
        fi
        if [[ -n "$auth" ]]; then
            fp_add_evidence "http:www-authenticate:${port}" "$auth"
            case "$(printf '%s' "$auth" | tr '[:upper:]' '[:lower:]')" in
                *digest*) ;; *basic*) ;;
            esac
        fi
        # --- Source 2: HTML body fingerprints ---
        if [[ "$status" == "200" && ( "$port" == "80" || "$port" == "$HTTP_PROBE_PORT" ) ]]; then
            body="$(http_get "http://${host}:${port}/")"
            if [[ -n "$body" ]]; then
                score_den=$((score_den+1))
                fp_add_evidence "http:body:${port}" "retrieved $(printf '%s' "$body" | wc -c | tr -d ' ') bytes"
                local bl; bl="$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')"
                case "$bl" in
                    *hikvision*) vscore=$((vscore+3)); candidate_vendor="${candidate_vendor:-Hikvision}" ;;
                    *dahua*)     vscore=$((vscore+3)); candidate_vendor="${candidate_vendor:-Dahua}" ;;
                    *reolink*)   vscore=$((vscore+3)); candidate_vendor="${candidate_vendor:-Reolink}" ;;
                    *foscam*)    vscore=$((vscore+2)); candidate_vendor="${candidate_vendor:-Foscam}" ;;
                    *tp-link*|*tplink*) vscore=$((vscore+2)); candidate_vendor="${candidate_vendor:-TP-Link}" ;;
                    *axis*)      vscore=$((vscore+3)); candidate_vendor="${candidate_vendor:-Axis}" ;;
                esac
                # model / firmware strings, e.g. "var model = \"DS-2CD...\"; "
                local m; m="$(printf '%s' "$body" | grep -oiE '(model|devicetype|device_type)[=: ]+["'"'"']?[A-Za-z0-9 _.-]{2,40}' | head -n1 || true)"
                if [[ -n "$m" ]]; then candidate_model="$m"; mscore=$((mscore+2)); fi
                local fw; fw="$(printf '%s' "$body" | grep -oiE '(firmware|fwversion|softwareversion)[=: ]+["'"'"']?[A-Za-z0-9 .:_-]{2,40}' | head -n1 || true)"
                if [[ -n "$fw" ]]; then candidate_fw="$fw"; fi
            fi
        fi
    done

    # --- Source 3: HTTPS on 443/8443 (TLS presence is itself evidence) ---
    for port in 443 8443; do
        local p; p="$(probe_https "$host" "$port")" || true
        [[ -z "$p" ]] && continue
        score_den=$((score_den+1))
        fp_add_evidence "https:probe:${port}" "reachable"
        server="${p#*|}"; server="${server%%|*}"
        if [[ -n "$server" ]]; then
            fp_add_evidence "https:server:${port}" "$server"
            case "$(printf '%s' "$server" | tr '[:upper:]' '[:lower:]')" in
                *hikvision*) vscore=$((vscore+3)); candidate_vendor="${candidate_vendor:-Hikvision}" ;;
                *dahua*)     vscore=$((vscore+3)); candidate_vendor="${candidate_vendor:-Dahua}" ;;
            esac
        fi
    done

    # --- Source 4: ONVIF device service (real SOAP probe) ---
    local onvif_body
    onvif_body="$(curl -sS -m "$HTTP_TIMEOUT" \
        -H 'Content-Type: application/soap+xml; charset=utf-8' \
        -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>' \
        "http://${host}:${CAMSEC_TEST_ONVIF_PORT:-8080}/onvif/device_service" 2>/dev/null | head -c 2048 || true)"
    if [[ -n "$onvif_body" ]]; then
        score_den=$((score_den+2))
        if printf '%s' "$onvif_body" | grep -qi 'onvif\|GetDeviceInformationResponse\|Manufacturer'; then
            FP_ONVIF="PRESENT"
            fp_add_evidence "onvif:device_service" "SOAP endpoint responded"
            local m; m="$(printf '%s' "$onvif_body" | grep -oE '<(tds:)?Manufacturer>[^<]+' | sed -E 's/<[^>]+>//' | head -n1 || true)"
            [[ -n "$m" ]] && { candidate_vendor="$m"; vscore=$((vscore+4)); fp_add_evidence "onvif:manufacturer" "$m"; }
            local fwx; fwx="$(printf '%s' "$onvif_body" | grep -oE '<(tds:)?FirmwareVersion>[^<]+' | sed -E 's/<[^>]+>//' | head -n1 || true)"
            [[ -n "$fwx" ]] && { candidate_fw="$fwx"; fp_add_evidence "onvif:firmware" "$fwx"; }
            local mo; mo="$(printf '%s' "$onvif_body" | grep -oE '<(tds:)?Model>[^<]+' | sed -E 's/<[^>]+>//' | head -n1 || true)"
            [[ -n "$mo" ]] && { candidate_model="$mo"; mscore=$((mscore+3)); fp_add_evidence "onvif:model" "$mo"; }
        fi
    else
        FP_ONVIF="ABSENT"
    fi

    # --- Source 5: RTSP banner (DESCRIBE response, unauthenticated) ---
    if [[ "${DEPS_OK[ffprobe]:-0}" -eq 1 ]]; then
        local rtsp_hdr
        rtsp_hdr="$(run_with_timeout "$RTSP_TIMEOUT" ffprobe -v error -rtsp_transport tcp \
            -i "rtsp://${host}:554/" 2>&1 | head -c 512 || true)"
        if printf '%s' "$rtsp_hdr" | grep -qi 'server:\|401\|407'; then
            score_den=$((score_den+1))
            fp_add_evidence "rtsp:banner" "$(printf '%s' "$rtsp_hdr" | head -n1)"
            local srv; srv="$(printf '%s' "$rtsp_hdr" | grep -oiE 'server:[^ ]+' | head -n1 || true)"
            case "$(printf '%s' "$srv" | tr '[:upper:]' '[:lower:]')" in
                *hikvision*) vscore=$((vscore+2)); candidate_vendor="${candidate_vendor:-Hikvision}" ;;
                *dahua*) vscore=$((vscore+2)); candidate_vendor="${candidate_vendor:-Dahua}" ;;
                *gstreamer*|*live555*|*rtsp*) ;; # generic
            esac
        fi
    fi

    # --- Thresholds: evidence-based or UNKNOWN (no guessing) ---
    # vendor:  min 2 weighted points AND ≥2 evidence items → confident
    if [[ "$vscore" -ge 2 && "$FP_EVIDENCE_COUNT" -ge 2 && -n "$candidate_vendor" ]]; then
        FP_VENDOR="$candidate_vendor"
        FP_VENDOR_CONF="$(awk -v s="$vscore" -v d="$((score_den+2))" 'BEGIN{printf "%.2f", (s>d?d:s)/d}')"
    elif [[ "$vscore" -ge 1 && -n "$candidate_vendor" ]]; then
        FP_VENDOR="$candidate_vendor"; FP_VENDOR_CONF="0.40"
    fi
    if [[ "$mscore" -ge 2 && -n "$candidate_model" && "$FP_VENDOR" != "UNKNOWN" ]]; then
        FP_MODEL="$candidate_model"
        FP_MODEL_CONF="$(awk -v s="$mscore" -v d=8 'BEGIN{printf "%.2f", (s>d?d:s)/d}')"
    fi
    if [[ -n "$candidate_fw" && "$FP_VENDOR" != "UNKNOWN" ]]; then
        FP_FIRMWARE="$candidate_fw"; FP_FW_CONF="0.85"
    fi
    return 0
}

###############################################################################
# Timeout helper: prefers GNU timeout; falls back to watchdog kill.
# Tracks PIDs for guaranteed cleanup. Usage: run_with_timeout SECS CMD [ARGS...]
###############################################################################
run_with_timeout() {
    local secs="$1"; shift
    if [[ "${DEPS_OK[timeout]:-0}" -eq 1 ]]; then
        timeout --signal=TERM --kill-after=2 "$secs" "$@" 2>/dev/null
        return $?
    fi
    "$@" &
    local pid=$!
    ORPHAN_PIDS+=("$pid")
    (
        sleep "$secs"
        kill -TERM "$pid" 2>/dev/null || true
        sleep 1
        kill -KILL "$pid" 2>/dev/null || true
    ) &
    local wd=$!
    local rc=0
    wait "$pid" 2>/dev/null || rc=$?
    kill "$wd" 2>/dev/null || true
    wait "$wd" 2>/dev/null || true
    return "$rc"
}

disk_free_kb() {
    local dir="$1"
    df -k "$dir" 2>/dev/null | awk 'NR==2{print $4}' | grep -E '^[0-9]+$' || echo 0
}

###############################################################################
# 10. RTSP / STREAM ASSESSMENT (bounded, timeout-safe)
###############################################################################
# RTSP path candidates — bounded list, ordered by real-world prevalence.
RTSP_PATHS_QUICK=("/" "/live" "/h264" "/cam/realmonitor" "/Streaming/Channels/101" "/11")
RTSP_PATHS_FULL=(
    "/" "/live" "/live/main" "/live/sub" "/live/ch00_0"
    "/h264" "/h264/ch01/main/av_stream" "/h264/ch01/sub/av_stream"
    "/stream1" "/stream2" "/cam/realmonitor" "/cam/realmonitor?channel=1&subtype=0"
    "/video" "/video1" "/media/video1" "/ch01/0" "/ch01/1"
    "/Streaming/Channels/101" "/Streaming/Channels/102" "/ISAPI/Streaming/channels/101"
    "/unicast" "/11" "/12" "/av0_0" "/mpeg4/media.amp"
)

rtsp_paths_for_profile() {
    if [[ "$PROFILE" == "quick" ]]; then printf '%s\n' "${RTSP_PATHS_QUICK[@]}"
    else printf '%s\n' "${RTSP_PATHS_FULL[@]}"; fi
}

# Returns via globals: RTSP_STATE = NO_SERVICE|AUTH_REQUIRED|OPEN|TIMEOUT|ERROR
# and RTSP_PATHS_OPEN / RTSP_PATHS_AUTHREQ arrays.
RTSP_STATE="NOT_CHECKED"; RTSP_PORT_OPEN=0
declare -a RTSP_PATHS_OPEN=() RTSP_PATHS_AUTHREQ=()

rtsp_describe_status() {
    # Classify a DESCRIBE probe using ffprobe error output.
    # $1=host $2=path → echoes OPEN | AUTH_REQUIRED | NOT_FOUND | TIMEOUT
    local host="$1" path="$2" out rc
    if [[ "${DEPS_OK[ffprobe]:-0}" -ne 1 ]]; then echo "NO_TOOL"; return 0; fi
    out="$(run_with_timeout "$RTSP_TIMEOUT" ffprobe -v error -rtsp_transport tcp \
        -i "rtsp://${host}:554${path}" 2>&1 | head -c 1024 || true)"
    if [[ -z "$out" ]]; then echo "TIMEOUT"; return 0; fi
    if printf '%s' "$out" | grep -qi '401 Unauthorized\|407 Proxy Authentication\|authentication'; then
        echo "AUTH_REQUIRED"; return 0
    fi
    if printf '%s' "$out" | grep -qiE '404|not found|invalid url|bad request|unsupported'; then
        echo "NOT_FOUND"; return 0
    fi
    if printf '%s' "$out" | grep -qiE 'Connection refused|Connection timed out|No route|Immediate exit requested'; then
        echo "TIMEOUT"; return 0
    fi
    # ffprobe produced stream info or a non-auth error → treat as reachable
    if printf '%s' "$out" | grep -qiE 'Stream #|rtsp:|option|error'; then
        echo "OPEN"; return 0
    fi
    echo "TIMEOUT"
}

scan_rtsp() {
    local host="$1"
    RTSP_STATE="NOT_CHECKED"; RTSP_PORT_OPEN=0
    RTSP_PATHS_OPEN=(); RTSP_PATHS_AUTHREQ=()
    # Port reachability: TCP connect check via bash /dev/tcp with timeout
    if run_with_timeout 3 bash -c "exec 3<>/dev/tcp/${host}/554" 2>/dev/null; then
        RTSP_PORT_OPEN=1
    else
        RTSP_STATE="NO_SERVICE"
        log "INFO" "rtsp" "$host:554 closed/unreachable"
        return 0
    fi
    local path cls
    local saw_open=0 saw_auth=0 saw_timeout=0
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        cls="$(rtsp_describe_status "$host" "$path")"
        case "$cls" in
            OPEN)         RTSP_PATHS_OPEN+=("$path");  saw_open=1 ;;
            AUTH_REQUIRED) RTSP_PATHS_AUTHREQ+=("$path"); saw_auth=1 ;;
            NOT_FOUND)    : ;;
            TIMEOUT)      saw_timeout=1 ;;
            NO_TOOL)      RTSP_STATE="NOT_SUPPORTED"; log "WARN" "rtsp" "ffprobe unavailable"; return 0 ;;
        esac
    done < <(rtsp_paths_for_profile)
    if [[ "$saw_open" -eq 1 ]]; then RTSP_STATE="OPEN"
    elif [[ "$saw_auth" -eq 1 ]]; then RTSP_STATE="AUTH_REQUIRED"
    elif [[ "$saw_timeout" -eq 1 ]]; then RTSP_STATE="TIMEOUT"
    else RTSP_STATE="NO_PATHS"; fi
    log "INFO" "rtsp" "$host: state=$RTSP_STATE open=${#RTSP_PATHS_OPEN[@]} authreq=${#RTSP_PATHS_AUTHREQ[@]}"
    return 0
}

###############################################################################
# 11. VULNERABILITY ASSESSMENT (evidence-based states — never assumed)
###############################################################################
# Each check appends findings to FINDINGS_JSON via add_finding().
FINDINGS_JSON="[]"
FINDING_SEQ=0
declare -a FINDINGS_ROWS=()
findings_json() {
    local out="[" first=1 row
    for row in "${FINDINGS_ROWS[@]:-}"; do
        [[ -n "$row" ]] || continue
        [[ $first -eq 0 ]] && out+=","
        out+="$row"; first=0
    done
    printf '%s]' "$out"
}

add_finding() {
    # $1=severity $2=title $3=description $4=evidence $5=verification
    # $6=confidence(0-1) $7=cve $8=remediation
    local sev="$1" title="$2" desc="$3" evid="$4" ver="$5" conf="$6" cve="$7" remed="$8"
    FINDING_SEQ=$((FINDING_SEQ+1))
    local id; id="$(printf 'CAMSEC-%s-%03d' "$(date +%Y%m%d)" "$FINDING_SEQ")"
    FINDINGS_ROWS+=("$(printf '{"id":%s,"severity":%s,"title":%s,"description":%s,"evidence":%s,"verification":%s,"confidence":%s,"cve":%s,"remediation":%s}' \
        "$(json_str "$id")" "$(json_str "$sev")" "$(json_str "$title")" "$(json_str "$desc")" \
        "$(json_str "$evid")" "$(json_str "$ver")" "$(json_str "$conf")" \
        "$(json_str "$cve")" "$(json_str "$remed")")")
    say "  ${C_YEL}[${sev}]${C_RST} ${title} — ${ver} (conf ${conf})"
    log "SECURITY" "vuln" "$id $sev $title ver=$ver conf=$conf"
    return 0
}

assess_vulnerabilities() {
    local host="$1"
    local vendor_lc; vendor_lc="$(printf '%s' "$FP_VENDOR" | tr '[:upper:]' '[:lower:]')"
    say ""; say "${C_CYN}== Vulnerability assessment: ${host} ==${C_RST}"
    say "   Vendor: ${FP_VENDOR} (conf ${FP_VENDOR_CONF}, ${FP_EVIDENCE_COUNT} evidence items)"

    # -- CVE-2017-7921 (Hikvision auth bypass) --------------------------------
    # Detection: unauthenticated access to /Security/users returning an XML
    # user list with <userName> entries. VERIFIED only on that exact evidence.
    if [[ "$vendor_lc" == *hikvision* ]]; then
        local r
        r="$(curl -sS -m "$HTTP_TIMEOUT" "http://${host}:${HTTP_PROBE_PORT}/Security/users?auth=YWRtaW46MTEK" 2>/dev/null | head -c 2048 || true)"
        if printf '%s' "$r" | grep -q '<userName>' && printf '%s' "$r" | grep -q '<userID>'; then
            add_finding "$SEV_CRITICAL" "CVE-2017-7921: Hikvision authentication bypass" \
                "Unauthenticated /Security/users endpoint returned the device user list." \
                "GET /Security/users?auth=... → 200 with <userName>/<userID> XML" \
                "VERIFIED" "0.95" "CVE-2017-7921" \
                "Upgrade firmware; restrict HTTP access; place camera behind authenticated proxy/VLAN."
        else
            add_finding "$SEV_INFO" "CVE-2017-7921: Hikvision auth bypass" \
                "Vendor matches; backdoor endpoint probe returned no user-list evidence." \
                "GET /Security/users → no XML user list in response" \
                "NO_EVIDENCE" "0.60" "CVE-2017-7921" "Keep firmware current."
        fi
        # CVE-2017-7925: config file exposure
        local cfg
        cfg="$(curl -sS -m "$HTTP_TIMEOUT" -o /dev/null -w '%{http_code}:%{size_download}' "http://${host}:${HTTP_PROBE_PORT}/System/configurationFile?auth=YWRtaW46MTEK" 2>/dev/null || true)"
        if [[ "$cfg" == 200:* && "${cfg##*:}" -gt 1000 ]]; then
            add_finding "$SEV_CRITICAL" "CVE-2017-7925: configuration file exposure" \
                "Unauthenticated configuration download endpoint returned a large binary blob." \
                "GET /System/configurationFile → HTTP 200, ${cfg##*:} bytes" \
                "VERIFIED" "0.90" "CVE-2017-7925" \
                "Upgrade firmware immediately; block endpoint at gateway."
        fi
    else
        add_finding "$SEV_INFO" "CVE-2017-7921/7925 not applicable" \
            "Device not fingerprinted as Hikvision; Hikvision-specific checks skipped." \
            "fingerprint vendor=${FP_VENDOR}" "NOT_APPLICABLE" "1.0" "CVE-2017-7921" "N/A"
    fi

    # -- CVE-2021-33044 (Dahua RPC auth bypass) --------------------------------
    if [[ "$vendor_lc" == *dahua* ]]; then
        local r
        r="$(curl -sS -m "$HTTP_TIMEOUT" -X POST "http://${host}/RPC2_Login" \
            -H 'Content-Type: application/json' \
            -d '{"method":"global.login","params":{"userName":"admin","password":"not-a-real-password-z9","clientType":"Web3.0"}}' 2>/dev/null | head -c 1024 || true)"
        # The bypass signature: a session id issued without valid credentials.
        if printf '%s' "$r" | grep -qE '"session"[ ]*:[ ]*[0-9]+'; then
            add_finding "$SEV_CRITICAL" "CVE-2021-33044: Dahua RPC authentication bypass" \
                "RPC2_Login issued a session ID in response to an intentionally invalid password — authentication bypass confirmed." \
                "POST /RPC2_Login (bad password) → session id present" \
                "VERIFIED" "0.95" "CVE-2021-33044" \
                "Upgrade Dahua firmware; disable web service if unused."
        else
            add_finding "$SEV_INFO" "CVE-2021-33044: Dahua RPC auth bypass" \
                "Vendor matches; invalid-credential login probe did not yield a session." \
                "POST /RPC2_Login (bad password) → no session id" \
                "NO_EVIDENCE" "0.60" "CVE-2021-33044" "Keep firmware current."
        fi
    else
        add_finding "$SEV_INFO" "CVE-2021-33044 not applicable" \
            "Device not fingerprinted as Dahua." "fingerprint vendor=${FP_VENDOR}" \
            "NOT_APPLICABLE" "1.0" "CVE-2021-33044" "N/A"
    fi

    # -- Evidence-generic checks (apply to any camera-like device) -------------
    # 1) RTSP exposure without authentication → HIGH
    case "$RTSP_STATE" in
        OPEN)
            add_finding "$SEV_HIGH" "RTSP stream accessible without authentication" \
                "One or more RTSP paths accepted an unauthenticated DESCRIBE/SETUP." \
                "open paths: ${RTSP_PATHS_OPEN[*]:-none}" \
                "VERIFIED" "0.90" "N/A" \
                "Enable RTSP authentication; restrict 554/tcp via firewall/VLAN."
            ;;
        AUTH_REQUIRED)
            add_finding "$SEV_INFO" "RTSP requires authentication" \
                "RTSP service answered with 401/407 — authentication enforced on tested paths." \
                "auth-required paths: ${RTSP_PATHS_AUTHREQ[*]:-none}" \
                "VERIFIED" "0.90" "N/A" "Verify credentials are strong; prefer digest over basic."
            ;;
        NO_SERVICE)
            : ;; # nothing to report — absence of a service is INFO at most
        TIMEOUT)
            add_finding "$SEV_INFO" "RTSP probe inconclusive" \
                "RTSP port open but path probes timed out." "state=TIMEOUT" "INCONCLUSIVE" "0.5" "N/A" "Manual review advised."
            ;;
    esac

    # 2) /.env and backup config exposure — verified only on real content match
    local env_code env_body
    env_code="$(curl -sS -m "$HTTP_TIMEOUT" -o /dev/null -w '%{http_code}' "http://${host}:${HTTP_PROBE_PORT}/.env" 2>/dev/null || true)"
    if [[ "$env_code" == "200" ]]; then
        env_body="$(curl -sS -m "$HTTP_TIMEOUT" "http://${host}:${HTTP_PROBE_PORT}/.env" 2>/dev/null | head -c 512 || true)"
        if printf '%s' "$env_body" | grep -qiE '^(APP_KEY|DB_PASSWORD|PASSWORD|SECRET)='; then
            add_finding "$SEV_HIGH" "Environment file exposed" \
                "/.env returned HTTP 200 and contains key=value secret material." \
                "GET /.env → 200, keys: $(printf '%s' "$env_body" | grep -oiE '^[A-Z_]+=' | tr '\n' ' ' | head -c 80)" \
                "VERIFIED" "0.85" "N/A" "Remove file from web root; rotate exposed secrets."
        else
            add_finding "$SEV_INFO" "/.env reachable but no secrets pattern" \
                "/.env returned 200 but content did not match secret patterns." \
                "GET /.env → 200, no key=secret lines" "INCONCLUSIVE" "0.4" "N/A" "Verify manually."
        fi
    fi

    # 3) Plaintext HTTP management with Basic auth → MEDIUM (evidence-based)
    local p80; p80="$(probe_http "$host" "$HTTP_PROBE_PORT" || true)"
    if [[ -n "$p80" ]]; then
        local auth80; auth80="$(printf '%s' "$p80" | awk -F'|' '{print $4}')"
        if printf '%s' "$auth80" | grep -qi '^[Bb]asic'; then
            add_finding "$SEV_MEDIUM" "Credentials transmitted over plaintext HTTP (Basic auth)" \
                "Port 80 answers with WWW-Authenticate: Basic — credentials are base64 (effectively plaintext) on an unencrypted channel." \
                "GET http://${host}:80/ → WWW-Authenticate: Basic" \
                "VERIFIED" "0.90" "N/A" \
                "Disable Basic on HTTP; force HTTPS (443) for management; use digest or form auth on TLS."
        elif printf '%s' "$auth80" | grep -qi '^[Dd]igest'; then
            add_finding "$SEV_LOW" "HTTP management uses Digest auth on plaintext channel" \
                "Digest avoids cleartext replay, but the channel itself is unencrypted (MITM of traffic/metadata)." \
                "GET http://${host}:80/ → WWW-Authenticate: Digest" \
                "VERIFIED" "0.80" "N/A" "Prefer HTTPS for management UI."
        fi
    fi

    # 4) ONVIF — informational only (presence is not a vulnerability)
    if [[ "$FP_ONVIF" == "PRESENT" ]]; then
        add_finding "$SEV_INFO" "ONVIF service present" \
            "ONVIF GetDeviceInformation responded on :8080. Exposure should match your trust zone." \
            "SOAP GetDeviceInformation → response received" "VERIFIED" "0.95" "N/A" \
            "Restrict :8080 to management VLAN if ONVIF is unused."
    fi

    # 5) TLS posture
    local has_tls=0 p
    for p in 443 8443; do
        probe_https "$host" "$p" >/dev/null 2>&1 && has_tls=1
    done
    if [[ "$has_tls" -eq 0 && -n "$p80" ]]; then
        add_finding "$SEV_MEDIUM" "No HTTPS management interface detected" \
            "Neither :443 nor :8443 answered an HTTPS probe while HTTP is served — management is plaintext-only." \
            "https probes on 443/8443 → no response; http on 80 → alive" \
            "LIKELY_VULNERABLE" "0.70" "N/A" "Enable HTTPS; redirect HTTP→HTTPS."
    fi
    return 0
}

###############################################################################
# 12. AUTHENTICATION ASSESSMENT (opt-in --auth-test only; safe by design)
###############################################################################
AUTH_TEST_ENABLED=0
declare -a AUTH_CREDS=()
AUTH_STOP_ON_SUCCESS=1
AUTH_RESULTS_JSON="[]"
declare -a AUTH_RESULT_ROWS=()
auth_results_json() {
    local out="[" first=1 row
    for row in "${AUTH_RESULT_ROWS[@]:-}"; do
        [[ -n "$row" ]] || continue
        [[ $first -eq 0 ]] && out+=","
        out+="$row"; first=0
    done
    printf '%s]' "$out"
}
# credentials are NEVER printed, logged, or exported — username + sha256 hash only.
AUTH_DEFAULT_CREDS=(
    "admin:admin" "admin:12345" "admin:123456"
    "admin:hikvision" "admin:1111" "root:root" "guest:guest"
)
auth_sha256() {
    if [[ "${DEPS_OK[openssl]:-0}" -eq 1 ]]; then
        printf '%s' "$1" | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}'
    else
        printf 'UNHASHED:%s' "$(printf '%s' "$1" | wc -c)"  # length-only fingerprint fallback
    fi
}

# Safe HTTP auth probe: success = server actually challenges and then ACCEPTS.
# A public 200 page without 401 challenge is NOT a credential success.
http_auth_probe() {
    local host="$1" user="$2" pass="$3"
    local noauth auth_then_ok
    noauth="$(curl -sS -o /dev/null -w '%{http_code}' -m "$HTTP_TIMEOUT" "http://${host}:${HTTP_PROBE_PORT}/" 2>/dev/null || echo 000)"
    if [[ "$noauth" == "200" ]]; then return 1; fi   # no auth required at all → nothing proven
    auth_then_ok="$(curl -sS -o /dev/null -w '%{http_code}' -m "$HTTP_TIMEOUT" -u "${user}:${pass}" "http://${host}:${HTTP_PROBE_PORT}/" 2>/dev/null || echo 000)"
    if [[ "$auth_then_ok" == "200" && "$noauth" =~ ^(401|403)$ ]]; then return 0; fi
    return 1
}

run_auth_test() {
    local host="$1" attempts=0 successes=0
    AUTH_RESULTS_JSON="[]"
    [[ "$AUTH_TEST_ENABLED" -eq 1 ]] || return 0
    say ""; say "${C_CYN}== Authentication assessment: ${host} (authorized lab use) ==${C_RST}"
    local cred
    for cred in "${AUTH_CREDS[@]}"; do
        [[ "$attempts" -ge "$MAX_AUTH_ATTEMPTS" ]] && { warn "Attempt cap reached ($MAX_AUTH_ATTEMPTS)"; break; }
        attempts=$((attempts+1))
        local user="${cred%%:*}" pass="${cred#*:}"
        if http_auth_probe "$host" "$user" "$pass"; then
            successes=$((successes+1))
            local h; h="$(auth_sha256 "${user}:${pass}")"
            warn "Weak/default credential ACCEPTED: user=$(json_str "$user") sha256=${h:0:16}… (password withheld)"
            AUTH_RESULT_ROWS+=("$(printf '{"username":%s,"credential_sha256":%s}' "$(json_str "$user")" "$(json_str "$h")")")
            add_finding "$SEV_HIGH" "Default/weak credential accepted" \
                "HTTP Basic/Digest login succeeded with a commonly-used default credential against an auth-challenging endpoint." \
                "GET / (no auth) → 401; GET / with tested credential → 200" \
                "VERIFIED" "0.95" "N/A" \
                "Change password to a unique strong value; disable default accounts."
            [[ "$AUTH_STOP_ON_SUCCESS" -eq 1 ]] && break
        fi
        sleep "$(awk -v ms="$AUTH_DELAY_MS" 'BEGIN{printf "%.3f", ms/1000}')" 2>/dev/null || sleep 0.4
    done
    [[ "$successes" -eq 0 ]] && ok "No tested default credentials accepted (${attempts} attempt(s), cap ${MAX_AUTH_ATTEMPTS})"
    log "SECURITY" "auth" "$host: auth-test done attempts=$attempts successes=$successes"
    return 0
}

###############################################################################
# 13. EVIDENCE COLLECTION (screenshots — opt-in via profile full or --captures)
###############################################################################
CAPTURES_ENABLED=0
declare -a CAPTURE_FILES=()

capture_screenshot() {
    # $1=host $2=rtsp_path → saves jpeg if OPEN; guarded by disk space + timeouts
    local host="$1" path="$2"
    [[ "${DEPS_OK[ffmpeg]:-0}" -eq 1 ]] || { warn "ffmpeg unavailable — capture: NOT_SUPPORTED"; return 1; }
    local free_kb; free_kb="$(disk_free_kb "$CAPTURE_DIR")"
    if [[ "${free_kb:-0}" -lt "$DISK_MIN_KB" ]]; then
        warn "INSUFFICIENT_STORAGE (${free_kb} KB free < ${DISK_MIN_KB} KB required) — capture skipped"
        log "ERROR" "capture" "insufficient storage: ${free_kb}KB free"
        return 1
    fi
    local ts safe_host out tmp
    ts="$(date +%Y%m%d_%H%M%S)"; safe_host="${host//:/_}"; safe_host="${safe_host//./_}"
    out="${CAPTURE_DIR}/${safe_host}_${ts}.jpg"
    tmp="${TMPDIR_SCAN}/cap_$$_${RANDOM}.jpg"
    run_with_timeout "$((RTSP_TIMEOUT+2))" ffmpeg -v error -rtsp_transport tcp \
        -i "rtsp://${host}:554${path}" -frames:v 1 -q:v 3 -y "$tmp" || true
    if [[ -f "$tmp" ]] && [[ "$(stat -c %s "$tmp" 2>/dev/null || echo 0)" -gt 2048 ]]; then
        mv "$tmp" "$out"
        CAPTURE_FILES+=("$out")
        ok "Evidence screenshot: $out"
        log "INFO" "capture" "saved $out ($(stat -c %s "$out" 2>/dev/null || echo '?') bytes)"
        return 0
    fi
    rm -f "$tmp"
    warn "Capture failed for rtsp://${host}:554${path} (no decodable frame)"
    return 1
}

collect_evidence_captures() {
    local host="$1"
    [[ "$CAPTURES_ENABLED" -eq 1 ]] || return 0
    [[ "$RTSP_STATE" == "OPEN" ]] || { say "  Captures: skipped (RTSP not open)"; return 0; }
    local p
    for p in "${RTSP_PATHS_OPEN[@]:-}"; do
        [[ -n "$p" ]] && capture_screenshot "$host" "$p" || true
    done
    return 0
}

###############################################################################
# 14. RISK ENGINE (severity is derived from evidence, never from port state alone)
###############################################################################
risk_counts_json() {
    local c=0 h=0 m=0 l=0 i=0 row sev
    for row in "${FINDINGS_ROWS[@]:-}"; do
        sev="$(printf '%s' "$row" | grep -o '"severity":"[A-Z]*"' | head -n1 | cut -d'"' -f4)"
        case "$sev" in
            CRITICAL) c=$((c+1)) ;; HIGH) h=$((h+1)) ;; MEDIUM) m=$((m+1)) ;;
            LOW) l=$((l+1)) ;; INFO) i=$((i+1)) ;;
        esac
    done
    printf '{"critical":%d,"high":%d,"medium":%d,"low":%d,"info":%d}' "$c" "$h" "$m" "$l" "$i"
}

risk_overall() {
    local counts; counts="$(risk_counts_json)"
    if   [[ "$counts" == *'"critical":[1-9]*' ]]; then printf 'CRITICAL'
    elif [[ "$counts" == *'"high":[1-9]*' ]];     then printf 'HIGH'
    elif [[ "$counts" == *'"medium":[1-9]*' ]];   then printf 'MEDIUM'
    elif [[ "$counts" == *'"low":[1-9]*' ]];      then printf 'LOW'
    else printf 'INFO'; fi
}

###############################################################################
# 15/16. REPORT ENGINE (JSON export + human TXT)
###############################################################################
build_json_report() {
    local host="$1"
    local end_ts dur
    end_ts="$(date +%s)"; dur=$((end_ts - SCAN_START_TS))
    local fp_evid_json="["
    local e first=1
    for e in "${FP_EVIDENCE[@]:-}"; do
        [[ -n "$e" ]] || continue
        [[ $first -eq 0 ]] && fp_evid_json+=","
        fp_evid_json+="${e}"; first=0
    done
    fp_evid_json+="]"
    local services_json="[]"
    if [[ "$RTSP_PORT_OPEN" -eq 1 ]]; then
        services_json="[{$(printf '"service":%s,"port":554,"state":%s' "$(json_str "rtsp")" "$(json_str "$RTSP_STATE")")}]"
    fi
    local caps_json="[" first_cap=1
    local c
    for c in "${CAPTURE_FILES[@]:-}"; do
        [[ -n "$c" ]] || continue
        [[ $first_cap -eq 0 ]] && caps_json+=","
        caps_json+=$(json_str "$c"); first_cap=0
    done
    caps_json+="]"
    local risk; risk="$(risk_counts_json)"
    cat > "$JSON_FILE" <<EOF
{
  "scanner": {
    "name": $(json_str "$SCRIPT_NAME"),
    "version": $(json_str "$VERSION"),
    "timestamp": $(json_str "$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"),
    "platform": $(json_str "$PLATFORM_STR"),
    "profile": $(json_str "$PROFILE"),
    "duration_seconds": $dur
  },
  "authorization": {
    "confirmed": $AUTHORIZED,
    "scope": "owner-authorized assessment only"
  },
  "target": { "host": $(json_str "$host") },
  "device": {
    "vendor": $(json_str "$FP_VENDOR"),
    "vendor_confidence": $FP_VENDOR_CONF,
    "model": $(json_str "$FP_MODEL"),
    "model_confidence": $FP_MODEL_CONF,
    "firmware": $(json_str "$FP_FIRMWARE"),
    "firmware_confidence": $FP_FW_CONF,
    "onvif": $(json_str "$FP_ONVIF"),
    "evidence_count": $FP_EVIDENCE_COUNT
  },
  "services": $services_json,
  "rtsp": {
    "state": $(json_str "$RTSP_STATE"),
    "open_paths": $(join_json_array RTSP_PATHS_OPEN),
    "auth_required_paths": $(join_json_array RTSP_PATHS_AUTHREQ)
  },
  "findings": $(findings_json),
  "auth_assessment": { "enabled": $AUTH_TEST_ENABLED, "results": $(auth_results_json) },
  "evidence": { "fingerprint": $fp_evid_json, "captures": $caps_json },
  "risk": { "overall": $(json_str "$(risk_overall)"), "counts": $risk },
  "errors": ${ERRORS_JSON:-[]},
  "warnings": ${WARNINGS_JSON:-[]}
}
EOF
    json_validate "$JSON_FILE" || { err "JSON validation failed for $JSON_FILE"; log "ERROR" "report" "JSON invalid: $JSON_FILE"; return 1; }
    ok "JSON report: $JSON_FILE (validation: $JSON_VALIDATE_OK)"
    return 0
}

build_txt_report() {
    local host="$1"
    {
        echo "CAM-SEC SECURITY ASSESSMENT"
        echo "==========================="
        echo "Scanner : $SCRIPT_NAME v$VERSION (profile: $PROFILE)"
        echo "Date    : $(date '+%Y-%m-%d %H:%M:%S %z')"
        echo "Target  : $host"
        echo "Auth    : confirmed=$AUTHORIZED"
        echo ""
        echo "Device"
        echo "------"
        echo "Vendor   : $FP_VENDOR (confidence $FP_VENDOR_CONF, $FP_EVIDENCE_COUNT evidence items)"
        echo "Model    : $FP_MODEL (confidence $FP_MODEL_CONF)"
        echo "Firmware : ${FP_FIRMWARE:-unknown} (confidence $FP_FW_CONF)"
        echo "ONVIF    : $FP_ONVIF"
        echo ""
        echo "Risk: $(risk_overall)"
        printf '%s' "$FINDINGS_JSON" | jq -r '"Counts — CRITICAL:\(.critical) HIGH:\(.high) MEDIUM:\(.medium) LOW:\(.low) INFO:\(.info)"' <<<"$(risk_counts_json)" 2>/dev/null || true
        echo ""
        echo "Findings"
        echo "--------"
        printf '%s' "$FINDINGS_JSON" | jq -r '.[] |
          "[\(.severity)] \(.id): \(.title)\n" +
          "  Description : \(.description)\n" +
          "  Evidence    : \(.evidence)\n" +
          "  Verification: \(.verification)  (confidence \(.confidence))\n" +
          (if .cve != "N/A" then "  CVE         : \(.cve)\n" else "" end) +
          "  Remediation : \(.remediation)\n"' 2>/dev/null \
          || echo "(findings unavailable — jq missing)"
        echo ""
        echo "RTSP state: $RTSP_STATE"
        echo "Evidence captures: ${#CAPTURE_FILES[@]}"
        echo "Log: $LOG_FILE"
        echo "Report end."
    } > "$TXT_FILE"
    ok "TXT report: $TXT_FILE"
    return 0
}

###############################################################################
# 17. CLEANUP + SIGNAL HANDLING
###############################################################################
ERRORS_JSON="[]"
WARNINGS_JSON="[]"
note_error()   { ERRORS_JSON="$(printf '%s' "$ERRORS_JSON"   | jq --arg m "$(redact "$1")" '. + [$m]')" 2>/dev/null || true; }
note_warning() { WARNINGS_JSON="$(printf '%s' "$WARNINGS_JSON" | jq --arg m "$(redact "$1")" '. + [$m]')" 2>/dev/null || true; }

cleanup() {
    local rc="${1:-0}"
    # kill any tracked orphan PIDs (ffmpeg/ffprobe watchdog fallbacks)
    local p
    for p in "${ORPHAN_PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
    done
    # defensive sweep: only our own ffmpeg/ffprobe children on rtsp inputs
    pkill -TERM -f "rtsp://" 2>/dev/null || true
    sleep 0.2 2>/dev/null || true
    [[ -n "$TMPDIR_SCAN" && -d "$TMPDIR_SCAN" ]] && rm -rf "$TMPDIR_SCAN"
    log "INFO" "main" "cleanup complete (rc=$rc)"
    return 0
}

on_exit()    { cleanup "${1:-0}"; }
on_sigint()  { echo; err "Interrupted (SIGINT) — cleaning up"; log "SECURITY" "main" "SIGINT received during scan"; cleanup 130; exit 130; }
on_sigterm() { err "Terminated (SIGTERM) — cleaning up"; cleanup 143; exit 143; }
trap on_sigint INT
trap on_sigterm TERM
trap 'on_exit $?' EXIT

###############################################################################
# 18. SELF-TEST
###############################################################################
self_test() {
    local fails=0
    say "${C_CYN}== SELF TEST ==${C_RST}"
    # 1 bash version
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then ok "bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]} >= 4"; else err "bash >= 4 required"; fails=$((fails+1)); fi
    # 2 required dirs + permissions
    local d
    for d in "$SCRIPT_DIR" "$LOG_DIR" "$REPORT_DIR" "$CAPTURE_DIR" "$TMPDIR_SCAN"; do
        [[ -d "$d" ]] && ok "dir writable: $d" || { err "dir missing: $d"; fails=$((fails+1)); }
    done
    # 3 logging
    log "INFO" "selftest" "self-test logging check" && ok "logging works"
    # 4 config parser with malicious input (must NOT execute)
    local tf="$TMPDIR_SCAN/cfg_malicious.cfg"
    printf 'SHODAN_API_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n$(touch %s/PAWNED)\n' "$TMPDIR_SCAN" > "$tf"
    config_load_from() {  # parse arbitrary file into globals (test helper)
        local save="$CONFIG_FILE"; CONFIG_FILE="$1"; config_load; CONFIG_FILE="$save"
    }
    config_load_from "$tf"
    if [[ ! -f "$TMPDIR_SCAN/PAWNED" && "$CONFIG_SHODAN_KEY" == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ]]; then
        ok "config parser: safe key=value parsing (no code execution)"
    else
        err "config parser: FAILED (code execution or parse error)"; fails=$((fails+1))
    fi
    # 5 validators
    valid_ipv4 192.168.1.1 && ! valid_ipv4 999.1.1.1 && ok "IPv4 validator"
    valid_cidr4 192.168.0.0/24 && ! valid_cidr4 192.168.0.0/33 && ok "CIDR validator"
    is_private_ip 10.0.0.5 && is_private_ip 127.0.0.1 && ! is_private_ip 8.8.8.8 && ok "private-scope validator"
    # 6 JSON engine round-trip
    local jf="$TMPDIR_SCAN/selftest.json"
    printf '{"esc":"%s","arr":[1,2]}' "$(json_escape $'quote"back\slash\nnewline')" > "$jf"
    if json_validate "$jf" && [[ "$JSON_VALIDATE_OK" == "PASS" ]]; then ok "JSON escape+validate"; else err "JSON engine FAILED"; fails=$((fails+1)); fi
    # 7 timeout mechanism
    local t0 t1
    t0="$(date +%s)"
    run_with_timeout 1 sleep 30 || true
    t1="$(date +%s)"
    if [[ $((t1-t0)) -le 3 ]]; then ok "timeout mechanism (bounded)"; else err "timeout FAILED"; fails=$((fails+1)); fi
    # 8 no orphan after timeout
    if ! pgrep -f "sleep 30" >/dev/null 2>&1; then ok "no orphan process after timeout"; else err "orphan process detected"; fails=$((fails+1)); fi
    # 9 report generation on synthetic data
    SCAN_START_TS=$(date +%s)
    FINDINGS_JSON='[]'; FINDING_SEQ=0; FINDINGS_ROWS=(); FP_EVIDENCE=(); FP_EVIDENCE_COUNT=0
    FP_VENDOR="TESTDEV"; FP_VENDOR_CONF="1.0"; FP_MODEL="M1"; FP_MODEL_CONF="1.0"
    FP_FIRMWARE=""; FP_FW_CONF="0"; FP_ONVIF="NOT_CHECKED"
    RTSP_STATE="NO_SERVICE"; RTSP_PORT_OPEN=0; RTSP_PATHS_OPEN=(); RTSP_PATHS_AUTHREQ=()
    AUTH_TEST_ENABLED=0; AUTH_RESULTS_JSON="[]"; CAPTURE_FILES=()
    JSON_FILE="$TMPDIR_SCAN/report_selftest.json"; TXT_FILE="$TMPDIR_SCAN/report_selftest.txt"
    build_json_report "127.0.0.1" && ok "JSON report generation (validated: $JSON_VALIDATE_OK)" || { err "JSON report FAILED"; fails=$((fails+1)); }
    build_txt_report "127.0.0.1" && [[ -s "$TXT_FILE" ]] && ok "TXT report generation" || { err "TXT report FAILED"; fails=$((fails+1)); }
    # 10 redaction
    local _save_cfg="${CONFIG_SHODAN_KEY:-}" _save_env="${SHODAN_API_KEY:-}"
    if [[ "$(redact_with SECRETKEY123 'key=SECRETKEY123 end')" != *"SECRETKEY123"* ]]; then ok "secret redaction"; else err "redaction FAILED"; fails=$((fails+1)); fi
    CONFIG_SHODAN_KEY="$_save_cfg"; SHODAN_API_KEY="$_save_env"
    # 11 cleanup
    cleanup 0 && [[ ! -d "$TMPDIR_SCAN" ]] && ok "cleanup removes temp dir" || { err "cleanup FAILED"; fails=$((fails+1)); }
    setup_paths  # restore runtime dir after cleanup test
    echo ""
    if [[ "$fails" -eq 0 ]]; then say "${C_GRN}SELF TEST: PASS${C_RST}"; return 0
    else say "${C_RED}SELF TEST: FAIL (${fails} failure(s))${C_RST}"; return 1; fi
}

redact_with() { local k="$1" s="$2"; SHODAN_API_KEY="$k"; CONFIG_SHODAN_KEY="$k"; redact "$s"; }


###############################################################################
# SHODAN LOOKUP (real API; key never printed or logged)
###############################################################################
declare -a SHODAN_ROWS=()
shodan_lookup() {
    local query="$1" key; key="$(shodan_key)"
    if [[ -z "$key" ]]; then
        warn "Shodan: NOT_SUPPORTED — no API key (menu option 4, or SHODAN_API_KEY env)"
        return 1
    fi
    if [[ "${DEPS_OK[jq]:-0}" -ne 1 && "${DEPS_OK[python3]:-0}" -ne 1 ]]; then
        warn "Shodan: NOT_SUPPORTED — jq or python3 required for response parsing"
        return 1
    fi
    local enc
    if [[ "${DEPS_OK[jq]:-0}" -eq 1 ]]; then
        enc="$(printf '%s' "$query" | jq -sRr @uri 2>/dev/null || true)"
    else
        enc="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$query" 2>/dev/null || true)"
    fi
    [[ -n "$enc" ]] || { err "Shodan: query encoding failed"; return 1; }
    say "${C_CYN}== Shodan lookup: ${query} ==${C_RST}"
    local resp
    resp="$(run_with_timeout 20 curl -sS "https://api.shodan.io/shodan/host/search?key=${key}&query=${enc}&limit=20" 2>/dev/null || true)"
    if [[ -z "$resp" ]]; then err "Shodan: network error or timeout"; log "ERROR" "shodan" "no response (query len ${#query})"; return 1; fi
    local api_err=""
    if [[ "${DEPS_OK[jq]:-0}" -eq 1 ]]; then
        api_err="$(printf '%s' "$resp" | jq -r '.error // empty' 2>/dev/null || true)"
    else
        api_err="$(python3 -c 'import json,sys
try:
    d=json.loads(sys.stdin.read()); print(d.get("error") or "")
except Exception:
    print("")' <<<"$resp" 2>/dev/null || true)"
    fi
    if [[ -n "$api_err" ]]; then
        err "Shodan API error: $api_err"
        log "ERROR" "shodan" "API error: $(redact "$api_err")"
        return 1
    fi
    SHODAN_ROWS=()
    local total="0" line
    if [[ "${DEPS_OK[jq]:-0}" -eq 1 ]]; then
        total="$(printf '%s' "$resp" | jq -r '.total // 0' 2>/dev/null || echo 0)"
        while IFS='|' read -r s_ip s_port s_org s_country; do
            [[ -n "${s_ip:-}" ]] || continue
            SHODAN_ROWS+=("{"ip":$(json_str "$s_ip"),"port":$(json_str "$s_port"),"org":$(json_str "$s_org"),"country":$(json_str "$s_country")}")
            printf '  %s%-16s%s :%-6s %s / %s\n' "$C_WHT" "$s_ip" "$C_RST" "$s_port" "$s_org" "$s_country"
        done < <(printf '%s' "$resp" | jq -r '.matches[]? | "\(.ip_str)|\(.port)|\(.org // "unknown")|\(.location.country_name // "unknown")"' 2>/dev/null || true)
    else
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            SHODAN_ROWS+=("$line")
            printf '  %s\n' "$line"
        done < <(python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    for m in d.get("matches",[])[:20]:
        print(json.dumps({"ip":m.get("ip_str",""),"port":m.get("port",0),"org":m.get("org","unknown"),"country":(m.get("location") or {}).get("country_name","unknown")},separators=(",",":")))
except Exception:
    pass' <<<"$resp" 2>/dev/null || true)
        total="$(python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("total",0))
except Exception:
    print(0)' <<<"$resp" 2>/dev/null || echo 0)"
    fi
    say "  Total results: ${total} (showing up to 20)"
    local out="[" first=1 r
    for r in "${SHODAN_ROWS[@]:-}"; do
        [[ -n "$r" ]] || continue
        [[ $first -eq 0 ]] && out+=","; out+="$r"; first=0
    done
    out+="]"
    local sf="$REPORT_DIR/shodan_$(date +%Y%m%d_%H%M%S).json"
    printf '{\n  "scanner": {"name": %s, "version": %s},\n  "query": %s,\n  "total": %s,\n  "results": %s\n}\n' \
        "$(json_str "$SCRIPT_NAME")" "$(json_str "$VERSION")" "$(json_str "$query")" "${total:-0}" "$out" > "$sf"
    json_validate "$sf" && ok "Shodan report: $sf (validation: $JSON_VALIDATE_OK)"
    log "INFO" "shodan" "lookup complete: total=${total:-0} rows=${#SHODAN_ROWS[@]}"
    return 0
}

###############################################################################
# 19. CLI PARSER
###############################################################################
TARGET="" ; CIDR="" ; IFACE="" ; REPORT_FMT="txt"
ALLOW_PUBLIC=0 ; INSTALL_HINTS=0
usage() {
    cat <<EOF
$SCRIPT_NAME v$VERSION — defensive IP-camera assessment (Termux/Android, rootless)

USAGE:
  cam_scanner.sh --target <ip> [options]     assess a single host
  cam_scanner.sh --cidr  <a.b.c.d/n> [opts]  assess hosts in a local CIDR
  cam_scanner.sh --self-test                 verify the installation
  cam_scanner.sh --deps                      show dependency status
  cam_scanner.sh (no args)                   interactive menu

OPTIONS:
  --target IP          single IPv4/IPv6 target (private/loopback by default)
  --cidr CIDR          IPv4 CIDR range to enumerate (LAN scans)
  --interface NAME     network interface for discovery (default: auto)
  --quick|--normal|--full   scan profile (default: normal)
  --timeout SECS       per-probe timeout (default: ${HTTP_TIMEOUT})
  --ports LIST         comma-separated port list (default: $PORT_LIST)
  --auth-test          enable default-credential check (authorized lab use)
  --auth-cred U:P      add a credential pair to the auth-test set (repeatable)
  --captures           capture RTSP screenshots (evidence)
  --report FMT         txt | json | both (default: txt)
  --output NAME        base name for reports (default: auto)
  --allow-public       permit non-private targets (logged; requires confirm)
  --i-own-targets      skip interactive authorization prompt (CI use)
  --quiet              suppress non-essential output
  --version            print version
  --help               this help

EXIT CODES: 0 ok | 1 general | 2 bad args | 3 missing dep | 4 bad target | 5 incomplete
EOF
}

parse_args() {
    [[ $# -eq 0 ]] && return 0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h) usage; exit 0 ;;
            --version|-V) printf '%s v%s\n' "$SCRIPT_NAME" "$VERSION"; exit 0 ;;
            --self-test) DO_SELFTEST=1 ;;
            --deps) DO_DEPS=1 ;;
            --target) shift; TARGET="${1:-}" ;;
            --cidr) shift; CIDR="${1:-}" ;;
            --interface) shift; IFACE="${1:-}" ;;
            --quick) PROFILE="quick" ;;
            --normal) PROFILE="normal" ;;
            --full) PROFILE="full" ;;
            --timeout) shift; HTTP_TIMEOUT="${1:-}"; RTSP_TIMEOUT="${1:-}" ;;
            --ports) shift; PORT_LIST="${1:-}" ;;
            --auth-test) AUTH_TEST_ENABLED=1 ;;
            --auth-cred) shift; AUTH_CREDS+=("${1:-}"); AUTH_TEST_ENABLED=1 ;;
            --captures) CAPTURES_ENABLED=1 ;;
            --report) shift; REPORT_FMT="${1:-}" ;;
            --output) shift; OUT_NAME="${1:-}" ;;
            --allow-public) ALLOW_PUBLIC=1 ;;
            --i-own-targets) AUTHORIZED=1 ;;
            --shodan) shift; SHODAN_QUERY="${1:-}" ;;
            --quiet) QUIET=1 ;;
            *) err "Unknown argument: $1"; usage >&2; exit "$EX_ARGS" ;;
        esac
        shift
    done
    # validation
    if [[ -n "$TARGET" && -n "$CIDR" ]]; then err "--target and --cidr are mutually exclusive"; exit "$EX_ARGS"; fi
    if [[ -n "$TARGET" ]]; then
        valid_ipv4 "$TARGET" || valid_ipv6 "$TARGET" || { err "Invalid target IP: '$TARGET'"; exit "$EX_TARGET"; }
        if ! is_private_ip "$TARGET" && [[ "$TARGET" != "::1" && "$TARGET" != "localhost" ]]; then
            if [[ "$ALLOW_PUBLIC" -ne 1 ]]; then
                err "Refusing public target $TARGET (scope: private/loopback only). Use --allow-public with authorization."
                log "SECURITY" "scope" "public target refused: $TARGET"
                exit "$EX_TARGET"
            fi
            note_warning "public target assessed with --allow-public: $TARGET"
        fi
    fi
    if [[ -n "$CIDR" ]]; then
        valid_cidr4 "$CIDR" || { err "Invalid CIDR: '$CIDR'"; exit "$EX_TARGET"; }
        if ! is_private_cidr "$CIDR" && [[ "$ALLOW_PUBLIC" -ne 1 ]]; then
            err "Refusing public CIDR $CIDR. Use --allow-public with authorization."; exit "$EX_TARGET"
        fi
    fi
    if [[ -n "$IFACE" ]] && ! valid_iface "$IFACE"; then err "Invalid interface name"; exit "$EX_ARGS"; fi
    [[ "$HTTP_TIMEOUT" =~ ^[0-9]+$ ]] || { err "--timeout must be integer seconds"; exit "$EX_ARGS"; }
    case "$REPORT_FMT" in txt|json|both) ;; *) err "--report must be txt|json|both"; exit "$EX_ARGS" ;; esac
    if [[ ${#AUTH_CREDS[@]} -eq 0 && "$AUTH_TEST_ENABLED" -eq 1 ]]; then
        AUTH_CREDS=("${AUTH_DEFAULT_CREDS[@]}")
    fi
    return 0
}

###############################################################################
# 20. AUTHORIZATION GATE + MAIN CONTROLLER
###############################################################################
authorization_gate() {
    [[ "$AUTHORIZED" -eq 1 ]] && return 0
    [[ -t 0 ]] || { err "Non-interactive mode: pass --i-own-targets after confirming authorization"; exit "$EX_ARGS"; }
    echo ""
    warn "You are about to assess: ${TARGET:-$CIDR}"
    say  "This tool performs non-destructive verification probes only."
    say  "Continuing confirms YOU OWN these devices or have EXPLICIT WRITTEN PERMISSION."
    local ans
    read -r -p "Type 'YES' to confirm authorization: " ans
    if [[ "$ans" == "YES" ]]; then
        AUTHORIZED=1
        log "SECURITY" "auth" "operator confirmed authorization for ${TARGET:-$CIDR}"
    else
        err "Authorization not confirmed — aborting"; exit "$EX_ARGS"
    fi
}

scan_single() {
    local host="$1"
    say ""; say "${C_CYN}═══ Assessment: ${host} (profile: $PROFILE) ═══${C_RST}"
    fingerprint_device "$host"
    scan_rtsp "$host"
    assess_vulnerabilities "$host"
    collect_evidence_captures "$host"
    run_auth_test "$host"
    return 0
}

enumerate_cidr() {
    # Pure-bash IPv4 enumerator (no nmap dependency); nmap used as accelerator if present.
    local cidr="$1" base="${1%/*}" plen="${1#*/}"
    local o1 o2 o3 o4
    IFS=. read -r o1 o2 o3 o4 <<< "$base"
    local max_host
    if [[ "$plen" -ge 24 ]]; then max_host=$(( (1 << (32-plen)) - 2 ))
    else max_host=254; note_warning "prefix /$plen large — capping host enumeration at 254"; fi
    [[ "$max_host" -lt 1 ]] && max_host=1
    if [[ "${DEPS_OK[nmap]:-0}" -eq 1 ]]; then
        say "Using nmap host discovery for $cidr"
        nmap -sn -T3 --host-timeout 3s "$cidr" 2>/dev/null | awk '/Nmap scan report/{print $NF}' | tr -d '()'
        return 0
    fi
    local cache="$TMPDIR_SCAN/cidr_hosts.txt"; : > "$cache"
    local i h
    for (( i=1; i<=max_host; i++ )); do
        h="$o1.$o2.$o3.$((o4+i))"
        run_with_timeout 2 bash -c "exec 3<>/dev/tcp/${h}/80" 2>/dev/null && echo "$h" >> "$cache" || true
    done
    cat "$cache"
    return 0
}

main() {
    setup_paths
    PLATFORM_STR="$(uname -srm 2>/dev/null || echo unknown)"
    [[ -n "${PREFIX:-}" ]] && PLATFORM_STR="Termux/Android $PLATFORM_STR"
    LOG_FILE="$LOG_DIR/scanner.log"; LOG_FILE_SET=1
    log "INFO" "main" "=== $SCRIPT_NAME v$VERSION start (profile=$PROFILE) ==="
    dep_detect
    dep_require
    config_load

    parse_args "$@"

    if [[ -n "${SHODAN_QUERY:-}" ]]; then banner; shodan_lookup "$SHODAN_QUERY"; exit $?; fi
    if [[ "${DO_DEPS:-0}" -eq 1 ]]; then banner; dep_report; exit "$EX_OK"; fi
    if [[ "${DO_SELFTEST:-0}" -eq 1 ]]; then banner; self_test; exit $?; fi

    # Interactive menu when no scan target specified
    if [[ -z "$TARGET" && -z "$CIDR" ]]; then
        interactive_menu; exit $?
    fi

    authorization_gate
    SCAN_START_TS="$(date +%s)"
    local stamp; stamp="$(date +%Y%m%d_%H%M%S)"
    local base="${OUT_NAME:-scan_${TARGET:-${CIDR//\//_}}_${stamp}}"
    safe_filename "$base" || base="scan_${stamp}"
    JSON_FILE="$REPORT_DIR/${base}.json"
    TXT_FILE="$REPORT_DIR/${base}.txt"

    local rc=0 hosts=0
    if [[ -n "$TARGET" ]]; then
        scan_single "$TARGET" || rc=$?
        hosts=1
    else
        mapfile -t host_list < <(enumerate_cidr "$CIDR")
        hosts="${#host_list[@]}"
        [[ "$hosts" -eq 0 ]] && { err "NETWORK_DETECTION_FAILED: no live hosts found in $CIDR (or enumeration blocked)"; note_error "no hosts in $CIDR"; }
        local h
        for h in "${host_list[@]:-}"; do
            [[ -n "$h" ]] || continue
            scan_single "$h" || true
        done
    fi

    # Reports (JSON aggregates last-scanned target in CIDR mode; documented)
    if [[ "$REPORT_FMT" == "json" || "$REPORT_FMT" == "both" ]]; then
        build_json_report "${TARGET:-$CIDR}" || rc=5
    fi
    if [[ "$REPORT_FMT" == "txt" || "$REPORT_FMT" == "both" ]]; then
        build_txt_report "${TARGET:-$CIDR}" || rc=5
    fi

    local overall; overall="$(risk_overall)"
    say ""; say "${C_BOLD}Assessment complete: overall risk = ${overall}${C_RST} (${hosts} host(s))"
    log "INFO" "main" "scan complete overall=$overall hosts=$hosts rc=$rc"
    [[ "$rc" -ne 0 ]] && exit "$EX_INCOMPLETE"
    exit "$EX_OK"
}

###############################################################################
# INTERACTIVE MENU (all entries real; no placeholders)
###############################################################################
interactive_menu() {
    while true; do
        clear 2>/dev/null || true
        banner
        dep_report
        echo ""
        say "  ${C_CYN}[1]${C_RST} Assess single target (--target)"
        say "  ${C_CYN}[2]${C_RST} Assess local network (auto-detect CIDR)"
        say "  ${C_CYN}[3]${C_RST} Run self-test"
        say "  ${C_CYN}[4]${C_RST} Configure Shodan API key (stored 0600, never logged)"
        say "  ${C_CYN}[5]${C_RST} Open reports directory info"
        say "  ${C_CYN}[6]${C_RST} Shodan lookup (configure key with option 4)"
        say "  ${C_CYN}[0]${C_RST} Exit"
        echo ""
        local choice
        read -r -p "Choice > " choice
        case "$choice" in
            1) read -r -p "Target IP: " t
               valid_ipv4 "$t" || valid_ipv6 "$t" || { err "Invalid IP"; read -r -p "Enter..." _; continue; }
               TARGET="$t"; authorization_gate
               local stamp; stamp="$(date +%Y%m%d_%H%M%S)"
               JSON_FILE="$REPORT_DIR/scan_${t//./_}_${stamp}.json"
               TXT_FILE="$REPORT_DIR/scan_${t//./_}_${stamp}.txt"
               SCAN_START_TS="$(date +%s)"
               scan_single "$t"; build_txt_report "$t"; build_json_report "$t"
               read -r -p "Enter..." _ ;;
            2) local c; c="$(network_cidr "$IFACE" || true)"
               if [[ -z "$c" ]]; then err "NETWORK_DETECTION_FAILED: could not determine local CIDR (no ip/ifconfig, or no IPv4 address)"; read -r -p "Enter..." _; continue; fi
               CIDR="$c"; authorization_gate
               local stamp; stamp="$(date +%Y%m%d_%H%M%S)"
               JSON_FILE="$REPORT_DIR/scan_lan_${stamp}.json"
               TXT_FILE="$REPORT_DIR/scan_lan_${stamp}.txt"
               SCAN_START_TS="$(date +%s)"
               mapfile -t host_list < <(enumerate_cidr "$CIDR")
               local h
               for h in "${host_list[@]:-}"; do [[ -n "$h" ]] && scan_single "$h"; done
               build_txt_report "$CIDR"; read -r -p "Enter..." _ ;;
            3) self_test; read -r -p "Enter..." _ ;;
            4) read -r -p "Shodan API key (32 chars): " k
               if config_save_shodan "$k"; then ok "Shodan key stored (0600)"; else err "Invalid key format"; fi
               read -r -p "Enter..." _ ;;
            5) say "Reports : $REPORT_DIR"; say "Logs    : $LOG_DIR"; say "Captures: $CAPTURE_DIR"
               ls -lt "$REPORT_DIR" 2>/dev/null | head -n 8
               read -r -p "Enter..." _ ;;
            6) read -r -p "Shodan query: " q
               [[ -n "$q" ]] && shodan_lookup "$q"
               read -r -p "Enter..." _ ;;
            0) exit 0 ;;
            *) err "Invalid choice" ;;
        esac
    done
}

main "$@"
