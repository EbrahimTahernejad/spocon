#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# spocon installer
#
#   # Online (default): pull latest release from GitHub
#   bash <(curl -fsSL https://raw.githubusercontent.com/ebrahimtahernejad/spocon/main/install.sh)
#
#   # Online, pinned to a specific release tag
#   bash <(curl -fsSL https://raw.githubusercontent.com/ebrahimtahernejad/spocon/main/install.sh) v0.1.1
#
#   # Offline: use a tarball already present on disk (no network needed
#   # beyond reaching this script). The arg is auto-detected as a file
#   # path if it exists on disk; otherwise it's treated as a release tag.
#   sudo ./install.sh ./spocon-0.1.1-x86_64-unknown-linux-musl.tar.gz
#
# - Downloads the static x86_64 / aarch64 musl binary from the GitHub
#   release matching the optional `[tag]` argument (default: latest), or
#   uses a local tarball when one is passed in.
# - Asks role (server / client), pipe speed, and connection params.
# - Tunes sysctls, drops conntrack on the relay port, writes a systemd
#   unit, and starts the service.
# - Re-running the installer remembers the last answers (defaults pulled
#   from /etc/spocon/<role>.env).
#
# Override the source repo at runtime:
#   SPOCON_REPO=myuser/spocon bash <(curl ...) v0.1.1
# -----------------------------------------------------------------------------

set -euo pipefail

# ---- config ------------------------------------------------------------------
REPO="${SPOCON_REPO:-ebrahimtahernejad/spocon}"

# First arg is either:
#   - a path to a local .tar.gz (offline install), OR
#   - a release tag like `v0.1.1` / `latest` (online install).
# The two are disambiguated by checking whether the arg points at an
# existing file on disk.
ARG1="${1:-}"
LOCAL_TARBALL=""
if [[ -n "$ARG1" && -f "$ARG1" ]]; then
    LOCAL_TARBALL=$(readlink -f -- "$ARG1")
    TAG="offline"
elif [[ "$ARG1" == */* || "$ARG1" == *.tar.gz || "$ARG1" == *.tgz ]]; then
    printf '\033[1;31mTarball not found: %s\033[0m\n' "$ARG1" >&2
    exit 1
else
    TAG="${ARG1:-latest}"
fi

INSTALL_DIR=/usr/local/bin
SERVICE_DIR=/etc/systemd/system
SYSCTL_FILE=/etc/sysctl.d/99-spocon.conf
CONFIG_DIR=/etc/spocon
RP_SNAPSHOT=$CONFIG_DIR/rp_filter.snapshot

# Markers used to delimit any block we write into a *shared* config file
# (sysctl drop-in, /etc/sysctl.conf if we ever fall back to it, etc.) so
# that an uninstall / re-install can excise just our lines without
# clobbering anything the user added themselves.
MARK_BEGIN="# >>> spocon installer >>>"
MARK_END="# <<< spocon installer <<<"

# Make stdin point to the controlling tty even when launched via
# `bash <(curl ...)` or `curl ... | bash`.
if [[ ! -t 0 ]] && [[ -e /dev/tty ]]; then exec </dev/tty; fi

# ---- pretty -------------------------------------------------------------------
say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
hr()   { printf -- '─%.0s' $(seq 1 60); echo; }

require_root() { [[ $EUID -eq 0 ]] || { err "Must run as root"; exit 1; }; }

# ---- platform -----------------------------------------------------------------
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo x86_64-unknown-linux-musl ;;
        aarch64|arm64) echo aarch64-unknown-linux-musl ;;
        *) err "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

resolve_tag() {
    if [[ "$TAG" == "latest" ]]; then
        TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
              | grep -oE '"tag_name":\s*"[^"]+"' \
              | head -n1 | cut -d'"' -f4)
    fi
    [[ -n "${TAG:-}" ]] || { err "Could not resolve release tag from $REPO"; exit 1; }
    say "Using release: $TAG"
}

# Install the two binaries. In offline mode (`LOCAL_TARBALL` set) the
# tarball is taken from disk; otherwise we fetch it from the release
# matching `$TAG` for the current architecture.
install_binaries() {
    local tmp; tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    local archive=""

    if [[ -n "$LOCAL_TARBALL" ]]; then
        say "Installing from local tarball: $LOCAL_TARBALL"
        archive="$LOCAL_TARBALL"
    else
        local target; target=$(detect_arch)
        resolve_tag
        local ver=${TAG#v}
        local fname="spocon-$ver-$target.tar.gz"
        local url="https://github.com/$REPO/releases/download/$TAG/$fname"
        say "Downloading $url"
        curl -fsSL "$url" -o "$tmp/$fname" || { err "Download failed: $url"; exit 1; }
        archive="$tmp/$fname"
    fi

    tar -xzf "$archive" -C "$tmp" || { err "Failed to extract tarball: $archive"; exit 1; }

    # Locate the binaries anywhere inside the extracted tree so we accept
    # both the GitHub release layout (spocon-<ver>-<target>/spocon-*) and
    # any flat or differently-named user-built tarball.
    local sb cb
    sb=$(find "$tmp" -type f -name spocon-server -print -quit)
    cb=$(find "$tmp" -type f -name spocon-client -print -quit)
    [[ -n "$sb" && -n "$cb" ]] || {
        err "Tarball does not contain spocon-server / spocon-client binaries"
        exit 1
    }

    install -m 755 "$sb" "$INSTALL_DIR/spocon-server"
    install -m 755 "$cb" "$INSTALL_DIR/spocon-client"
    ok "Binaries installed to $INSTALL_DIR/spocon-{server,client}"
}

# ---- prompts -----------------------------------------------------------------
prompt() {
    local var=$1 q=$2 def=${3:-} input=""
    if [[ -n "$def" ]]; then
        read -rp "  $q [$def]: " input || true
        printf -v "$var" '%s' "${input:-$def}"
    else
        while [[ -z "${input:-}" ]]; do read -rp "  $q: " input || true; done
        printf -v "$var" '%s' "$input"
    fi
}

# yes/no prompt; default Y if def="y", default N if def="n"
prompt_yesno() {
    local var=$1 q=$2 def=${3:-y} a=""
    local hint="[Y/n]"
    [[ "$def" == "n" ]] && hint="[y/N]"
    while :; do
        read -rp "  $q $hint: " a || true
        a=${a:-$def}
        case "${a,,}" in
            y|yes) printf -v "$var" '%s' "1"; return 0 ;;
            n|no)  printf -v "$var" '%s' "0"; return 0 ;;
        esac
    done
}

choose_role() {
    cat <<EOF

Choose role:
  1) Server  — terminates spoofed UDP from a client and forwards to a
               Hysteria/QUIC backend on a separate host.
  2) Client  — wraps local-app UDP into spoofed packets towards the server
               and unwraps spoofed replies.
EOF
    local r; read -rp "  > " r
    case "$r" in
        1) ROLE=server ;;
        2) ROLE=client ;;
        *) err "invalid"; exit 1 ;;
    esac
}

choose_speed() {
    cat <<EOF

Pipe speed (used to tune --batch / --rcvbuf / --sndbuf):
  1) 1 Gbps        (≤500 Mbps user each direction)
  2) 2 Gbps        (≤1 Gbps each)
  3) 5 Gbps
  4) 10 Gbps
  5) Custom (enter Mbps)
  6) Auto-detect via speedtest-cli
EOF
    local c; read -rp "  > " c
    case "$c" in
        1|"") SPEED=1000 ;;
        2)    SPEED=2000 ;;
        3)    SPEED=5000 ;;
        4)    SPEED=10000 ;;
        5)    read -rp "  Mbps: " SPEED ;;
        6)    detect_speed ;;
        *)    err "invalid"; exit 1 ;;
    esac
    [[ "$SPEED" =~ ^[0-9]+$ && "$SPEED" -gt 0 ]] || { err "Bad speed: $SPEED"; exit 1; }
    derive_tuning
    say "Tuning → batch=$BATCH bufsize=$BUFSIZE rcvbuf=sndbuf=$SOCKBUF"
}

detect_speed() {
    if ! command -v speedtest-cli >/dev/null; then
        warn "speedtest-cli missing; attempting to install..."
        if   command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq speedtest-cli
        elif command -v dnf     >/dev/null; then dnf install -y -q speedtest-cli
        elif command -v yum     >/dev/null; then yum install -y -q speedtest-cli
        elif command -v pip3    >/dev/null; then pip3 install --quiet speedtest-cli
        else err "Cannot install speedtest-cli; pick a manual speed instead"; exit 1
        fi
    fi
    say "Running speedtest..."
    local out; out=$(speedtest-cli --simple 2>&1 || true)
    echo "$out"
    local dl ul
    dl=$(awk '/^Download:/{print int($2)}' <<<"$out")
    ul=$(awk '/^Upload:/{print int($2)}'   <<<"$out")
    [[ -z "$dl" ]] && dl=0
    [[ -z "$ul" ]] && ul=0
    SPEED=$(( dl > ul ? dl : ul ))
    [[ $SPEED -gt 0 ]] || { err "speedtest could not determine bandwidth"; exit 1; }
    ok "Detected ~${SPEED} Mbps; using as cap"
}

derive_tuning() {
    if   [[ $SPEED -le 1000 ]]; then BATCH=64;  BUFSIZE=2048; SOCKBUF=$((16<<20))
    elif [[ $SPEED -le 5000 ]]; then BATCH=128; BUFSIZE=2048; SOCKBUF=$((64<<20))
    else                              BATCH=256; BUFSIZE=2048; SOCKBUF=$((128<<20))
    fi
}

# ---- marked-block helpers ----------------------------------------------------
# Apply / replace a `MARK_BEGIN .. MARK_END` block inside an arbitrary
# file. If the file doesn't exist or has no marker, the block is created
# (or appended). Otherwise the existing block is replaced in place. Any
# lines outside the markers are preserved verbatim.
apply_marked_block() {
    local file=$1 body=$2
    mkdir -p "$(dirname "$file")"
    if [[ ! -f "$file" ]] || ! grep -qF "$MARK_BEGIN" "$file" 2>/dev/null; then
        {
            [[ -f "$file" ]] && { cat "$file"; echo; }
            echo "$MARK_BEGIN"
            echo "# Managed by the spocon installer. Remove these lines (or run"
            echo "# the uninstaller) to revert. Do not edit between the markers."
            echo "$body"
            echo "$MARK_END"
        } >"$file.tmp"
        mv "$file.tmp" "$file"
    else
        awk -v b="$MARK_BEGIN" -v e="$MARK_END" -v body="$body" '
            $0 == b { print; print "# Managed by the spocon installer. Remove these lines (or run";
                       print "# the uninstaller) to revert. Do not edit between the markers.";
                       print body; skip=1; next }
            $0 == e { skip=0; print; next }
            !skip   { print }
        ' "$file" >"$file.tmp"
        mv "$file.tmp" "$file"
    fi
}

# Remove the spocon-marked block (and the markers themselves) from a
# file. If the file ends up empty, delete it.
remove_marked_block() {
    local file=$1
    [[ -f "$file" ]] || return 0
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        $0 == b { skip=1; next }
        $0 == e { skip=0; next }
        !skip   { print }
    ' "$file" | sed -e '$ { /^$/d }' >"$file.tmp"
    if [[ -s "$file.tmp" ]]; then
        mv "$file.tmp" "$file"
    else
        rm -f "$file" "$file.tmp"
    fi
}

# ---- rp_filter snapshot / restore --------------------------------------------
# Snapshot every interface's current rp_filter value to RP_SNAPSHOT *the
# first time*. Subsequent installs leave the snapshot untouched so the
# uninstaller can always revert all the way back to the user's original
# kernel state.
snapshot_rp_filter() {
    [[ -f "$RP_SNAPSHOT" ]] && return 0
    mkdir -p "$CONFIG_DIR"
    : >"$RP_SNAPSHOT"
    for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
        [[ -r "$f" ]] || continue
        local iface; iface=$(basename "$(dirname "$f")")
        echo "${iface}=$(cat "$f")" >>"$RP_SNAPSHOT"
    done
    chmod 600 "$RP_SNAPSHOT"
}

restore_rp_filter() {
    [[ -f "$RP_SNAPSHOT" ]] || return 0
    while IFS='=' read -r iface val; do
        [[ -z "$iface" ]] && continue
        echo "$val" >"/proc/sys/net/ipv4/conf/$iface/rp_filter" 2>/dev/null || true
    done <"$RP_SNAPSHOT"
    rm -f "$RP_SNAPSHOT"
}

# ---- system tuning -----------------------------------------------------------
choose_rp_filter() {
    cat <<EOF

Disable kernel reverse-path filter (rp_filter) on this host?
  Spoofed-source UDP is exactly what rp_filter is built to drop. Without
  rp_filter=0, spocon's spoofed packets will be silently discarded by
  the kernel and the tunnel will not move traffic.
  The original values are snapshotted to $RP_SNAPSHOT and restored on
  uninstall.
EOF
    prompt_yesno RP_FILTER_OFF "Disable rp_filter (recommended for spocon)?" y
    if [[ "$RP_FILTER_OFF" != "1" ]]; then
        warn "rp_filter left enabled — spocon will most likely drop traffic."
        warn "If you change your mind later, re-run the installer."
    fi
}

write_sysctl() {
    local m=$((SOCKBUF * 4))
    [[ $m -lt 67108864 ]] && m=67108864    # at least 64 MiB

    local body
    body="net.core.rmem_max = $m
net.core.wmem_max = $m
net.core.netdev_max_backlog = 300000
net.core.optmem_max = 4194304"

    if [[ "${RP_FILTER_OFF:-1}" == "1" ]]; then
        snapshot_rp_filter
        body="$body
# rp_filter drops packets whose source isn't reverse-routable through
# the arrival interface — exactly the property we violate by spoofing.
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0"
        for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
            [[ -w "$f" ]] || continue
            local iface; iface=$(basename "$(dirname "$f")")
            [[ "$iface" == "all" || "$iface" == "default" ]] && continue
            body="$body
net.ipv4.conf.${iface}.rp_filter = 0"
            echo 0 >"$f" 2>/dev/null || true
        done
    fi

    apply_marked_block "$SYSCTL_FILE" "$body"
    sysctl --system >/dev/null
    ok "Sysctls written → $SYSCTL_FILE"
}

write_env_file() {
    local path=$1; shift
    mkdir -p "$CONFIG_DIR"
    : >"$path"; chmod 600 "$path"
    for kv in "$@"; do echo "$kv" >>"$path"; done
}

write_service() {
    local name=$1 binary=$2 port=$3 args=$4
    local ipt; ipt=$(command -v iptables || true)
    local pre="" post=""
    if [[ -n "$ipt" ]]; then
        # `-D` first to remove any leftover rule from a previous run
        # (succeeds quietly if absent thanks to the leading `-`), then
        # `-I` to (re)insert. Result: exactly one rule per direction.
        pre="ExecStartPre=-${ipt} -t raw -D PREROUTING -p udp --dport ${port} -j NOTRACK
ExecStartPre=-${ipt} -t raw -D OUTPUT     -p udp --sport ${port} -j NOTRACK
ExecStartPre=-${ipt} -t raw -I PREROUTING -p udp --dport ${port} -j NOTRACK
ExecStartPre=-${ipt} -t raw -I OUTPUT     -p udp --sport ${port} -j NOTRACK"
        post="ExecStopPost=-${ipt} -t raw -D PREROUTING -p udp --dport ${port} -j NOTRACK
ExecStopPost=-${ipt} -t raw -D OUTPUT     -p udp --sport ${port} -j NOTRACK"
    fi
    cat >"$SERVICE_DIR/$name.service" <<EOF
[Unit]
Description=spocon ${name#spocon-} (spoofed UDP relay)
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
LimitNOFILE=1048576
LimitMEMLOCK=infinity
Restart=always
RestartSec=2
${pre}
ExecStart=$binary $args
${post}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$name"
    ok "$name enabled and running"
    systemctl status "$name" --no-pager -l | sed -n '1,12p' || true
}

# ---- per-role install ---------------------------------------------------------
install_server() {
    say ""; say "=== spocon-server params ==="
    local env=$CONFIG_DIR/server.env
    # shellcheck disable=SC1090,SC2015
    [[ -f "$env" ]] && source "$env" 2>/dev/null || true

    # Backward-compat: derive new combined defaults from older split env
    # (CLIENT_IP + CLIENT_WAN, SERVER_IP) if a previous installer wrote
    # them.
    : "${CLIENT:=${CLIENT_IP:+${CLIENT_IP}:${CLIENT_WAN:-$UPSTREAM_PORT}}}"
    : "${SPOOF_SRC:=${SERVER_IP:+${SERVER_IP}:${UPSTREAM_PORT:-51820}}}"

    prompt UPSTREAM_PORT  "Upstream listen port (UDP)"                          "${UPSTREAM_PORT:-51820}"
    prompt H_OUT          "Hysteria backend host:port (--h-out, IP or DNS)"     "${H_OUT:-}"
    prompt CLIENT         "Client public host:port (--client; port = client's --wan-port)" "${CLIENT:-}"

    cat <<EOF

  Source spoofing wraps every reply in an IPv4+UDP header with a
  spoofed src= so the client sees traffic as if it came from that IP.
  Disabling sends plain UDP from --upstream-port (no raw socket needed,
  no CAP_NET_RAW required) — pick this if the path doesn't need
  spoofing or this box can't open raw sockets.
EOF
    prompt_yesno SPOOF_ON "Enable source spoofing (downlink to client)?" y

    local spoof_arg=""
    if [[ "$SPOOF_ON" == "1" ]]; then
        prompt SPOOF_SRC  "Spoof src host:port (--spoof-src; usually this box's public IP:$UPSTREAM_PORT)" "${SPOOF_SRC:-}"
        spoof_arg="--spoof-src ${SPOOF_SRC}"
    else
        SPOOF_SRC=""
    fi

    write_sysctl
    write_env_file "$env" \
        "UPSTREAM_PORT=$UPSTREAM_PORT" \
        "H_OUT=$H_OUT" \
        "CLIENT=$CLIENT" \
        "SPOOF_SRC=$SPOOF_SRC" \
        "SPOOF_ON=${SPOOF_ON:-0}" \
        "SPEED=$SPEED" "BATCH=$BATCH" "BUFSIZE=$BUFSIZE" "SOCKBUF=$SOCKBUF" \
        "RP_FILTER_OFF=${RP_FILTER_OFF:-1}"

    local args="--upstream-port ${UPSTREAM_PORT} \
--h-out ${H_OUT} \
--client ${CLIENT} \
${spoof_arg} \
--batch ${BATCH} --bufsize ${BUFSIZE} \
--rcvbuf ${SOCKBUF} --sndbuf ${SOCKBUF} \
--no-udp-csum"
    write_service spocon-server "$INSTALL_DIR/spocon-server" "$UPSTREAM_PORT" "$args"
}

install_client() {
    say ""; say "=== spocon-client params ==="
    local env=$CONFIG_DIR/client.env
    # shellcheck disable=SC1090,SC2015
    [[ -f "$env" ]] && source "$env" 2>/dev/null || true

    : "${SERVER:=${SERVER_IP:+${SERVER_IP}:${SERVER_PORT:-51820}}}"
    : "${SPOOF_SRC:=${CLIENT_IP:+${CLIENT_IP}:${WAN_PORT:-51820}}}"

    prompt LOCAL_IN     "Local app listen ip:port (--local-in)"                   "${LOCAL_IN:-127.0.0.1:5000}"
    prompt SERVER       "Server host:port (--server, IP or DNS)"                  "${SERVER:-}"
    prompt WAN_PORT     "WAN listen port (must equal server's --client port)"     "${WAN_PORT:-${SERVER##*:}}"

    cat <<EOF

  Source spoofing wraps every uplink in an IPv4+UDP header with a
  spoofed src= so the server sees traffic as if it came from that IP.
  Disabling sends plain UDP from the wan-port socket (no raw socket
  needed, no CAP_NET_RAW required).
EOF
    prompt_yesno SPOOF_ON "Enable source spoofing (uplink to server)?" y

    local spoof_arg=""
    if [[ "$SPOOF_ON" == "1" ]]; then
        prompt SPOOF_SRC "Spoof src host:port (--spoof-src; usually this box's public IP:$WAN_PORT)" "${SPOOF_SRC:-}"
        spoof_arg="--spoof-src ${SPOOF_SRC}"
    else
        SPOOF_SRC=""
    fi

    write_sysctl
    write_env_file "$env" \
        "LOCAL_IN=$LOCAL_IN" \
        "SERVER=$SERVER" \
        "WAN_PORT=$WAN_PORT" \
        "SPOOF_SRC=$SPOOF_SRC" \
        "SPOOF_ON=${SPOOF_ON:-0}" \
        "SPEED=$SPEED" "BATCH=$BATCH" "BUFSIZE=$BUFSIZE" "SOCKBUF=$SOCKBUF" \
        "RP_FILTER_OFF=${RP_FILTER_OFF:-1}"

    local args="--local-in ${LOCAL_IN} \
--server ${SERVER} \
--wan-port ${WAN_PORT} \
${spoof_arg} \
--batch ${BATCH} --bufsize ${BUFSIZE} \
--rcvbuf ${SOCKBUF} --sndbuf ${SOCKBUF} \
--no-udp-csum"
    write_service spocon-client "$INSTALL_DIR/spocon-client" "$WAN_PORT" "$args"
}

# ---- top-level actions --------------------------------------------------------
do_install() {
    require_root
    hr; say "spocon installer"; hr
    choose_role
    choose_speed
    choose_rp_filter
    install_binaries
    case "$ROLE" in
        server) install_server ;;
        client) install_client ;;
    esac
    hr
    ok "Installation complete."
    ok "  status: systemctl status spocon-$ROLE"
    ok "  logs:   journalctl -u spocon-$ROLE -f"
    ok "  config: $CONFIG_DIR/$ROLE.env  (re-run installer to edit)"
}

do_uninstall() {
    require_root
    say "Stopping spocon services..."
    for svc in spocon-server spocon-client; do
        systemctl disable --now "$svc" 2>/dev/null || true
        rm -f "$SERVICE_DIR/$svc.service"
    done
    systemctl daemon-reload
    rm -f "$INSTALL_DIR/spocon-server" "$INSTALL_DIR/spocon-client"

    # Strip our marker block out of the sysctl drop-in. The drop-in is
    # the only shared system file we touch today, but the helper works
    # for any file we might modify later (sysctl.conf, sysctl.d/*, etc).
    remove_marked_block "$SYSCTL_FILE"

    # Restore every interface's rp_filter to the value we snapshotted
    # before turning it off — kernels keep runtime values in /proc even
    # after a drop-in is removed, so an explicit restore is required.
    restore_rp_filter

    sysctl --system >/dev/null 2>&1 || true

    rm -rf "$CONFIG_DIR"

    # The systemd `ExecStopPost` should already have removed the iptables
    # NOTRACK rules, but flush again defensively if iptables exists.
    if command -v iptables >/dev/null; then
        iptables -t raw -F 2>/dev/null || true
    fi
    ok "Uninstalled."
}

do_reinstall() {
    do_uninstall
    do_install
}

main() {
    require_root
    local source_line
    if [[ -n "$LOCAL_TARBALL" ]]; then
        source_line="offline tarball: $(basename "$LOCAL_TARBALL")"
    else
        source_line="$REPO @ $TAG"
    fi
    cat <<EOF
═══════════════════════════════════════════════
  spocon installer  ($source_line)
═══════════════════════════════════════════════
  1) Install
  2) Uninstall
  3) Re-install
EOF
    local a; read -rp "  > " a
    case "$a" in
        1) do_install ;;
        2) do_uninstall ;;
        3) do_reinstall ;;
        *) err "invalid"; exit 1 ;;
    esac
}

main "$@"
