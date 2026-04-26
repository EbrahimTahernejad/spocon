#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# spocon installer
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/ebrahimtahernejad/spocon/main/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/ebrahimtahernejad/spocon/main/install.sh) v0.1.1
#
# - Downloads the static x86_64 / aarch64 musl binary from the GitHub
#   release matching the optional `[tag]` argument (default: latest).
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
TAG="${1:-latest}"

INSTALL_DIR=/usr/local/bin
SERVICE_DIR=/etc/systemd/system
SYSCTL_FILE=/etc/sysctl.d/99-spocon.conf
CONFIG_DIR=/etc/spocon

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

download_binaries() {
    local target=$1
    local ver=${TAG#v}
    local tarball="spocon-$ver-$target.tar.gz"
    local url="https://github.com/$REPO/releases/download/$TAG/$tarball"
    say "Downloading $url"
    local tmp; tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    curl -fsSL "$url" -o "$tmp/$tarball" || { err "Download failed: $url"; exit 1; }
    tar -xzf "$tmp/$tarball" -C "$tmp"
    install -m 755 "$tmp"/spocon-*/spocon-server "$INSTALL_DIR/spocon-server"
    install -m 755 "$tmp"/spocon-*/spocon-client "$INSTALL_DIR/spocon-client"
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

# ---- system tuning -----------------------------------------------------------
write_sysctl() {
    local m=$((SOCKBUF * 4))
    [[ $m -lt 67108864 ]] && m=67108864    # at least 64 MiB
    cat >"$SYSCTL_FILE" <<EOF
# spocon installer (auto-generated, safe to edit)
net.core.rmem_max = $m
net.core.wmem_max = $m
net.core.netdev_max_backlog = 300000
net.core.optmem_max = 4194304
# rp_filter drops packets whose source isn't reverse-routable through the
# arrival interface — exactly the property we violate by spoofing.
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
    sysctl --system >/dev/null
    for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 >"$f" 2>/dev/null || true; done
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
    # shellcheck disable=SC1090
    [[ -f "$env" ]] && source "$env" 2>/dev/null || true

    prompt UPSTREAM_PORT  "Upstream listen port (UDP)"               "${UPSTREAM_PORT:-51820}"
    prompt H_OUT          "Hysteria backend ip:port (--h-out)"       "${H_OUT:-}"
    prompt SERVER_IP      "This box's public IP (--spoof-src ip)"    "${SERVER_IP:-}"
    prompt CLIENT_IP      "Client public IP (--client ip)"           "${CLIENT_IP:-}"
    prompt CLIENT_WAN     "Client WAN port (--client port)"          "${CLIENT_WAN:-$UPSTREAM_PORT}"

    write_sysctl
    write_env_file "$env" \
        "UPSTREAM_PORT=$UPSTREAM_PORT" \
        "H_OUT=$H_OUT" \
        "SERVER_IP=$SERVER_IP" \
        "CLIENT_IP=$CLIENT_IP" \
        "CLIENT_WAN=$CLIENT_WAN" \
        "SPEED=$SPEED" "BATCH=$BATCH" "BUFSIZE=$BUFSIZE" "SOCKBUF=$SOCKBUF"

    local args="--upstream-port ${UPSTREAM_PORT} \
--h-out ${H_OUT} \
--spoof-src ${SERVER_IP}:${UPSTREAM_PORT} \
--client ${CLIENT_IP}:${CLIENT_WAN} \
--batch ${BATCH} --bufsize ${BUFSIZE} \
--rcvbuf ${SOCKBUF} --sndbuf ${SOCKBUF} \
--no-udp-csum"
    write_service spocon-server "$INSTALL_DIR/spocon-server" "$UPSTREAM_PORT" "$args"
}

install_client() {
    say ""; say "=== spocon-client params ==="
    local env=$CONFIG_DIR/client.env
    # shellcheck disable=SC1090
    [[ -f "$env" ]] && source "$env" 2>/dev/null || true

    prompt LOCAL_IN     "Local app listen ip:port (--local-in)"               "${LOCAL_IN:-127.0.0.1:5000}"
    prompt SERVER_IP    "Server public IP (--server ip)"                      "${SERVER_IP:-}"
    prompt SERVER_PORT  "Server port (--server port)"                         "${SERVER_PORT:-51820}"
    prompt CLIENT_IP    "This box's public IP (--spoof-src ip)"               "${CLIENT_IP:-}"
    prompt WAN_PORT     "WAN listen port (must equal server's --client port)" "${WAN_PORT:-$SERVER_PORT}"

    write_sysctl
    write_env_file "$env" \
        "LOCAL_IN=$LOCAL_IN" \
        "SERVER_IP=$SERVER_IP" \
        "SERVER_PORT=$SERVER_PORT" \
        "CLIENT_IP=$CLIENT_IP" \
        "WAN_PORT=$WAN_PORT" \
        "SPEED=$SPEED" "BATCH=$BATCH" "BUFSIZE=$BUFSIZE" "SOCKBUF=$SOCKBUF"

    local args="--local-in ${LOCAL_IN} \
--server ${SERVER_IP}:${SERVER_PORT} \
--spoof-src ${CLIENT_IP}:${WAN_PORT} \
--wan-port ${WAN_PORT} \
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
    local target; target=$(detect_arch)
    resolve_tag
    download_binaries "$target"
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
    rm -f "$SYSCTL_FILE"
    rm -rf "$CONFIG_DIR"
    sysctl --system >/dev/null 2>&1 || true
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
    cat <<EOF
═══════════════════════════════════════════════
  spocon installer  ($REPO @ $TAG)
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
