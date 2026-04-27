#!/usr/bin/env python3
"""End-to-end test harness for spocon.

Exercises every combination of {spoof on, spoof off} × {IP literal, hostname}
on loopback against a Python UDP echo backend. For each scenario the harness
spins up:

    test app  ──(127.0.0.1:LOCAL_IN)──>  spocon-client
        spocon-client  ──(localhost|127.0.0.1:UPSTREAM_PORT)──>  spocon-server
            spocon-server  ──(localhost|127.0.0.1:H_OUT_PORT)──>  echo backend
            echo backend  ──reply──>
        spocon-server  ──(127.0.0.1:WAN_PORT)──>
    spocon-client  ──(local app)──>  test app

then sends N datagrams through and counts how many round-trip. Spoof
scenarios use 127.0.0.x as the source IP so loopback's per-iface rp_filter
doesn't drop them (every 127.0.0.0/8 address is routable through `lo`).

Usage:
    sudo python3 tests/e2e.py            # runs all 4 scenarios
    python3 tests/e2e.py                  # non-root: only the 2 plain ones
    python3 tests/e2e.py --bin-dir <dir>  # pick a different build of the binaries
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(SCRIPT_DIR)


def find_bin(name: str, override: str | None) -> str:
    candidates: list[str] = []
    if override:
        candidates.append(os.path.join(override, name))
    for sub in ("target/release", "target/debug"):
        candidates.append(os.path.join(PROJ_ROOT, sub, name))
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise SystemExit(
        f"binary {name!r} not found; tried {candidates!r}\n"
        f"build first with `cargo build --release` (or pass --bin-dir)"
    )


# ---------------------------------------------------------------------------
# echo backend
# ---------------------------------------------------------------------------
def echo_server(port: int, stop: threading.Event) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.2)
    try:
        while not stop.is_set():
            try:
                data, src = s.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                s.sendto(data, src)
            except OSError:
                pass
    finally:
        s.close()


# ---------------------------------------------------------------------------
# ping/pong
# ---------------------------------------------------------------------------
def ping_pong(local_in_port: int, n: int = 20, payload_len: int = 64,
              recv_timeout: float = 2.0) -> tuple[int, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(recv_timeout)
    sent: set[bytes] = set()
    for i in range(n):
        msg = (f"hello-{i:04d}-".encode() * 8)[:payload_len]
        msg = msg.ljust(payload_len, b".")
        s.sendto(msg, ("127.0.0.1", local_in_port))
        sent.add(msg)
    rx = 0
    deadline = time.time() + recv_timeout
    while rx < n and time.time() < deadline:
        try:
            data, _ = s.recvfrom(65535)
            if data in sent:
                rx += 1
        except socket.timeout:
            break
    s.close()
    return rx, n


# ---------------------------------------------------------------------------
# scenario harness
# ---------------------------------------------------------------------------
@dataclass
class Scenario:
    name: str
    spoof: bool
    host: str  # "127.0.0.1" or "localhost"


@dataclass
class Result:
    name: str
    matched: int
    total: int
    server_alive: bool
    client_alive: bool
    server_log: str
    client_log: str

    @property
    def passed(self) -> bool:
        return (
            self.server_alive
            and self.client_alive
            and self.matched == self.total
            and self.total > 0
        )


def _proc_alive(p: subprocess.Popen) -> bool:
    return p.poll() is None


def _kill(p: subprocess.Popen) -> None:
    try:
        p.send_signal(signal.SIGTERM)
        p.wait(2.0)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def run_scenario(
    scen: Scenario,
    *,
    server_bin: str,
    client_bin: str,
    log_dir: str,
    base_port: int,
    packets: int,
) -> Result:
    backend = base_port + 0
    upstream = base_port + 1
    wan = base_port + 2
    local_in = base_port + 3

    # Start the echo backend.
    stop_evt = threading.Event()
    echo_t = threading.Thread(
        target=echo_server, args=(backend, stop_evt), daemon=True
    )
    echo_t.start()
    time.sleep(0.05)

    server_args = [
        server_bin,
        "--upstream-port", str(upstream),
        "--h-out", f"{scen.host}:{backend}",
        "--client", f"127.0.0.1:{wan}",
        "--rcvbuf", str(1 << 20),
        "--sndbuf", str(1 << 20),
        "--batch", "8",
        "--bufsize", "2048",
        "-v",
    ]
    client_args = [
        client_bin,
        "--local-in", f"127.0.0.1:{local_in}",
        "--server", f"{scen.host}:{upstream}",
        "--wan-port", str(wan),
        "--rcvbuf", str(1 << 20),
        "--sndbuf", str(1 << 20),
        "--batch", "8",
        "--bufsize", "2048",
        "-v",
    ]
    if scen.spoof:
        # Pick loopback-range IPs so per-interface rp_filter on `lo` keeps
        # accepting the packet (127.0.0.0/8 is always routable through lo).
        server_args += ["--spoof-src", f"127.0.0.2:{upstream}"]
        client_args += ["--spoof-src", f"127.0.0.3:{wan}"]

    srv_log_path = os.path.join(log_dir, f"{scen.name}.server.log")
    cli_log_path = os.path.join(log_dir, f"{scen.name}.client.log")
    srv_log = open(srv_log_path, "wb")
    cli_log = open(cli_log_path, "wb")
    srv = subprocess.Popen(server_args, stdout=srv_log, stderr=srv_log)
    cli = subprocess.Popen(client_args, stdout=cli_log, stderr=cli_log)

    # Give the binaries a beat to bind sockets.
    time.sleep(0.4)

    server_alive = _proc_alive(srv)
    client_alive = _proc_alive(cli)

    matched = 0
    if server_alive and client_alive:
        try:
            matched, _ = ping_pong(local_in, n=packets)
        except Exception as e:  # noqa: BLE001
            print(f"  ping_pong error: {e}", file=sys.stderr)

    _kill(srv)
    _kill(cli)
    stop_evt.set()
    echo_t.join(timeout=1.5)
    srv_log.close()
    cli_log.close()

    return Result(
        name=scen.name,
        matched=matched,
        total=packets,
        server_alive=server_alive,
        client_alive=client_alive,
        server_log=srv_log_path,
        client_log=cli_log_path,
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin-dir", default=None,
                    help="directory containing spocon-server / spocon-client")
    ap.add_argument("--log-dir", default=os.path.join(SCRIPT_DIR, "logs"),
                    help="where to write per-scenario stdout/stderr")
    ap.add_argument("--packets", type=int, default=20,
                    help="datagrams per scenario (default 20)")
    ap.add_argument("--base-port", type=int, default=60000,
                    help="starting UDP port; each scenario uses base..base+3")
    ap.add_argument("--include-spoof", choices=["auto", "yes", "no"], default="auto",
                    help="run spoof scenarios (raw socket; needs CAP_NET_RAW)")
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)

    server_bin = find_bin("spocon-server", args.bin_dir)
    client_bin = find_bin("spocon-client", args.bin_dir)

    is_root = os.geteuid() == 0
    do_spoof = (
        args.include_spoof == "yes"
        or (args.include_spoof == "auto" and is_root)
    )

    scenarios: list[Scenario] = [
        Scenario(name="plain_ip", spoof=False, host="127.0.0.1"),
        Scenario(name="plain_dns", spoof=False, host="localhost"),
    ]
    if do_spoof:
        scenarios += [
            Scenario(name="spoof_ip", spoof=True, host="127.0.0.1"),
            Scenario(name="spoof_dns", spoof=True, host="localhost"),
        ]
    elif args.include_spoof != "no":
        print("(skipping spoof scenarios — re-run as root or pass "
              "`--include-spoof yes`)\n")

    print(f"spocon e2e — server={server_bin}")
    print(f"spocon e2e — client={client_bin}")
    print(f"spocon e2e — logs in {args.log_dir}")
    print()

    results: list[Result] = []
    for i, scen in enumerate(scenarios):
        # Each scenario gets its own port window so a slow shutdown of the
        # previous run can't bind-collide with the next.
        port = args.base_port + i * 10
        print(f"  running {scen.name:11s}  spoof={scen.spoof!s:5s}  host={scen.host:10s}  ports={port}-{port + 3}")
        r = run_scenario(
            scen,
            server_bin=server_bin,
            client_bin=client_bin,
            log_dir=args.log_dir,
            base_port=port,
            packets=args.packets,
        )
        results.append(r)

    print()
    print(f"{'scenario':12s}  {'result':6s}  {'rx/tx':7s}  log")
    print("-" * 70)
    n_pass = 0
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        if r.passed:
            n_pass += 1
        extra = ""
        if not r.server_alive:
            extra += " server-died"
        if not r.client_alive:
            extra += " client-died"
        print(f"  {r.name:10s}  {status:6s}  {r.matched:>3d}/{r.total:<3d}  "
              f"{r.client_log}{extra}")

    print()
    print(f"{n_pass}/{len(results)} scenarios passed")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
