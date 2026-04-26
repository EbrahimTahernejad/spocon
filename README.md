# spocon

High-throughput Rust port of the spoof path of [randconnect](../).

Unlike the Go original, **both** legs of the tunnel use spoofed source
addresses on raw IPv4 sockets:

```
local-app  ──UDP──>  spocon-client  ──RAW IP (src=spoof_src)──>  spocon-server  ──UDP──>  h_out
                                                                                           │
local-app  <──UDP──  spocon-client  <──RAW IP (src=spoof_src)──  spocon-server  <──UDP──   h_out
```

The hot path is a tight `recvmmsg(2)` → build IP+UDP in place →
`sendmmsg(2)` loop with pre-allocated buffers, no allocations per packet,
and one dedicated thread per direction.

## Performance knobs

* `--batch <N>`           — `recvmmsg` / `sendmmsg` batch size (default 64).
* `--bufsize <N>`         — per-slot payload buffer (default 65535).
* `--rcvbuf <bytes>`      — `SO_RCVBUF` (force-version tried first; up to
                            ~64 MiB recommended on big pipes).
* `--sndbuf <bytes>`      — `SO_SNDBUF` (likewise).
* `--busy-poll-us <us>`   — `SO_BUSY_POLL` microseconds. Lowers latency at
                            the cost of CPU; needs `CAP_NET_ADMIN`.
* `--no-udp-csum`         — emit zero UDP checksum on spoofed packets
                            (RFC 768 says checksum is optional over IPv4).
                            Saves a full payload pass; some middleboxes
                            drop it.

The `MSG_WAITFORONE` flag is always set on `recvmmsg`, so the syscall
returns as soon as **one** packet is queued and then drains as much of the
batch as is already in the queue without blocking.

## Capacity planning

Every user packet crosses the spocon-server NIC **twice** — once on the
spoofed leg with the client, once on the plain leg to the Hysteria
backend on a separate host:

```
NIC RX = (spoofed-from-client) + (plain-from-backend)   ≈ user_bw × 2
NIC TX = (plain-to-backend)    + (spoofed-to-client)    ≈ user_bw × 2
```

So a 1 Gbps full-duplex port carries ~500 Mbps of *user* traffic in each
direction, a 10 Gbps port carries ~5 Gbps each way, etc.

| Pipe (full-duplex NIC) | User bw each way | vCPU (modern x86) | RAM   | Recommended VPS / box                        |
|------------------------|------------------|-------------------|-------|----------------------------------------------|
| 100 Mbps               | 50 Mbps          | 1                 | 128 MiB | any cheap KVM / OpenVZ                       |
| 1 Gbps                 | 500 Mbps         | 2                 | 256 MiB | $5 / mo 2-vCPU (Hetzner CX22, DO, Vultr…)    |
| 2.5 Gbps               | 1.25 Gbps        | 2                 | 512 MiB | 2.5 GbE-capable VPS                          |
| 10 Gbps                | 5 Gbps           | 4 + multi-queue NIC | 1 GiB | dedicated host with virtio-net or ixgbe/i40e |
| 25 Gbps                | 12.5 Gbps        | 8 + RSS hashing   | 2 GiB | bare-metal, mlx5/ice-class NIC               |

With `--no-udp-csum` enabled, spocon's userspace hot path is roughly
**~270 ns per packet** on modern x86, i.e. ≤ 5 % of one core per Gbps.
The dominant cost above 5 Gbps is kernel softirq / NIC driver, not
spocon — every doubling of pps wants another active RX queue + RPS.

### Recommended flags by pipe size

```bash
# 100 Mbps – 1 Gbps
--batch 64  --bufsize 2048 --rcvbuf $((16<<20))  --sndbuf $((16<<20))  --no-udp-csum

# 1 – 5 Gbps
--batch 128 --bufsize 2048 --rcvbuf $((64<<20))  --sndbuf $((64<<20))  --no-udp-csum

# 5 + Gbps  (also pin threads with taskset, spread NIC IRQs across CPUs)
--batch 256 --bufsize 2048 --rcvbuf $((128<<20)) --sndbuf $((128<<20)) --no-udp-csum
```

A smaller `--bufsize` (2048 ≫ MTU is plenty for QUIC/Hysteria) keeps the
per-batch working set inside L2/L3 cache; raise it only if the backend
sends single UDP datagrams larger than that (rare).

### Pre-flight tuning checklist

Spoofed-source UDP is exactly what `rp_filter` and `conntrack` are built
to block — if either is in the way, throughput collapses no matter how
fast the relay is.

```bash
# 1) Bigger socket buffers so SO_*BUFFORCE actually takes
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.core.netdev_max_backlog=250000
sudo sysctl -w net.core.optmem_max=4194304

# 2) Disable reverse-path filtering on every interface (both ends!)
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 | sudo tee "$f"; done

# 3) Don't conntrack the relay ports — replace 51500 with your actual
#    server --upstream-port and client --wan-port respectively.
sudo iptables -t raw -I PREROUTING -p udp --dport 51500 -j NOTRACK
sudo iptables -t raw -I OUTPUT     -p udp --sport 51500 -j NOTRACK

# 4) Multi-queue NIC: spread RX softirq + RPS across all cores
sudo ethtool -L eth0 combined $(nproc)
echo $(printf 'ffff%.0s' {1..16}) | sudo tee /sys/class/net/eth0/queues/rx-*/rps_cpus
```

### Diagnosing low throughput

1. **Test the backend without spocon first.** Point your local client
   straight at the Hysteria server and run the same speedtest. If that's
   already slow, spocon is not at fault.
2. **`nstat` diff during a transfer.** Significant counters:
   * `UdpRcvbufErrors` — kernel ran out of socket buffer; raise
     `--rcvbuf` and `net.core.rmem_max`.
   * `IpReversesPath` — `rp_filter` is dropping spoofed packets.
   * `UdpInErrors` / `UdpNoPorts` — port mismatch between client/server
     args, or middlebox stripping packets.
3. **Drop `--no-udp-csum`** if any hop on the path treats UDP-csum=0 as
   malformed (some carrier-grade NATs do).
4. **Smaller `--batch`** (16–32) for very low-RTT links or anything
   running QUIC; lowers per-packet jitter at the cost of a bit of
   syscall overhead.
5. **Hysteria `bandwidth.up/down`** must be ≥ what you actually want;
   Brutal CC won't exceed the configured cap.

## Build

### Dynamic glibc build (development)

```bash
cd spocon
cargo build --release
```

Outputs `target/release/spocon-{server,client}` (~3 MB, dynamically linked
to glibc, fast incremental builds).

### Fully-static musl build (shipping)

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools          # provides musl-gcc
cargo build --release --target x86_64-unknown-linux-musl
```

Outputs `target/x86_64-unknown-linux-musl/release/spocon-{server,client}`
— ~750 KB ELF executables, **statically linked** with zero `NEEDED`
entries (`ldd` reports "not a dynamic executable"). Drop into
`FROM scratch` Docker images, copy onto a router, etc.

The `.cargo/config.toml` forces `target-feature=+crt-static` and disables
PIE so the resulting binary is a plain `EXEC` — necessary because
Rust's default static-PIE on musl can segfault at startup on certain
toolchains.

### Capabilities

Both binaries need `CAP_NET_RAW` to open the raw socket. Either run as
root or set the capability:

```bash
sudo setcap cap_net_raw,cap_net_admin=+ep target/release/spocon-server
sudo setcap cap_net_raw,cap_net_admin=+ep target/release/spocon-client
```

## Usage

### Server side

```bash
spocon-server \
    --upstream-port 51500 \
    --h-out         127.0.0.1:51500 \
    --spoof-src     1.2.3.4:51500 \
    --client        5.6.7.8:40000
```

* Spoofed UDP from the client arrives on UDP/51500.
* Forwarded as plain UDP to `--h-out`.
* Replies from `--h-out` are wrapped in IP/UDP with
  `src=1.2.3.4:51500`, `dst=5.6.7.8:40000` and pushed out a raw socket.

### Client side

```bash
spocon-client \
    --local-in   0.0.0.0:10333 \
    --server     <server-public-ip>:51500 \
    --spoof-src  9.9.9.9:33333 \
    --wan-port   40000
```

* Local app talks UDP to `--local-in`.
* spocon-client wraps each datagram in IP/UDP with `src=9.9.9.9:33333`,
  `dst=server:51500` and pushes it out a raw socket.
* Spoofed downlink lands on UDP/40000 and is delivered back to the
  most-recently-seen local-app peer.

The server's `--client <ip>:<port>` must equal the client's external
`<wan-ip>:<wan-port>`.

## Docker

The shipped Dockerfiles are two-stage `rust:1-alpine` → `FROM scratch`:

```bash
docker build -t spocon-server -f Dockerfile.server .
docker build -t spocon-client -f Dockerfile.client .
```

Final images contain **only the static binary** (~750 KB) on `scratch`,
no shell, no libc. Run with `--cap-add=NET_RAW` and a network where
the spoofed source is actually reachable from the kernel's perspective
(usually `--network=host`).

## Architecture

Layout:

```
src/
├── lib.rs        re-exports + Tuning struct
├── checksum.rs   64-bit accumulating Internet checksum
├── packet.rs     SpoofTemplate (precomputed pseudo-header / IP-header sums,
│                 builds a complete IPv4+UDP packet in place)
├── sock.rs       UDP bind / setsockopt / sockaddr_in helpers
├── raw.rs        AF_INET / SOCK_RAW / IP_HDRINCL helper
├── mmsg.rs       Batch — owns one heap-allocated buffer block of
│                 BATCH × (HDRS+bufsize) bytes plus aligned iovec /
│                 sockaddr_in / mmsghdr arrays. recvmmsg/sendmmsg wrappers.
├── peer.rs       Lock-free `AtomicU64` peer cell (last local-app addr)
├── logging.rs    `vlog!` macro gated on a global atomic
└── bin/
    ├── server.rs  upstream UDP → h_out UDP   /   h_out UDP → raw spoofed → client
    └── client.rs  local UDP → raw spoofed → server  /  wan UDP → local UDP
```

Each binary spawns exactly two threads, one per direction, plus the main
thread which holds the `OwnedFd`s and joins. Per-batch work is:

1. `Batch::prep_recv(off)` — point each iovec at the right offset inside
   the slot. For raw-send paths this is `HEADER_ROOM=28` so the payload
   lands right after the future IP+UDP header and the same buffer is
   reusable as-is for the outgoing raw datagram.
2. `Batch::recvmmsg(fd)` — single syscall, blocks until ≥1 packet is
   queued, drains the rest of the batch non-blockingly via
   `MSG_WAITFORONE`.
3. Per slot: write IP+UDP header in place via
   `SpoofTemplate::build_in_place`. Header & UDP checksums are computed
   from precomputed session-constant sums.
4. `Batch::sendmmsg(fd, n)` — single syscall, fires the whole batch.

There are zero heap allocations on the hot path.
