//! spocon — high-throughput UDP relay with spoofed source addresses on both
//! the uplink (client → server) and downlink (server → client) legs.
//!
//! The hot path is a tight `recvmmsg` → build → `sendmmsg` loop with
//! pre-allocated buffers and zero allocations per packet.

pub mod checksum;
pub mod logging;
pub mod mmsg;
pub mod packet;
pub mod peer;
pub mod raw;
pub mod sock;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

/// Parse `ip:port` into a v4 socket address. Used by clap value parsers
/// where DNS resolution is undesirable (e.g. local bind addresses).
pub fn parse_v4(s: &str) -> Result<SocketAddrV4, String> {
    SocketAddrV4::from_str(s).map_err(|e| format!("invalid ipv4 ip:port {s:?}: {e}"))
}

/// Parse a bare IPv4 literal.
pub fn parse_v4_ip(s: &str) -> Result<Ipv4Addr, String> {
    Ipv4Addr::from_str(s).map_err(|e| format!("invalid ipv4 {s:?}: {e}"))
}

/// Parse `ip:port` *or* `host:port` into a v4 socket address. Resolves DNS
/// once, at clap parse time, picking the first IPv4 result. The relays
/// then operate on the resolved address forever — no per-packet lookups.
pub fn resolve_v4(s: &str) -> Result<SocketAddrV4, String> {
    use std::net::{SocketAddr, ToSocketAddrs};
    s.to_socket_addrs()
        .map_err(|e| format!("could not resolve {s:?}: {e}"))?
        .find_map(|sa| match sa {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("no IPv4 address for {s:?}"))
}

/// Tunable that survives across binaries.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    pub batch: usize,
    pub buf_size: usize,
    pub rcvbuf: usize,
    pub sndbuf: usize,
    pub busy_poll_us: u32,
    pub no_udp_csum: bool,
    pub verbose: bool,
}

impl Tuning {
    pub const DEFAULT_BATCH: usize = 64;
    pub const DEFAULT_BUF_SIZE: usize = 65535;
    pub const DEFAULT_SOCK_BUF: usize = 16 << 20; // 16 MiB
}
