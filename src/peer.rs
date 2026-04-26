//! Lock-free shared cell holding the most-recent local-app peer address.
//!
//! Encoded as a single `AtomicU64`:
//!
//!   bit 63    : valid flag
//!   bits 16-47: IPv4 octets (native-order u32)
//!   bits  0-15: port

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};

const VALID: u64 = 1u64 << 63;

pub struct PeerCell(AtomicU64);

impl PeerCell {
    pub const fn empty() -> Self {
        Self(AtomicU64::new(0))
    }

    #[inline]
    pub fn store(&self, addr: SocketAddrV4) {
        let ip = u32::from_ne_bytes(addr.ip().octets()) as u64;
        let port = addr.port() as u64;
        self.0.store(VALID | (ip << 16) | port, Ordering::Release);
    }

    #[inline]
    pub fn load(&self) -> Option<SocketAddrV4> {
        let v = self.0.load(Ordering::Acquire);
        if v & VALID == 0 {
            return None;
        }
        let port = (v & 0xFFFF) as u16;
        let ip = ((v >> 16) & 0xFFFF_FFFF) as u32;
        let o = ip.to_ne_bytes();
        Some(SocketAddrV4::new(
            Ipv4Addr::new(o[0], o[1], o[2], o[3]),
            port,
        ))
    }
}
