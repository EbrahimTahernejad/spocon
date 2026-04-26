//! Build raw IPv4 + UDP datagrams directly into a caller-owned buffer.
//!
//! All addresses, ports and the constant part of the UDP pseudo-header are
//! computed once at session start and folded into a `SpoofTemplate`. The
//! per-packet hot path then only:
//!
//!   1. Writes the variable IPv4 fields (total length, IP id, IP checksum),
//!   2. Writes the variable UDP fields (length),
//!   3. Copies the payload (already in place when caller reads into the same
//!      buffer at offset 28),
//!   4. Computes the UDP checksum incrementally from the precomputed
//!      session-constant sum (`const_sum`) plus a per-packet contribution
//!      that depends only on the payload and `udp_len`.

use crate::checksum;

pub const IP_HDR: usize = 20;
pub const UDP_HDR: usize = 8;
pub const HDRS: usize = IP_HDR + UDP_HDR;

const IPV4_VER_IHL: u8 = 0x45;
const PROTO_UDP: u8 = 17;
const TTL: u8 = 64;
const FLAGS_FRAG_DF: u16 = 0x4000;

/// Precomputed session state for spoofing one (src ip:port → dst ip:port) flow.
#[derive(Clone, Copy)]
pub struct SpoofTemplate {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    /// Sum of (src_ip ‖ dst_ip ‖ proto-as-16bit ‖ src_port ‖ dst_port).
    /// Per-packet code adds `2 * udp_len` and the payload checksum.
    udp_const_sum: u64,
    /// Sum of all fixed IPv4 header fields (ver/ihl, dscp/ecn, flags+frag,
    /// ttl/proto, src_ip, dst_ip). Per-packet code adds `total_len` and
    /// `ip_id`.
    ip_const_sum: u64,
}

impl SpoofTemplate {
    pub fn new(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> Self {
        // UDP pseudo-header constant part:
        //   src_ip (4B), dst_ip (4B), zero+proto (2B), src_port (2B), dst_port (2B)
        let mut udp_const = 0u64;
        udp_const = checksum::partial(&src_ip, udp_const);
        udp_const = checksum::partial(&dst_ip, udp_const);
        udp_const += PROTO_UDP as u64; // zero high byte, proto in low byte
        udp_const += src_port as u64;
        udp_const += dst_port as u64;

        // IPv4 header constant part: ver/ihl, dscp/ecn=0, flags+frag, ttl/proto, ips
        let mut ip_const = 0u64;
        ip_const += (IPV4_VER_IHL as u64) << 8; // ver/ihl in high, dscp/ecn=0 (low byte)
        ip_const += FLAGS_FRAG_DF as u64;
        ip_const += ((TTL as u64) << 8) | (PROTO_UDP as u64);
        ip_const = checksum::partial(&src_ip, ip_const);
        ip_const = checksum::partial(&dst_ip, ip_const);

        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            udp_const_sum: udp_const,
            ip_const_sum: ip_const,
        }
    }

    /// Build a raw IPv4 + UDP datagram **in place**.
    ///
    /// The payload of length `payload_len` must already live at
    /// `slot[HDRS .. HDRS + payload_len]` — the caller is expected to have
    /// arranged this by passing `payload_off = HDRS` to `Batch::prep_recv`.
    /// Bytes `slot[0 .. HDRS]` are overwritten with a fresh IP+UDP header.
    ///
    /// Returns the total IP datagram length (`HDRS + payload_len`).
    #[inline]
    pub fn build_in_place(
        &self,
        slot: &mut [u8],
        payload_len: usize,
        ip_id: u16,
        compute_udp_csum: bool,
    ) -> usize {
        debug_assert!(slot.len() >= HDRS + payload_len);
        let udp_len = (UDP_HDR + payload_len) as u16;
        let total_len = IP_HDR as u16 + udp_len;

        // ---------- IPv4 header ----------
        slot[0] = IPV4_VER_IHL;
        slot[1] = 0;
        slot[2..4].copy_from_slice(&total_len.to_be_bytes());
        slot[4..6].copy_from_slice(&ip_id.to_be_bytes());
        slot[6..8].copy_from_slice(&FLAGS_FRAG_DF.to_be_bytes());
        slot[8] = TTL;
        slot[9] = PROTO_UDP;
        slot[10] = 0;
        slot[11] = 0;
        slot[12..16].copy_from_slice(&self.src_ip);
        slot[16..20].copy_from_slice(&self.dst_ip);
        let ip_csum = {
            let s = self.ip_const_sum + total_len as u64 + ip_id as u64;
            checksum::fold(s)
        };
        slot[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // ---------- UDP header ----------
        slot[20..22].copy_from_slice(&self.src_port.to_be_bytes());
        slot[22..24].copy_from_slice(&self.dst_port.to_be_bytes());
        slot[24..26].copy_from_slice(&udp_len.to_be_bytes());
        slot[26] = 0;
        slot[27] = 0;

        // ---------- UDP checksum (optional) ----------
        if compute_udp_csum {
            // const pseudo-header (src ip / dst ip / proto / src port / dst port)
            // + udp_len (pseudo) + udp_len (udp hdr) + payload.
            let mut s = self.udp_const_sum + 2 * (udp_len as u64);
            s = checksum::partial(&slot[HDRS..HDRS + payload_len], s);
            let mut c = checksum::fold(s);
            if c == 0 {
                c = 0xFFFF; // RFC 768: zero means "not computed", flip to all-ones
            }
            slot[26..28].copy_from_slice(&c.to_be_bytes());
        }

        total_len as usize
    }

    /// Build a raw IPv4 + UDP datagram into `out`, copying `payload` if it
    /// is not already at `out[HDRS..]`. Convenience wrapper around
    /// [`Self::build_in_place`].
    #[inline]
    pub fn build(
        &self,
        out: &mut [u8],
        payload: &[u8],
        ip_id: u16,
        compute_udp_csum: bool,
    ) -> usize {
        debug_assert!(out.len() >= HDRS + payload.len());
        let same_buf = std::ptr::eq(unsafe { out.as_ptr().add(HDRS) }, payload.as_ptr());
        if !same_buf {
            out[HDRS..HDRS + payload.len()].copy_from_slice(payload);
        }
        self.build_in_place(out, payload.len(), ip_id, compute_udp_csum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    /// Reference implementation: byte-for-byte equivalent of the Go
    /// `buildIPv4UDP` in randconnect's server.
    fn reference_build(
        out: &mut [u8],
        data: &[u8],
        src_port: u16,
        dst_port: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        ip_id: u16,
    ) -> usize {
        let udp_len = (8 + data.len()) as u16;
        let total_len = 20 + udp_len;
        out[0] = 0x45;
        out[1] = 0;
        out[2..4].copy_from_slice(&total_len.to_be_bytes());
        out[4..6].copy_from_slice(&ip_id.to_be_bytes());
        out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        out[8] = 64;
        out[9] = 17;
        out[10] = 0;
        out[11] = 0;
        out[12..16].copy_from_slice(&src_ip);
        out[16..20].copy_from_slice(&dst_ip);
        let ip_csum = checksum::ones_complement(&out[..20]);
        out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        out[20..22].copy_from_slice(&src_port.to_be_bytes());
        out[22..24].copy_from_slice(&dst_port.to_be_bytes());
        out[24..26].copy_from_slice(&udp_len.to_be_bytes());
        out[26] = 0;
        out[27] = 0;
        out[28..28 + data.len()].copy_from_slice(data);

        // pseudo-header
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip);
        pseudo[4..8].copy_from_slice(&dst_ip);
        pseudo[8] = 0;
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());

        let mut s = checksum::partial(&pseudo, 0);
        s = checksum::partial(&out[20..28 + data.len()], s);
        let mut c = checksum::fold(s);
        if c == 0 {
            c = 0xFFFF;
        }
        out[26..28].copy_from_slice(&c.to_be_bytes());

        total_len as usize
    }

    fn run_case(data: &[u8]) {
        let src_ip = [10, 0, 0, 1];
        let dst_ip = [10, 0, 0, 2];
        let src_port = 51500u16;
        let dst_port = 40000u16;
        let ip_id = 0xABCDu16;

        let mut buf_a = vec![0u8; HDRS + data.len()];
        let mut buf_b = vec![0u8; HDRS + data.len()];

        let tpl = SpoofTemplate::new(src_ip, src_port, dst_ip, dst_port);
        let n_a = tpl.build(&mut buf_a, data, ip_id, true);

        let n_b = reference_build(&mut buf_b, data, src_port, dst_port, src_ip, dst_ip, ip_id);

        assert_eq!(n_a, n_b);
        assert_eq!(buf_a, buf_b, "len={}", data.len());

        // IP header checksum must verify to 0 across the 20-byte header.
        assert_eq!(checksum::ones_complement(&buf_a[..20]), 0);

        // UDP checksum must verify to 0 across pseudo-header + udp+data.
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip);
        pseudo[4..8].copy_from_slice(&dst_ip);
        pseudo[8] = 0;
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        let mut s = checksum::partial(&pseudo, 0);
        s = checksum::partial(&buf_a[20..], s);
        assert_eq!(checksum::fold(s), 0);
    }

    #[test]
    fn matches_reference_various_sizes() {
        run_case(&[]);
        run_case(b"hello");
        run_case(b"hello, world!");
        let big: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();
        run_case(&big);
        let huge: Vec<u8> = (0..65000u32).map(|i| (i ^ (i >> 8)) as u8).collect();
        run_case(&huge);
    }

    #[test]
    fn build_in_place_equals_build() {
        let data: Vec<u8> = (0..1234u32).map(|i| (i * 31) as u8).collect();
        let tpl = SpoofTemplate::new([1, 2, 3, 4], 1111, [5, 6, 7, 8], 2222);

        let mut buf_a = vec![0u8; HDRS + data.len()];
        tpl.build(&mut buf_a, &data, 0x1111, true);

        let mut buf_b = vec![0u8; HDRS + data.len()];
        buf_b[HDRS..].copy_from_slice(&data);
        tpl.build_in_place(&mut buf_b, data.len(), 0x1111, true);

        assert_eq!(buf_a, buf_b);
    }
}
