//! Internet checksum (RFC 1071) — fast 64-bit accumulating implementation.
//!
//! The internet checksum is the one's-complement of the one's-complement sum
//! of 16-bit big-endian words. Because addition is associative and the
//! end-around carry property holds for any 2^k-bit chunking, we can:
//!
//!   * Read 8 bytes at a time as a big-endian `u64`,
//!   * Accumulate using native 64-bit addition while propagating the carry,
//!   * Fold the 64-bit result down to 16 bits at the end.
//!
//! `partial` returns the running 64-bit sum so the caller can chain multiple
//! buffers (e.g. pseudo-header + UDP header + payload) without allocating.

/// Add `data` into the running 64-bit ones-complement accumulator.
#[inline]
pub fn partial(data: &[u8], mut sum: u64) -> u64 {
    let mut i = 0;
    let n = data.len();

    // 32-byte unrolled inner loop: 4 × u64 adds with carry-propagation.
    while i + 32 <= n {
        let a = u64::from_be_bytes(unsafe { *(data.as_ptr().add(i) as *const [u8; 8]) });
        let b = u64::from_be_bytes(unsafe { *(data.as_ptr().add(i + 8) as *const [u8; 8]) });
        let c = u64::from_be_bytes(unsafe { *(data.as_ptr().add(i + 16) as *const [u8; 8]) });
        let d = u64::from_be_bytes(unsafe { *(data.as_ptr().add(i + 24) as *const [u8; 8]) });

        let (s1, c1) = a.overflowing_add(b);
        let (s2, c2) = c.overflowing_add(d);
        let (s3, c3) = s1.overflowing_add(s2);
        let block = s3;
        let carries = (c1 as u64) + (c2 as u64) + (c3 as u64);

        let (s4, c4) = sum.overflowing_add(block);
        sum = s4.wrapping_add(carries).wrapping_add(c4 as u64);

        i += 32;
    }

    while i + 8 <= n {
        let v = u64::from_be_bytes(unsafe { *(data.as_ptr().add(i) as *const [u8; 8]) });
        let (s, c) = sum.overflowing_add(v);
        sum = s.wrapping_add(c as u64);
        i += 8;
    }

    while i + 2 <= n {
        let v = ((data[i] as u64) << 8) | (data[i + 1] as u64);
        sum = sum.wrapping_add(v);
        i += 2;
    }

    if i < n {
        // Trailing odd byte goes into the high half of a 16-bit word.
        sum = sum.wrapping_add((data[i] as u64) << 8);
    }

    sum
}

/// Fold the 64-bit running sum down to a final ones-complement 16-bit value.
#[inline]
pub fn fold(mut sum: u64) -> u16 {
    // Fold 64 → 32 → 16 with end-around carry.
    sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
    sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
    let mut s32 = sum as u32;
    s32 = (s32 & 0xFFFF) + (s32 >> 16);
    s32 = (s32 & 0xFFFF) + (s32 >> 16);
    !(s32 as u16)
}

/// One-shot internet checksum over a single buffer.
#[inline]
pub fn ones_complement(data: &[u8]) -> u16 {
    fold(partial(data, 0))
}
