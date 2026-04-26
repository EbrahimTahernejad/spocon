//! Batched send/receive via `recvmmsg(2)` / `sendmmsg(2)`.
//!
//! `Batch` owns a single contiguous storage block laid out as `BATCH` slots
//! of `HEADER_ROOM + bufsize` bytes. Slots can be used for either:
//!
//!   * a plain UDP recv/send that uses bytes `[HEADER_ROOM..]`, or
//!   * a raw IPv4+UDP send that occupies the whole slot, with bytes
//!     `[0..HEADER_ROOM]` reserved for the IP+UDP headers and bytes
//!     `[HEADER_ROOM..HEADER_ROOM+payload_len]` containing the payload that
//!     was previously written there by a recv.
//!
//! The same `Batch` is reused indefinitely; the hot path only touches
//! `iov_len` / `iov_base` / per-slot `sockaddr_in` and never reallocates.

use std::io;
use std::net::SocketAddrV4;

use crate::packet;
use crate::sock::sockaddr_in_to_v4;

// `libc` declares these with subtly different prototypes on glibc vs musl
// (`c_int` flags on glibc, `c_uint` on musl). The kernel ABI is identical
// either way, so we re-declare them ourselves to keep one prototype across
// targets.
extern "C" {
    fn recvmmsg(
        sockfd: libc::c_int,
        msgvec: *mut libc::mmsghdr,
        vlen: libc::c_uint,
        flags: libc::c_int,
        timeout: *mut libc::timespec,
    ) -> libc::c_int;

    fn sendmmsg(
        sockfd: libc::c_int,
        msgvec: *mut libc::mmsghdr,
        vlen: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::c_int;
}

/// Bytes reserved at the start of every slot for an IPv4+UDP header.
pub const HEADER_ROOM: usize = packet::HDRS;

pub struct Batch {
    pub batch: usize,
    pub bufsize: usize,
    storage: Box<[u8]>,
    iovs: Box<[libc::iovec]>,
    addrs: Box<[libc::sockaddr_in]>,
    msgs: Box<[libc::mmsghdr]>,
}

// SAFETY: the raw pointers stored in `msgs` reference `iovs` / `addrs` heap
// storage that lives for the lifetime of the `Batch` and is never reallocated.
unsafe impl Send for Batch {}

impl Batch {
    pub fn new(batch: usize, bufsize: usize) -> Self {
        assert!(batch > 0 && bufsize > 0);
        let stride = HEADER_ROOM + bufsize;
        let storage = vec![0u8; batch * stride].into_boxed_slice();
        let iovs = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0
            };
            batch
        ]
        .into_boxed_slice();
        let addrs =
            vec![unsafe { std::mem::zeroed::<libc::sockaddr_in>() }; batch].into_boxed_slice();
        let msgs = vec![unsafe { std::mem::zeroed::<libc::mmsghdr>() }; batch].into_boxed_slice();

        let mut b = Self {
            batch,
            bufsize,
            storage,
            iovs,
            addrs,
            msgs,
        };
        b.wire_pointers();
        b
    }

    /// Initialise the per-slot `mmsghdr` to point at `iovs[i]` / `addrs[i]`.
    /// Called exactly once at construction; pointers are stable thereafter.
    fn wire_pointers(&mut self) {
        let iovs_ptr = self.iovs.as_mut_ptr();
        let addrs_ptr = self.addrs.as_mut_ptr();
        for i in 0..self.batch {
            let m = &mut self.msgs[i];
            m.msg_hdr.msg_iov = unsafe { iovs_ptr.add(i) };
            m.msg_hdr.msg_iovlen = 1;
            m.msg_hdr.msg_name = unsafe { addrs_ptr.add(i) as *mut _ };
            m.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            m.msg_hdr.msg_control = std::ptr::null_mut();
            m.msg_hdr.msg_controllen = 0;
            m.msg_hdr.msg_flags = 0;
            m.msg_len = 0;
        }
    }

    #[inline]
    fn stride(&self) -> usize {
        HEADER_ROOM + self.bufsize
    }

    /// Configure all slots for `recvmmsg`. Received bytes will land at
    /// `slot[payload_off..]`. Pass `0` for plain UDP recv, or `HEADER_ROOM`
    /// when the same slot will later be used to send a raw IPv4+UDP packet
    /// in place.
    pub fn prep_recv(&mut self, payload_off: usize) {
        debug_assert!(payload_off <= self.stride());
        let stride = self.stride();
        let storage_ptr = self.storage.as_mut_ptr();
        let cap = stride - payload_off;
        for i in 0..self.batch {
            self.iovs[i].iov_base = unsafe { storage_ptr.add(i * stride + payload_off) as *mut _ };
            self.iovs[i].iov_len = cap;
            self.msgs[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            self.msgs[i].msg_len = 0;
        }
    }

    /// Run `recvmmsg`. Blocks until at least one packet is available, then
    /// drains as many additional already-queued packets as fit in the batch
    /// without blocking (this is what `MSG_WAITFORONE` buys us — without it
    /// the kernel would block for the *full* `vlen` packets, which is a
    /// throughput killer at low rates).
    pub fn recvmmsg(&mut self, fd: i32) -> io::Result<usize> {
        loop {
            let n = unsafe {
                recvmmsg(
                    fd,
                    self.msgs.as_mut_ptr(),
                    self.batch as libc::c_uint,
                    libc::MSG_WAITFORONE as libc::c_int,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }

    /// Number of payload bytes received in slot `i`.
    #[inline]
    pub fn payload_len(&self, i: usize) -> usize {
        self.msgs[i].msg_len as usize
    }

    /// Source address recorded by the kernel on the most recent recv into
    /// slot `i`.
    #[inline]
    pub fn src_addr(&self, i: usize) -> SocketAddrV4 {
        sockaddr_in_to_v4(&self.addrs[i])
    }

    /// Mutable view of the entire slot (`HEADER_ROOM + bufsize` bytes).
    #[inline]
    pub fn slot_mut(&mut self, i: usize) -> &mut [u8] {
        let stride = self.stride();
        let off = i * stride;
        &mut self.storage[off..off + stride]
    }

    /// Mutable view of slot `i` starting at `offset`, `len` bytes.
    #[inline]
    pub fn slice_mut(&mut self, i: usize, offset: usize, len: usize) -> &mut [u8] {
        let stride = self.stride();
        let off = i * stride + offset;
        &mut self.storage[off..off + len]
    }

    /// Configure slot `i` for sending: bytes `[offset .. offset+len]` go on
    /// the wire, addressed to `dst`.
    pub fn prep_send_slot(&mut self, i: usize, offset: usize, len: usize, dst: &libc::sockaddr_in) {
        debug_assert!(offset + len <= self.stride());
        let stride = self.stride();
        self.iovs[i].iov_base =
            unsafe { self.storage.as_mut_ptr().add(i * stride + offset) as *mut _ };
        self.iovs[i].iov_len = len;
        self.addrs[i] = *dst;
        self.msgs[i].msg_hdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    }

    /// Send the first `n` slots via `sendmmsg`. Returns number sent (may be
    /// less than `n` on partial send / per-message error).
    pub fn sendmmsg(&mut self, fd: i32, n: usize) -> io::Result<usize> {
        debug_assert!(n <= self.batch);
        loop {
            let r = unsafe { sendmmsg(fd, self.msgs.as_mut_ptr(), n as libc::c_uint, 0) };
            if r < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(r as usize);
        }
    }
}
