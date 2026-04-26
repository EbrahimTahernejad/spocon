//! Raw IPv4 socket with `IP_HDRINCL` for sending fully-handcrafted IPv4 + UDP
//! packets. Requires `CAP_NET_RAW` (or root).

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

fn last_err(ctx: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

/// Open an `AF_INET / SOCK_RAW / IPPROTO_UDP` socket with `IP_HDRINCL=1`.
/// `sndbuf` is applied to `SO_SNDBUF` (force-version tried first).
pub fn open_raw_udp(sndbuf: usize) -> io::Result<OwnedFd> {
    let fd: RawFd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(last_err("socket(AF_INET, SOCK_RAW, IPPROTO_UDP)"));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let one: libc::c_int = 1;
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const _,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(last_err("setsockopt IP_HDRINCL"));
    }

    // Best-effort large send buffer (bypasses sysctl with FORCE if possible).
    let v = sndbuf as libc::c_int;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            &v as *const _ as *const _,
            std::mem::size_of_val(&v) as libc::socklen_t,
        )
    };
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &v as *const _ as *const _,
            std::mem::size_of_val(&v) as libc::socklen_t,
        )
    };

    Ok(owned)
}
