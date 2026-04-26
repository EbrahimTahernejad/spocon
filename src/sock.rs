//! Socket setup helpers (UDP and raw IPv4).
//!
//! All sockets are kept as raw FDs because the hot path uses
//! `recvmmsg`/`sendmmsg` directly through `libc`.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

fn last_err(ctx: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    let v = val as libc::c_int;
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &v as *const _ as *const _,
            std::mem::size_of_val(&v) as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(last_err("setsockopt"));
    }
    Ok(())
}

fn set_buffers(fd: RawFd, rcvbuf: usize, sndbuf: usize) -> io::Result<()> {
    // SO_RCVBUFFORCE / SO_SNDBUFFORCE bypass net.core.rmem_max if we have CAP_NET_ADMIN.
    // Try the FORCE versions first, fall back to the regular ones (which the kernel will
    // silently cap at the sysctl limit).
    let try_set =
        |name_force: libc::c_int, name_plain: libc::c_int, val: usize| -> io::Result<()> {
            let v = val as libc::c_int;
            let r = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    name_force,
                    &v as *const _ as *const _,
                    std::mem::size_of_val(&v) as libc::socklen_t,
                )
            };
            if r == 0 {
                return Ok(());
            }
            setsockopt_int(fd, libc::SOL_SOCKET, name_plain, v)
        };
    try_set(libc::SO_RCVBUFFORCE, libc::SO_RCVBUF, rcvbuf)?;
    try_set(libc::SO_SNDBUFFORCE, libc::SO_SNDBUF, sndbuf)?;
    Ok(())
}

/// Bind a UDP socket on `bind_addr`. Sets large RCV/SND buffers, optional
/// `SO_BUSY_POLL`, `SO_REUSEADDR`/`SO_REUSEPORT`.
pub fn bind_udp(
    bind_addr: SocketAddrV4,
    rcvbuf: usize,
    sndbuf: usize,
    busy_poll_us: u32,
) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(last_err("socket(AF_INET, SOCK_DGRAM)"));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1).ok();
    set_buffers(fd, rcvbuf, sndbuf)?;
    if busy_poll_us > 0 {
        // SO_BUSY_POLL requires CAP_NET_ADMIN; ignore failures.
        setsockopt_int(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            busy_poll_us as i32,
        )
        .ok();
    }

    let sa = sockaddr_in_v4(bind_addr);
    let r = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(last_err(&format!("bind {bind_addr}")));
    }
    Ok(owned)
}

/// Create an ephemeral (kernel-chosen port) UDP socket bound to 0.0.0.0.
pub fn ephemeral_udp(rcvbuf: usize, sndbuf: usize, busy_poll_us: u32) -> io::Result<OwnedFd> {
    bind_udp(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        rcvbuf,
        sndbuf,
        busy_poll_us,
    )
}

/// Build a `sockaddr_in` from a `SocketAddrV4`.
pub fn sockaddr_in_v4(a: SocketAddrV4) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = a.port().to_be();
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(a.ip().octets()),
    };
    sa
}

/// Decode a `sockaddr_in` filled by the kernel (e.g. from recvfrom).
pub fn sockaddr_in_to_v4(sa: &libc::sockaddr_in) -> SocketAddrV4 {
    // `s_addr` is in network byte order: the in-memory layout is
    // [octet0, octet1, octet2, octet3]. `u32::to_ne_bytes` returns those
    // bytes in their native-memory order, which is exactly the octet array
    // `Ipv4Addr::from([u8;4])` wants. Same trick avoids a needless bswap on
    // every recvmmsg slot.
    let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
    SocketAddrV4::new(ip, u16::from_be(sa.sin_port))
}

/// Get the bound address of a socket (e.g. to learn the kernel-assigned
/// ephemeral port).
pub fn local_addr_v4(fd: &OwnedFd) -> io::Result<SocketAddrV4> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            &mut sa as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if r != 0 {
        return Err(last_err("getsockname"));
    }
    Ok(sockaddr_in_to_v4(&sa))
}
