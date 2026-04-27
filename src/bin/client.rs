//! spocon-client — Rust port of randconnect's client-side spoof path.
//!
//! With `--spoof-src` set (spoof mode), packets travel like this:
//!
//! * UPLINK: payloads from the local app are wrapped in an IPv4+UDP
//!   header with `src=--spoof-src` and `dst=--server` and pushed out
//!   a raw `IP_HDRINCL` socket via `sendmmsg`.
//!
//! * DOWNLINK: spoofed UDP arriving on `--wan-port` is forwarded as
//!   plain UDP back to the most-recently-seen local-app peer.
//!
//! Without `--spoof-src` (plain mode) the uplink is a regular UDP
//! `sendto(--server)` from the same socket bound to `0.0.0.0:--wan-port`,
//! so the server's natural reply lands back on that socket — no raw
//! socket, no header crafting, no `CAP_NET_RAW`.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use clap::Parser;

use spocon::{
    info, logging,
    mmsg::{Batch, HEADER_ROOM},
    packet::SpoofTemplate,
    parse_v4,
    peer::PeerCell,
    raw, resolve_v4, sock, vlog, Tuning,
};

#[derive(Parser, Debug)]
#[command(
    name = "spocon-client",
    about = "spocon (Rust) client: spoofs uplink to the server and receives spoofed downlink at --wan-port."
)]
struct Args {
    /// ip:port where the local app (kcp/quic/socks5/...) sends its UDP traffic.
    #[arg(long, value_parser = parse_v4)]
    local_in: SocketAddrV4,

    /// host:port of the spocon-server (DNS or IP literal accepted).
    /// Resolved once at startup.
    #[arg(long, value_parser = resolve_v4)]
    server: SocketAddrV4,

    /// host:port used as the source of spoofed uplink packets. If
    /// omitted, packets are sent as plain UDP from the wan-port socket
    /// (no spoofing) — useful when the path doesn't need it or the box
    /// can't open a raw socket.
    #[arg(long, value_parser = resolve_v4)]
    spoof_src: Option<SocketAddrV4>,

    /// UDP port to bind on 0.0.0.0 to receive downstream packets.
    /// Must match `--client <ip>:<wan-port>` on the server.
    #[arg(long)]
    wan_port: u16,

    /// recvmmsg / sendmmsg batch size.
    #[arg(long, default_value_t = Tuning::DEFAULT_BATCH)]
    batch: usize,

    /// Per-slot payload buffer size (max UDP datagram).
    #[arg(long, default_value_t = Tuning::DEFAULT_BUF_SIZE)]
    bufsize: usize,

    /// SO_RCVBUF (force-version tried first).
    #[arg(long, default_value_t = Tuning::DEFAULT_SOCK_BUF)]
    rcvbuf: usize,

    /// SO_SNDBUF (force-version tried first).
    #[arg(long, default_value_t = Tuning::DEFAULT_SOCK_BUF)]
    sndbuf: usize,

    /// SO_BUSY_POLL microseconds (0 = disabled).
    #[arg(long, default_value_t = 0)]
    busy_poll_us: u32,

    /// Skip UDP checksum on spoofed uplink packets (set checksum=0).
    /// Faster but may be dropped by some middleboxes.
    #[arg(long, default_value_t = false)]
    no_udp_csum: bool,

    /// Log every packet (direction + length).
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    logging::set_verbose(args.verbose);

    // ---------- sockets ----------
    let local_sock = sock::bind_udp(args.local_in, args.rcvbuf, args.sndbuf, args.busy_poll_us)?;

    let wan_bind = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.wan_port);
    let wan_sock = sock::bind_udp(wan_bind, args.rcvbuf, args.sndbuf, args.busy_poll_us)?;

    // Raw socket is only needed in spoof mode. Skipping it lets plain
    // mode run without CAP_NET_RAW.
    let raw_sock = match args.spoof_src {
        Some(_) => Some(raw::open_raw_udp(args.sndbuf)?),
        None => None,
    };

    let spoof_src_disp = args
        .spoof_src
        .map(|s| s.to_string())
        .unwrap_or_else(|| "<none — plain UDP>".to_string());

    info!(
        "spocon-client (rust)\n\
         \x20 local_in:   {}\n\
         \x20 server:     {} (uplink dst)\n\
         \x20 spoof_src:  {} (uplink src)\n\
         \x20 wan_listen: 0.0.0.0:{} (downlink rcv)\n\
         \x20 batch:      {}\n\
         \x20 bufsize:    {}\n\
         \x20 rcvbuf/sndbuf: {} / {}\n\
         \x20 udp checksum: {}\n\
         \x20 verbose:    {}",
        args.local_in,
        args.server,
        spoof_src_disp,
        args.wan_port,
        args.batch,
        args.bufsize,
        args.rcvbuf,
        args.sndbuf,
        if args.no_udp_csum {
            "skipped"
        } else {
            "computed"
        },
        args.verbose,
    );

    let last_local: Arc<PeerCell> = Arc::new(PeerCell::empty());
    let ip_id = Arc::new(AtomicU32::new(std::process::id() & 0xFFFF));

    // Pre-build the spoof template + raw msg_name only if spoofing is on.
    // For raw send: kernel routes by msg_name; the UDP port lives in our
    // crafted UDP header, so port=0 in the sockaddr.
    let template_opt = args.spoof_src.map(|src| {
        SpoofTemplate::new(
            src.ip().octets(),
            src.port(),
            args.server.ip().octets(),
            args.server.port(),
        )
    });
    let server_for_raw = sock::sockaddr_in_v4(SocketAddrV4::new(*args.server.ip(), 0));
    let server_plain = sock::sockaddr_in_v4(args.server);

    // ---------- uplink thread: local UDP -> (raw spoofed | plain UDP) -> server ----------
    let uplink = {
        let local_fd = local_sock.as_raw_fd();
        let raw_fd_opt = raw_sock.as_ref().map(|f| f.as_raw_fd());
        let wan_fd = wan_sock.as_raw_fd();
        let batch_n = args.batch;
        let bufsize = args.bufsize;
        let no_csum = args.no_udp_csum;
        let ip_id = ip_id.clone();
        let last_local = last_local.clone();
        let spoof_src = args.spoof_src;
        let server = args.server;
        thread::Builder::new()
            .name("spocon-up".to_string())
            .spawn(move || -> io::Result<()> {
                let mut b = Batch::new(batch_n, bufsize);
                let mut last_seen: Option<SocketAddrV4> = None;

                // Spoof mode: receive into [HEADER_ROOM..] so the IP+UDP
                // header can be filled in front of the payload in-place,
                // and send via the raw socket. Plain mode: receive at
                // offset 0 and `sendto(server)` from the wan-port socket
                // so the server's reply naturally lands back on it.
                let spoof = template_opt.is_some();
                let recv_off = if spoof { HEADER_ROOM } else { 0 };
                let send_fd = raw_fd_opt.unwrap_or(wan_fd);

                loop {
                    b.prep_recv(recv_off);
                    let n = b.recvmmsg(local_fd)?;
                    if n == 0 {
                        continue;
                    }
                    // Track the most recent local-app peer (last in batch
                    // wins, matching the Go client).
                    let src = b.src_addr(n - 1);
                    if last_seen != Some(src) {
                        last_seen = Some(src);
                        last_local.store(src);
                        eprintln!("local client attached: {src}");
                    }
                    for i in 0..n {
                        let plen = b.payload_len(i);
                        if let Some(ref tpl) = template_opt {
                            let id = (ip_id.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                            let total = tpl.build_in_place(b.slot_mut(i), plen, id, !no_csum);
                            b.prep_send_slot(i, 0, total, &server_for_raw);
                            vlog!(
                                "[up  ] local {} -> spoof {} -> server {} {}B",
                                src,
                                spoof_src.unwrap(),
                                server,
                                plen
                            );
                        } else {
                            b.prep_send_slot(i, 0, plen, &server_plain);
                            vlog!(
                                "[up  ] local {} -> server {} {}B (plain)",
                                src,
                                server,
                                plen
                            );
                        }
                    }
                    if let Err(e) = b.sendmmsg(send_fd, n) {
                        eprintln!("uplink sendmmsg: {e}");
                    }
                }
            })?
    };

    // ---------- downlink thread: wan UDP -> local UDP ----------
    let downlink = {
        let wan_fd = wan_sock.as_raw_fd();
        let local_fd = local_sock.as_raw_fd();
        let batch_n = args.batch;
        let bufsize = args.bufsize;
        let last_local = last_local.clone();
        thread::Builder::new()
            .name("spocon-dn".to_string())
            .spawn(move || -> io::Result<()> {
                let mut b = Batch::new(batch_n, bufsize);
                loop {
                    b.prep_recv(0);
                    let n = b.recvmmsg(wan_fd)?;
                    if n == 0 {
                        continue;
                    }
                    let dst = match last_local.load() {
                        Some(d) => d,
                        None => {
                            vlog!("[down?] wan recv {} pkts dropped (no local peer yet)", n);
                            continue;
                        }
                    };
                    let dst_sa = sock::sockaddr_in_v4(dst);
                    for i in 0..n {
                        let len = b.payload_len(i);
                        b.prep_send_slot(i, 0, len, &dst_sa);
                        if logging::verbose() {
                            let src = b.src_addr(i);
                            vlog!("[down] wan <- {} -> local {} {}B", src, dst, len);
                        }
                    }
                    if let Err(e) = b.sendmmsg(local_fd, n) {
                        eprintln!("local sendmmsg: {e}");
                    }
                }
            })?
    };

    let _ = uplink.join().expect("uplink thread panic");
    let _ = downlink.join().expect("downlink thread panic");

    drop(local_sock);
    drop(wan_sock);
    drop(raw_sock);
    Ok(())
}
