//! spocon-server — high-throughput Rust port of randconnect's server-side
//! spoof path with spoofed source addresses on **both** legs:
//!
//!   * UPLINK   : spoofed UDP from the client arrives at `upstream-port`,
//!                kernel doesn't care about source IP. We forward the
//!                payload as plain UDP to `--h-out` (the real KCP/QUIC/...
//!                server) over a connected ephemeral UDP socket.
//!
//!   * DOWNLINK : replies from `--h-out` are read off that same ephemeral
//!                socket, wrapped in a fresh IPv4+UDP header with
//!                src=`--spoof-src` and dst=`--client`, and pushed out a
//!                raw `IP_HDRINCL` socket via `sendmmsg`.

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
    parse_v4, raw, sock, vlog, Tuning,
};

#[derive(Parser, Debug)]
#[command(
    name = "spocon-server",
    about = "spocon (Rust) server: receives spoofed UDP from a client, forwards to h_out, and spoofs replies back."
)]
struct Args {
    /// UDP port to bind on 0.0.0.0 for incoming (spoofed) packets from the client.
    #[arg(long)]
    upstream_port: u16,

    /// ip:port of the real upstream protocol server (kcp/quic/...).
    #[arg(long, value_parser = parse_v4)]
    h_out: SocketAddrV4,

    /// ip:port used as the source of spoofed downstream packets.
    #[arg(long, value_parser = parse_v4)]
    spoof_src: SocketAddrV4,

    /// Client public ip:port (port must match client's --wan-port).
    #[arg(long, value_parser = parse_v4)]
    client: SocketAddrV4,

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

    /// Skip UDP checksum on spoofed downlink packets (set checksum=0).
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
    let upstream_bind = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.upstream_port);
    let upstream = sock::bind_udp(upstream_bind, args.rcvbuf, args.sndbuf, args.busy_poll_us)?;

    let h_out_sock = sock::ephemeral_udp(args.rcvbuf, args.sndbuf, args.busy_poll_us)?;
    // connect() to h_out so the kernel filters incoming packets by source and
    // we can use a slightly cheaper send path.
    {
        let sa = sock::sockaddr_in_v4(args.h_out);
        let r = unsafe {
            libc::connect(
                h_out_sock.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let h_out_local = sock::local_addr_v4(&h_out_sock)?;

    let raw_sock = raw::open_raw_udp(args.sndbuf)?;

    info!(
        "spocon-server (rust)\n\
         \x20 upstream_listen: 0.0.0.0:{}\n\
         \x20 h_out:           {} (local ephemeral {})\n\
         \x20 spoof_src:       {}\n\
         \x20 client:          {}\n\
         \x20 batch:           {}\n\
         \x20 bufsize:         {}\n\
         \x20 rcvbuf/sndbuf:   {} / {}\n\
         \x20 udp checksum:    {}\n\
         \x20 verbose:         {}",
        args.upstream_port,
        args.h_out,
        h_out_local,
        args.spoof_src,
        args.client,
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

    let ip_id = Arc::new(AtomicU32::new(std::process::id() & 0xFFFF));

    // Static destinations.
    let h_out_sa = sock::sockaddr_in_v4(args.h_out);
    // For raw IPv4 send the kernel ignores the port in msg_name (the UDP
    // port is in the IP+UDP header we built). We still pass an address so
    // the kernel knows where to route; port is set to 0.
    let client_for_raw = sock::sockaddr_in_v4(SocketAddrV4::new(*args.client.ip(), 0));

    let template = SpoofTemplate::new(
        args.spoof_src.ip().octets(),
        args.spoof_src.port(),
        args.client.ip().octets(),
        args.client.port(),
    );

    // ---------- uplink thread: upstream UDP -> h_out UDP ----------
    let uplink = {
        let upstream_fd = upstream.as_raw_fd();
        let h_out_fd = h_out_sock.as_raw_fd();
        let batch_n = args.batch;
        let bufsize = args.bufsize;
        let h_out_addr = args.h_out;
        thread::Builder::new()
            .name("spocon-up".to_string())
            .spawn(move || -> io::Result<()> {
                let mut b = Batch::new(batch_n, bufsize);
                loop {
                    // Recv at offset 0: pure UDP forward, no header wrapping.
                    b.prep_recv(0);
                    let n = b.recvmmsg(upstream_fd)?;
                    if n == 0 {
                        continue;
                    }
                    for i in 0..n {
                        let len = b.payload_len(i);
                        b.prep_send_slot(i, 0, len, &h_out_sa);
                        if logging::verbose() {
                            let src = b.src_addr(i);
                            vlog!(
                                "[up  ] upstream <- {} -> h_out {} {}B",
                                src,
                                h_out_addr,
                                len
                            );
                        }
                    }
                    if let Err(e) = b.sendmmsg(h_out_fd, n) {
                        eprintln!("h_out sendmmsg: {e}");
                    }
                }
            })?
    };

    // ---------- downlink thread: h_out UDP -> raw spoofed IP -> client ----------
    let downlink = {
        let h_out_fd = h_out_sock.as_raw_fd();
        let raw_fd = raw_sock.as_raw_fd();
        let batch_n = args.batch;
        let bufsize = args.bufsize;
        let no_csum = args.no_udp_csum;
        let ip_id = ip_id.clone();
        let template = template;
        let spoof_src = args.spoof_src;
        let client = args.client;
        thread::Builder::new()
            .name("spocon-dn".to_string())
            .spawn(move || -> io::Result<()> {
                let mut b = Batch::new(batch_n, bufsize);
                loop {
                    // Recv at offset HEADER_ROOM so we can prepend IP+UDP in place.
                    b.prep_recv(HEADER_ROOM);
                    let n = b.recvmmsg(h_out_fd)?;
                    if n == 0 {
                        continue;
                    }
                    for i in 0..n {
                        let plen = b.payload_len(i);
                        let id = (ip_id.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let total = template.build_in_place(b.slot_mut(i), plen, id, !no_csum);
                        b.prep_send_slot(i, 0, total, &client_for_raw);
                        vlog!(
                            "[down] h_out -> spoof {} -> client {} {}B",
                            spoof_src,
                            client,
                            plen
                        );
                    }
                    if let Err(e) = b.sendmmsg(raw_fd, n) {
                        eprintln!("raw sendmmsg: {e}");
                    }
                }
            })?
    };

    // Hold ownership; threads run forever. Joining only returns on error.
    let _ = uplink.join().expect("uplink thread panic");
    let _ = downlink.join().expect("downlink thread panic");

    // Keep the OwnedFds alive for the lifetime of the process.
    drop(upstream);
    drop(h_out_sock);
    drop(raw_sock);

    Ok(())
}
