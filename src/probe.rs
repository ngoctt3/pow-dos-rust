//! victim-probe (advisory §8.5).
//!
//! Emulates a legitimate client: paced, valid-length (> 4 byte) datagrams to the
//! relay, measuring round-trip latency and loss. This is the *sensor* that
//! quantifies degradation while the flood runs.
//!
//! Proxy caveat (advisory §8.1 note): a production relay only relays *authenticated*
//! flows end-to-end, so an unauthenticated probe may not observe true echoes. For a
//! faithful lab result, run the probe inside an established test call, OR run a
//! co-located echo responder bound to the same reuseport group and treat its service
//! latency as the thread-stall proxy. State which proxy was used in the writeup.

use crate::cli::{GlobalGuards, ProbeArgs};
use crate::guard;
use crate::pacer::RatePacer;
use hdrhistogram::Histogram;
use serde::Serialize;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Minimum payload to carry the 16-byte [seq|send_nanos] measurement header.
const HDR: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct ProbeStats {
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f64,
    pub rtt_p50_us: u64,
    pub rtt_p99_us: u64,
    pub rtt_p999_us: u64,
    pub rtt_max_us: u64,
}

pub fn validate_payload_len(len: usize) -> Result<(), String> {
    if len <= 4 {
        return Err(format!("probe payload_len must be > 4 (legitimate media frame); got {len}"));
    }
    if len < HDR {
        return Err(format!("probe payload_len must be >= {HDR} to carry the measurement header; got {len}"));
    }
    Ok(())
}

/// CLI entry point.
pub fn run(args: ProbeArgs, guards: &GlobalGuards) -> io::Result<()> {
    validate_payload_len(args.payload_len).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    guard::authorize(guards, args.pps, args.secs)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

    let stop = Arc::new(AtomicBool::new(false));

    eprintln!(
        "[probe] target={} pps={} payload_len={} window={}s",
        args.target, args.pps, args.payload_len, args.secs
    );
    let stats = run_probe(
        args.target,
        args.bind,
        args.pps,
        args.payload_len,
        Duration::from_secs(args.secs),
        stop,
    )?;
    println!("{}", serde_json::to_string_pretty(&stats).unwrap());
    Ok(())
}

/// Run the probe for `window` (or until `stop`). Shared by the harness.
pub fn run_probe(
    target: SocketAddr,
    bind: SocketAddr,
    pps: u64,
    payload_len: usize,
    window: Duration,
    stop: Arc<AtomicBool>,
) -> io::Result<ProbeStats> {
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let rx_sock = sock.try_clone()?;

    let origin = Instant::now();
    let deadline = origin + window;
    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let hist: Arc<Mutex<Histogram<u64>>> =
        Arc::new(Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 3).unwrap()));

    // Receiver task: drains echoes, records RTT.
    let rx = {
        let received = Arc::clone(&received);
        let hist = Arc::clone(&hist);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            // Keep draining slightly past the deadline to catch in-flight echoes.
            let rx_deadline = deadline + Duration::from_millis(500);
            while Instant::now() < rx_deadline && !stop.load(Ordering::Relaxed) {
                match rx_sock.recv_from(&mut buf) {
                    Ok((n, _)) if n >= HDR => {
                        let send_nanos = u64::from_be_bytes(buf[8..16].try_into().unwrap());
                        let now_nanos = origin.elapsed().as_nanos() as u64;
                        let rtt_us = now_nanos.saturating_sub(send_nanos) / 1000;
                        received.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut h) = hist.lock() {
                            let _ = h.record(rtt_us.max(1));
                        }
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
        })
    };

    // Sender: paced valid-length datagrams carrying [seq|send_nanos].
    let mut pacer = RatePacer::new(pps);
    let mut packet = vec![0u8; payload_len];
    let mut seq: u64 = 0;
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        pacer.wait_for_next_slot();
        let send_nanos = origin.elapsed().as_nanos() as u64;
        packet[0..8].copy_from_slice(&seq.to_be_bytes());
        packet[8..16].copy_from_slice(&send_nanos.to_be_bytes());
        match sock.send_to(&packet, target) {
            Ok(_) => {
                sent.fetch_add(1, Ordering::Relaxed);
                seq += 1;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }

    let _ = rx.join();

    let sent_n = sent.load(Ordering::Relaxed);
    let recv_n = received.load(Ordering::Relaxed);
    let h = hist.lock().unwrap();
    let loss = if sent_n == 0 {
        0.0
    } else {
        (1.0 - (recv_n as f64 / sent_n as f64)).max(0.0) * 100.0
    };
    Ok(ProbeStats {
        sent: sent_n,
        received: recv_n,
        loss_pct: loss,
        rtt_p50_us: h.value_at_quantile(0.50),
        rtt_p99_us: h.value_at_quantile(0.99),
        rtt_p999_us: h.value_at_quantile(0.999),
        rtt_max_us: h.max(),
    })
}
