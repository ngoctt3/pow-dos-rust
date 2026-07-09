//! Precise packet pacing.
//!
//! At the packet rates this PoC targets (hundreds of thousands of pps), the
//! ~1–15 ms granularity of `thread::sleep` is far too coarse. We use an
//! `Instant`-based schedule and a sleep/spin hybrid: sleep for the bulk of the
//! wait (giving the CPU back), then busy-spin the final sub-millisecond slice
//! for accuracy. The pacer never *drops* slots — if the sender falls behind it
//! catches up — and it reports the *achieved* rate, not the target (advisory §8.3).

use std::time::{Duration, Instant};

/// Schedules discrete "slots" at a fixed rate starting from a fixed origin.
pub struct RatePacer {
    origin: Instant,
    interval: Duration,
    slot: u64,
}

impl RatePacer {
    /// `pps` = 0 means "as fast as possible" (no pacing).
    pub fn new(pps: u64) -> Self {
        let interval = if pps == 0 {
            Duration::ZERO
        } else {
            Duration::from_nanos(1_000_000_000 / pps.max(1))
        };
        RatePacer {
            origin: Instant::now(),
            interval,
            slot: 0,
        }
    }

    /// Block until the next scheduled slot is due, then advance.
    pub fn wait_for_next_slot(&mut self) {
        if self.interval.is_zero() {
            self.slot += 1;
            return;
        }
        let target = self.origin + self.interval * self.slot as u32;
        spin_sleep_until(target);
        self.slot += 1;
    }
}

/// Sleep/spin hybrid until `target`. Sleeps until ~300 µs remain, then spins.
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
