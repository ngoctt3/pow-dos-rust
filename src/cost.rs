//! Cost model & fleet extrapolation (advisory §10).

use crate::cli::CostArgs;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CostRow {
    pub target: String,
    pub packets_per_sec: f64,
    pub bandwidth_kbps: f64,
}

#[derive(Debug, Serialize)]
pub struct CostModel {
    pub r_thread_pps: f64,
    pub r_deg_pps: f64,
    pub cores_per_server: u64,
    pub servers: u64,
    pub wire_bytes: u64,
    pub rows: Vec<CostRow>,
}

fn kbps(pps: f64, wire_bytes: u64) -> f64 {
    // pps * bytes * 8 bits -> bits/s -> kbps
    pps * wire_bytes as f64 * 8.0 / 1000.0
}

pub fn compute(args: &CostArgs) -> CostModel {
    let n = args.cores as f64;
    let m = args.servers as f64;
    let wb = args.wire_bytes;

    let row = |target: &str, pps: f64| CostRow {
        target: target.to_string(),
        packets_per_sec: pps,
        bandwidth_kbps: kbps(pps, wb),
    };

    let rows = vec![
        row("degrade 1 thread (r_deg)", args.r_deg),
        row("stall 1 thread (r_thread)", args.r_thread),
        row("stall 1 server", n * args.r_thread),
        row("degrade 1 server", n * args.r_deg),
        row(&format!("stall {} servers", args.servers), m * n * args.r_thread),
        row(&format!("degrade {} servers", args.servers), m * n * args.r_deg),
    ];

    CostModel {
        r_thread_pps: args.r_thread,
        r_deg_pps: args.r_deg,
        cores_per_server: args.cores,
        servers: args.servers,
        wire_bytes: wb,
        rows,
    }
}

pub fn run(args: CostArgs) {
    let model = compute(&args);
    eprintln!(
        "[cost] r_thread={} pps  r_deg={} pps  cores={}  servers={}  wire={} B",
        model.r_thread_pps, model.r_deg_pps, model.cores_per_server, model.servers, model.wire_bytes
    );
    println!("{:<28} {:>16} {:>18}", "target", "packets/s", "bandwidth");
    println!("{}", "-".repeat(64));
    for r in &model.rows {
        println!(
            "{:<28} {:>16.0} {:>15.1} kbps",
            r.target, r.packets_per_sec, r.bandwidth_kbps
        );
    }
    println!();
    println!("(echo-loop variant, advisory §10.5: sustained attacker bandwidth ~= 0;");
    println!(" cost reduces to seed packets/s to maintain L loops — measure loop lifetime.)");
    println!();
    println!("{}", serde_json::to_string_pretty(&model).unwrap());
}
