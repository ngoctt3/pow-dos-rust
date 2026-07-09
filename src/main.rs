//! ZUDP-2026-001 — authorized defensive PoC harness.
//!
//! Quantifies the short-datagram `sleep()` availability DoS in zrtpserver as a
//! dose–response curve (attacker pps vs. legitimate-flow degradation), plus a
//! fleet cost model and an optional (Linux-only) echo-loop seeder.
//!
//! AUTHORIZED USE ONLY. See ZUDP-2026-001-sleep-dos.md §12 and the companion
//! spoof guide §7 for the mandatory safety controls, all enforced in `guard.rs`.

mod attack;
mod cli;
mod cost;
mod diag;
#[cfg(target_os = "linux")]
mod fastsend;
mod guard;
mod harness;
mod pacer;
mod probe;
mod spoof;

use clap::Parser;
use cli::{Cli, Command};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Attack(a) => attack::run(a, &cli.guards),
        Command::Probe(a) => probe::run(a, &cli.guards),
        Command::Harness(a) => harness::run(a, &cli.guards),
        Command::Cost(a) => {
            cost::run(a);
            Ok(())
        }
        Command::Diag(a) => diag::run(a, &cli.guards),
        Command::LoopSeed(a) => spoof::run(a, &cli.guards),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
