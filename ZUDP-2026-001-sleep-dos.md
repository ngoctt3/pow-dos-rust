# ZUDP-2026-001 — Uncontrolled `sleep()` in UDP hot-path → asymmetric DoS

> **Internal security advisory + PoC specification.**
> Authorized defensive research on VNG zrtpserver (media relay). Do **not** run the
> PoC against any host you do not own or lack written authorization to test.
> This document is self-contained: an implementer (human or AI) can build the PoC in
> Rust from this file alone, without reading the C++ source.

---

## 1. Metadata

| Field | Value |
|---|---|
| Advisory ID | ZUDP-2026-001 |
| Title | Uncontrolled thread `sleep()` on short UDP datagrams enables low-cost availability DoS |
| Component | `zrtpserver` UDP media relay — `ServerEntry::serve()` receive loop |
| Location | `zrtpserver_project/src/zrtpserver/ZUdpServer.cpp:353-358` |
| Branch observed | `rocky/3.1.65_asr` (also present in prior versions with `length < 4`) |
| Class | CWE-400 (Uncontrolled Resource Consumption), CWE-405 (Asymmetric Resource Consumption), CWE-406 (Insufficient Control of Network Message Volume / reflection) |
| Severity | **High** |
| CVSS 3.1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5** |
| Authentication required | **None** (trigger is pre-auth) |
| Date | 2026-07-08 |

---

## 2. Executive summary

The UDP receive loop, on every datagram whose length is `<= 4` bytes, executes:

```
for (i = 0..3):
    sendto(original_datagram back to source)   // 3 reflected packets
    Poco::Thread::sleep(1)                      // 1 ms, blocking the IO thread
```

`Poco::Thread::sleep(1)` blocks the **entire IO thread** (wall-clock, not CPU-bound).
Each short datagram therefore costs the thread **~3 ms** of "do-nothing" time during
which it processes **zero** legitimate media. One IO thread can be driven to ~100%
stall with only **~300–333 short packets/second** (≈150 kbps). A stalled thread stops
relaying **all** calls/flows assigned to it, so the impact is disproportionate to the
attacker's spend.

The attack is **pre-authentication**: the `sleep` branch runs before any token/session
check, so no valid call, credential, or `private_key` is needed.

Because the server echoes the **unchanged** payload back to the packet's source address,
a single **spoofed** seed packet can also establish a **self-sustaining echo loop**
between two servers — or a server and itself — that keeps the involved threads pegged
**after the attacker stops sending** (CWE-406). This loop is the highest-impact variant
and is detailed in §3.3.

The current source revision's data-plane architecture (**NUMA/CPU affinity**,
**single listen port 4200 + `SO_REUSEPORT`**, **`SO_RCVBUF = 32 MB`**) is performance
tuning, **not** a security control, and does not address this bug. The single-port
reuseport hashing is exploitation-neutral, CPU affinity is orthogonal to a wall-clock
stall, and the 32 MB receive buffer actively **aggravates** it by making the induced
stall outlast the attack window. See §5 for the architectural analysis.

---

## 3. Vulnerability details

### 3.1 Annotated root cause

`ServerEntry::serve()` runs one blocking `epoll`/`recvmmsg` loop per IO thread. The
offending branch (reconstructed to the essential logic):

```cpp
int retval = recvmmsg(curFd, msgs, maxRecvMsg, 0, 0);
for (int i = 0; i < retval; i++) {
    int32_t length = msgs[i].msg_len;
    uint8_t* pMsg   = mesgArr[mesgIndex];
    sockaddr_storage* sock_addr = (sockaddr_storage*) msgs[i].msg_hdr.msg_name;

    if (length > 4) {
        // normal path: recvRtpMsg / recvRtcpMsg  (token/session verified downstream)
    } else {
        for (int i = 0; i < 3; i++) {                       // <-- 3 iterations
            sendto(curFd, pMsg, length, 0,
                   (struct sockaddr*) sock_addr, cliAddrLen); // <-- blind reflect to source
            Poco::Thread::sleep(1);                           // <-- 1 ms thread-wide stall
        }
    }
}
```

### 3.2 Why this is fatal for a real-time relay

1. **Wall-clock stall, single-threaded loop.** The IO thread is a serial
   `epoll_wait → recvmmsg → process` loop. `sleep()` parks the whole loop; queued
   media for every flow on this thread waits. ~3 ms/packet ⇒ ~333 pkt/s saturates one
   thread (`1000 ms / 3 ms`).
2. **Pre-auth trigger.** The branch fires on `length <= 4` before `recvRtpMsg()` and
   before any token/session validation — no valid call required.
3. **Collateral blast radius.** A thread serves many concurrent flows; stalling it
   drops/jitters *all* of them, not just the attacker's traffic.
4. **Real-time media breaks well below 100% stall.** Voice/video tolerate only tens of
   ms of added jitter/loss; ~30–50% thread stall already degrades calls. Effective
   damage threshold is **lower** than the full-saturation number.
5. **Reflection / amplification (secondary).** Each trigger packet emits **3** packets
   to the (attacker-chosen, spoofable) source address — a 3× packet-count reflection
   primitive, which escalates into a self-sustaining loop (see §3.3).

### 3.3 Amplification: self-sustaining echo loop (highest-impact variant)

The reflection primitive is not a one-shot: because the server echoes the **unchanged**
payload back to the **source address of the received datagram**, a single spoofed seed
packet can create a **self-sustaining echo loop** between two servers (or a server and
itself). This is the classic UDP echo/chargen loop (CWE-406).

**Why the loop never self-terminates:**

1. The echo re-sends the same `length` bytes, so the payload stays `<= 4` forever — every
   echoed packet re-enters the vulnerable branch. No length condition breaks it.
2. `sendto()` uses the receiving socket `curFd`, bound to `:4200`, so every echo carries
   **source port 4200**. If the seed packet's source port is set to **4200** (a port bound
   on the peer), each echo lands on the peer's live media socket and re-triggers.

**Preconditions:** ability to spoof the source IP (subject to BCP38 egress filtering,
§4) **and** setting the seed packet's source port to a bound port (**4200**). The source
port is fully attacker-controlled and never filtered; only the spoofed source IP depends
on network policy.

**Two-server loop (A ↔ B):**

```
Attacker ──► A:4200   [ spoofed src = B:4200 , payload = 3 bytes ]
A receives ──► echoes 3× ──► B:4200        (src = A:4200)
B receives (3B ≤ 4) ──► echoes 3× each ──► A:4200   (src = B:4200)
A receives ──► echoes ──► B ...            (never terminates on its own)
```

**Single-server self-loop (n = 1):** set the seed's `src = A:4200` and send to `A:4200`.
A echoes to itself; the datagram is delivered back to its own `:4200` socket and the loop
runs on **one** host from a single seed packet — no second server required.

**Growth and steady state.** Each received short packet emits **3** echoes (3× per hop,
nominally `3^n`). In practice the `sleep(1)` throttle caps a thread at ~333 received/s and
~1000 emitted/s, and since emission (3) exceeds consumption (1), packets accumulate in the
32 MB `SO_RCVBUF` (§5.3) until saturation. The result is not unbounded growth but a
**steady state in which the involved threads on both peers are pegged at maximum echo
throughput indefinitely** — from a single seed packet, and continuing **after the attacker
stops transmitting**.

**Weaponization across `n` servers.** With `n` relays and spoofing, an attacker seeds
independent loops (A↔B, C↔D, …) or a mesh, pinning threads across the fleet at negligible
cost (a handful of seed packets). This converts the bug from a bandwidth-metered flood
(§10) into a near-zero-cost, self-propagating availability attack, and is the
**highest-severity manifestation** of this finding.

---

## 4. Attack surface & preconditions

| Precondition | Status |
|---|---|
| Network reachability to the media UDP port (default **4200**) | Required (public-facing relay) |
| Valid call / token / session | **Not required** |
| Source-address spoofing | **Not required** (helpful for reflection & bucket steering) |
| Payload | Any UDP datagram with **1–4 byte** payload |

---

## 5. Deployment architecture and its interaction with the bug

> **Scope note.** The properties below are **architectural / performance features** of
> the current source revision (`rocky/3.1.65_asr`). They are **not** security controls
> and were not introduced to address this vulnerability. This section analyzes how the
> data-plane architecture *interacts* with the bug — it does not evaluate them as
> mitigations, because they are not.

Observed data-plane configuration under test:

- **Single listen port `4200`.** All RTP IO threads bind the same `(0.0.0.0, 4200)`
  with `SO_REUSEPORT` (kernel default 4-tuple hash; **no** eBPF/CBPF reuseport program).
- **CPU affinity per NUMA node** via `ZUtil::set_cpu_affinity`, with `SO_INCOMING_CPU`
  set per socket to align RX processing to the pinned core.
- **`SO_RCVBUF = SO_SNDBUF = 32 MB`** per socket.

### 5.1 Attacker's control over packet-to-thread placement

With one listen port, the kernel steers each datagram to one of the `N` reuseport
sockets by `hash(srcIP, srcPort, dstIP, dstPort=4200)`. Because `dstIP`/`dstPort` are
fixed and `srcIP` may be fixed (single attacker host), **`srcPort` is the entropy the
attacker controls**. Consequences for exploitation:

- A **fixed** source `(srcIP, srcPort)` always lands on **one** thread → precise
  per-thread targeting (~300 pps to stall it).
- **Varying** the source port sprays packets ~uniformly across **all** `N` threads →
  whole-server stall at `N × ~300 pps`.

Net effect: the single-port architecture changes *which flows* are affected (hash-based
placement instead of the older port-per-thread mapping) but **does not change the packet
budget** an attacker needs. It is exploitation-neutral, not protective.

### 5.2 CPU affinity / NUMA are orthogonal to a wall-clock stall

`Poco::Thread::sleep()` yields *wall-clock* time; the thread is descheduled regardless of
which core it is pinned to. Affinity, `SO_INCOMING_CPU`, and NUMA-local memory improve
throughput and latency of **legitimate** processing, but a pinned thread that is asleep
still relays nothing. These features neither help nor hinder this bug — they are simply
irrelevant to it.

### 5.3 The 32 MB receive buffer aggravates impact

This is the one architectural property that **worsens** the finding. While a thread
sleeps, the kernel keeps enqueuing arriving datagrams into the 32 MB `SO_RCVBUF`
(≈0.5 M packets at ~64 B each) instead of dropping them. Every queued short packet
re-enters the vulnerable branch on drain, so the thread falls progressively further
behind and the induced stall **outlasts the attack window** (measurable recovery time —
see §9). A smaller buffer would bound the backlog and cap recovery time; it would not,
however, remove the root cause.

---

## 6. Threat model

- **Attacker capability:** send UDP to `SERVER_IP:4200`; freely choose payload and source
  port; optionally spoof source IP.
- **Goal:** reduce/deny media availability (packet loss, jitter, dropped calls).
- **Not in scope for this PoC:** confidentiality/integrity (the bug is availability-only),
  and forging sessions (separate finding).

---

## 7. PoC objective — proof-of-work on ONE 40-core server

Produce **quantitative, reproducible evidence** that a small, measured packet rate
degrades legitimate media on a single production-representative host
(**40 cores ⇒ 40 RTP IO threads**, one listen port `4200`), then derive a cost model
to extrapolate to **80 servers**.

The deliverable is **not** "crash the server"; it is a *dose–response curve*:
attacker packet-rate (independent variable) vs. legitimate-flow degradation
(dependent variable). This is the industry-standard way to quantify an availability
DoS without ambiguity.

---

## 8. PoC design (implement in Rust)

### 8.1 Components

The PoC is three cooperating roles, ideally three binaries (or subcommands of one CLI):

1. **`victim-probe`** — emulates a legitimate client. Sends valid-length "media" packets
   (payload length **> 4**, e.g. 172 bytes to mimic a voice frame) at a fixed rate
   (e.g. 50 pps, typical RTP 20 ms ptime) to `SERVER_IP:4200` from a stable source
   `(srcIP, srcPort)`, and measures **round-trip behavior**: since the relay echoes/relays,
   record per-packet RTT and loss. This is the *sensor* that quantifies degradation.
   > Note: the relay only relays *authenticated* flows end-to-end. For a lab proof you
   > have two valid options — pick one and document it:
   > **(a)** run against a real established test call (preferred, most faithful), or
   > **(b)** if no call can be provisioned, measure the thread-stall proxy directly:
   > co-locate a lightweight `epoll` echo probe bound to the same reuseport group and
   > measure its service latency. State clearly which proxy was used.

2. **`attacker-flood`** — the load generator. Emits **1–4 byte** UDP datagrams to
   `SERVER_IP:4200` at a controlled rate, **ramping** through configured steps
   (e.g. 0 → 25 → 50 → 100 → 200 → 400 … pps *per thread-bucket*). Sprays across source
   ports to cover all `SO_REUSEPORT` buckets (see §8.4).

3. **`harness`** — orchestrates the ramp, aligns attacker steps with `victim-probe`
   windows, and emits a machine-readable results table (CSV/JSON): for each step record
   `{attacker_pps, attacker_bandwidth_kbps, probe_rtt_p50, probe_rtt_p99, probe_loss_pct}`.

### 8.2 Recommended crates

| Purpose | Crate |
|---|---|
| Raw UDP sockets, `SO_REUSEPORT`, bind options | `socket2` |
| Async runtime (or use OS threads) | `tokio` *or* `std::thread` + `std::net::UdpSocket` |
| High-precision latency histograms | `hdrhistogram` |
| CLI args | `clap` (derive) |
| Structured output | `serde` + `serde_json` / `csv` |
| Precise pacing | `std::time::Instant` + spin/sleep hybrid; `quanta` optional |
| (Optional) source-IP spoofing in lab | `pnet` / raw sockets (needs `CAP_NET_RAW`) |

### 8.3 `attacker-flood` algorithm (pseudocode)

```text
fn run_flood(target: SocketAddr, target_pps: u64, n_buckets: u32,
             duration: Duration, spoof: bool):
    payload = [0u8; 3]                      // length 3  (in 1..=4)
    n_workers = num_cpus()                  // saturate the loopback / NIC tx
    per_worker_pps = target_pps / n_workers

    parallel for w in 0..n_workers:
        // Each worker owns a disjoint slice of source ports so the union
        // of all packets hashes across ALL reuseport buckets on the server.
        socket = UdpSocket::bind("0.0.0.0:0")  // ephemeral; vary per send for spray
        pacer = RatePacer::new(per_worker_pps)
        while not done:
            pacer.wait_for_next_slot()
            // Spray: rotate source port to hit every reuseport bucket.
            // Easiest portable method: open K sockets on K different local ports,
            // round-robin sends across them (K >= n_buckets, e.g. K = 256).
            sock = pool[next_index % pool.len()]
            sock.send_to(&payload, target)
            record(sent += 1)
```

**Loop-seed mode (§3.3 variant).** In addition to the flood mode above, a loop-seed mode
emits a spoofed seed packet, then **stops transmitting**, and verification measures
whether/for how long the loop persists unattended (the key evidence for §10.5). The
source-spoofing packet-crafting mechanics, platform/privilege constraints, CLI surface,
and verification steps are documented separately in the companion implementation guide
**`ZUDP-2026-001-udp-spoof-poc-impl.md`** — this advisory intentionally does not repeat
the low-level implementation. Enforce isolated-lab guards (§12) before enabling this mode.

Key requirements:

- **Payload length ∈ {1,2,3,4}** — this is the *only* condition to hit the vulnerable
  branch. Use 3.
- **Precise pacing.** At high pps, `thread::sleep` granularity is too coarse; use a
  busy-wait/`Instant`-based pacer or `quanta`. Report *actual* achieved pps, not target.
- **Ramp, don't slam.** Start at 0 and step up. The knee of the curve is the finding.

### 8.4 Covering all `SO_REUSEPORT` buckets

The server hashes `(srcIP, srcPort, dstIP, dstPort=4200)` to one of `N` sockets
(`N` = number of IO threads ≈ 40). Because `dstIP`/`dstPort` are fixed and `srcIP` may be
fixed (single attacker host), **`srcPort` is the only entropy** the kernel hashes over.

- To **spread evenly across all N threads**: send from **many** distinct source ports
  (a pool of e.g. 256 ephemeral ports). The hash then distributes ~uniformly, covering
  all buckets. This is the "kill the whole server" mode.
- To **target one thread**: fix a single `srcPort` and increase pps on it (~300 pps).
  All packets land on one bucket. Useful to demonstrate per-thread threshold precisely.
- Do **not** assume a particular hash; treat it as a black box and *verify empirically*
  by measuring which buckets degrade (via the probe) as you add source ports.

### 8.5 `victim-probe` measurement

```text
fn run_probe(target, pps=50, payload_len=172, window):
    hist = Histogram::new()
    seq = 0
    for each tick at `pps`:
        stamp = now()
        send_to(target, packet_with(seq, stamp))
        seq += 1
    // separate rx task
    on receive(pkt):
        rtt = now() - pkt.stamp
        hist.record(rtt)
        mark seq as received
    at window end: emit { p50, p99, p99.9, loss_pct = 1 - received/sent }
```

---

## 9. Measurement methodology & success criteria

1. **Baseline.** Run `victim-probe` alone for T seconds. Record `rtt_p50_base`,
   `rtt_p99_base`, `loss_base` (should be ~0).
2. **Ramp.** For each attacker step `pps_k`, run for a fixed dwell (e.g. 30 s) with the
   probe active. Record the probe metrics per step.
3. **Curve.** Plot `probe_rtt_p99` and `probe_loss_pct` vs `attacker_pps`.
4. **Report two thresholds:**
   - **`T_degrade`** — attacker pps at which `rtt_p99 > 2× base` *or* `loss > 1%`
     (first user-perceptible degradation).
   - **`T_stall`** — attacker pps at which `loss > 50%` for the targeted bucket(s)
     (thread effectively dead).
5. **Per-thread vs whole-server.** Run once in single-source-port mode (per-thread
   threshold) and once in spray mode (whole-server threshold).

**Success = a monotonic dose–response curve** showing degradation begins at a packet
rate far below the server's legitimate capacity, with the induced stall outlasting the
attack window (evidence of the 32 MB backlog effect — measure recovery time after
stopping the flood).

---

## 10. Cost model & extrapolation to 80 servers

### 10.1 Symbols

| Symbol | Meaning | Reference value* |
|---|---|---|
| `s` | thread-seconds consumed per short packet | ~3 ms = 0.003 s |
| `r_thread` | packets/s to fully stall one thread = `1 / s` | ~333 pps |
| `r_deg` | packets/s for first perceptible degradation of one thread | measured (`T_degrade`), expect ~50–150 pps |
| `N` | IO threads per server (≈ cores) | 40 |
| `M` | number of servers | 80 |
| `L` | wire size of a trigger packet | payload 3 B + UDP 8 + IPv4 20 + Eth 14 = **45 B** (≈360 bits) |

\* Reference values are estimates; **replace with measured numbers from §9**.

### 10.2 Formulas

```
Packets/s to stall one full server      = N * r_thread
Packets/s to stall the fleet            = M * N * r_thread
Bandwidth to stall one full server      = N * r_thread * L * 8      (bits/s)
Bandwidth to stall the fleet            = M * N * r_thread * L * 8
```

Use `r_deg` instead of `r_thread` for the (cheaper, more realistic) "degrade service"
figure.

### 10.3 Worked example (reference values — confirm with measurements)

| Target | Packets/s | Bandwidth (@45 B) |
|---|---|---|
| Degrade 1 thread (`r_deg≈100`) | 100 pps | ~36 kbps |
| Stall 1 thread (`r_thread≈333`) | 333 pps | ~120 kbps |
| Stall 1 server (40 threads) | ~13.3 k pps | ~4.8 Mbps |
| **Stall 80 servers** | **~1.07 M pps** | **~384 Mbps** |
| **Degrade 80 servers** (`r_deg`) | **~320 k pps** | **~115 Mbps** |

**Interpretation for stakeholders:** taking the entire 80-server fleet to full stall
costs on the order of a few hundred Mbps of *tiny* packets — within reach of a single
rented server or a small botnet — whereas merely degrading call quality fleet-wide is
~100 Mbps. This is an **asymmetric** attack: the attacker's cost is a small fraction of
the capacity they deny, because the damage is metered in *stolen thread-time* (3 ms/pkt),
not in bandwidth. The current data-plane architecture (single-port reuseport, NUMA
affinity) does not change these numbers; the 32 MB receive buffer only prolongs the
stall (§5).

### 10.4 Sensitivity

The dominant term is `s` (thread-seconds/packet). If a fix removes the `sleep`
(`s` drops from 3 ms to sub-µs), `r_thread` rises by **~1000×**, and the attack
collapses back to an ordinary volumetric flood that must saturate real CPU/bandwidth —
i.e. the asymmetry disappears. This is the quantitative justification for the fix.

### 10.5 Echo-loop cost (breaks the bandwidth model)

The bandwidth figures above assume the attacker must *continuously* transmit. The
self-sustaining echo loop (§3.3) defeats that model: once seeded, a loop is fed by the
servers echoing each other, so the attacker's **sustained** bandwidth for an active loop
is ≈ **0**. Cost reduces to the one-time seed packets — on the order of one spoofed
packet per loop. Practical caveats:

- Requires the ability to spoof source IP (subject to BCP38, §4).
- Loops decay over time as buffer-overflow drops break the chain; an attacker re-seeds
  periodically (still negligible bandwidth) to keep `L` loops alive across the fleet.
- The correct cost metric for this variant is therefore **"seed packets per second to
  maintain `L` loops"**, not aggregate flood bandwidth. Measure loop lifetime in the PoC
  (§9 recovery-time measurement) to derive the re-seed rate.

---

## 11. Remediation

**Primary fix (one line of intent):** delete the reflect+sleep branch; silently drop
short datagrams.

```cpp
if (length > 4) {
    // normal processing
} else {
    continue;   // drop; no reflection, no sleep
}
```

Secondary hardening:
- Never call a blocking `sleep()` anywhere inside the `epoll`/`recvmmsg` IO loop.
- If a short-packet keep-alive/echo is genuinely required, respond **once**, without
  sleeping, and only **after** source validation.
- Consider per-source-IP rate limiting on the ingress path.
- Re-evaluate `SO_RCVBUF = 32 MB` against expected burst size to bound backlog.

**Re-test after fix:** re-run §9. Expect the dose–response curve to flatten — no
degradation until the attacker approaches genuine line-rate/CPU saturation. Confirm
`r_thread` increased by ~3 orders of magnitude.

---

## 12. Safety, authorization & blast-radius controls

- Run **only** against hosts you own / have written authorization for. Use an isolated
  lab or a maintenance window on a drained node.
- Build a **hard kill switch** (max duration, max pps ceiling, `--i-have-authorization`
  flag) into `attacker-flood`.
- Prefer **loopback or a private test VLAN**; if source-IP spoofing is exercised, keep it
  strictly on an isolated segment (egress spoofed packets are illegal on shared networks).
- Log every run (target, rate, duration, operator) for auditability.
- Coordinate with on-call: the induced stall can outlast the test (32 MB backlog).
- **Echo-loop caution (§3.3):** a spoofed seed can create a self-sustaining loop that
  continues after you stop transmitting. Do **not** exercise the loop variant against
  shared infrastructure. Test it only on isolated hosts, keep the involved ports firewalled
  from other systems, and have an out-of-band way to flush socket buffers / restart the
  process to break a loop. Never point a loop at a host you cannot forcibly reset.

---

## 13. Implementation checklist (for the Rust session)

- [ ] `clap` CLI: `attack`, `probe`, `harness` subcommands; global `--target`,
      `--i-have-authorization`, `--max-pps`, `--max-secs`.
- [ ] `attacker-flood`: 1–4 byte payload; source-port pool (≥256) for reuseport spray;
      single-port mode for per-thread threshold; `Instant`-based pacer; report achieved pps.
- [ ] `attacker-flood --mode loop-seed`: seed-then-stop; measure loop persistence for
      §10.5. Implementation of the spoofing itself → see companion guide
      `ZUDP-2026-001-udp-spoof-poc-impl.md`.
- [ ] `victim-probe`: paced valid-length sender (len > 4), RTT via `hdrhistogram`,
      loss via seq tracking; JSON/CSV output.
- [ ] `harness`: ramp schedule, dwell time, baseline capture, post-attack recovery-time
      measurement; emit results table matching §9.
- [ ] Compute and print the §10 cost model from the *measured* `r_thread` / `r_deg`.
- [ ] Kill switch + duration/rate caps enforced before any packet is sent.

---

## 14. References

- CWE-400: Uncontrolled Resource Consumption
- CWE-405: Asymmetric Resource Consumption (Amplification)
- CWE-406: Insufficient Control of Network Message Volume (Reflection)
- CWE-834: Excessive Iteration
- Vulnerable code: `zrtpserver_project/src/zrtpserver/ZUdpServer.cpp:353-358`
- Companion implementation guide (UDP source-spoofing CLI, echo-loop verification):
  `ZUDP-2026-001-udp-spoof-poc-impl.md`
