# VibeOS native TCP segmentation experiment

Based on allegro0132/smoltcp `main` at
`efcba2efc87b6dcc8a2953de5768dbcc83b8fac6` (smoltcp 0.14.0).
The original patch was developed against 0.13.1, upstream
`e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897`.
The main branch already provides generic `segmentation-offload` and congestion
window accounting. This port preserves both and adds the bounded VibeOS
`tcp-segmentation` compatibility interface. The original 0BSD license is retained.
VibeOS uses this repository as a commit-pinned submodule and patches crates.io
smoltcp to the local path.

The optional `tcp-segmentation` feature adds a logical Ethernet request size
capability and explicit TCP MSS metadata. Neither changes the wire MTU or SYN MSS.
Defaults remain None. Only Ethernet/plain-header IPv4 ACK/PSH data in Established
or CloseWait uses native large sends; control, FIN, timestamps and very small peer
MSS retain ordinary dispatch. Logical requests are capped at 32 KiB including
Ethernet headers, the receive window and remaining congestion window. In-flight
bytes are subtracted for this opt-in mode. Data stays in the TCP retransmission
buffer until ACKed. Failed emit does not advance sequence state; partial ACK and
RTO retain the unsatisfied suffix. Metadata is required even below the wire MTU
when a logical request exceeds the peer's smaller MSS.

The IPv4 emit path accepts oversized buffers only with validated explicit TCP
segmentation metadata and the advertised capability. A consumer advertising the
capability must provide lossless hardware or software segmentation. VibeOS supports both a bounded software segmentation fallback and a native
pooled FIFO carrying segmentation tickets to its EQoS hardware TSO consumer.
The latter copies a complete admitted request into driver-owned DMA buffers
before releasing the pool slot; backpressure retains the whole request.

Validation command:

```
cargo test --lib \
  --no-default-features --features \
  std,medium-ip,medium-ethernet,proto-ipv4,socket-tcp,socket-tcp-reno,tcp-segmentation
```

The tests cover native large-send retry/RTO, congestion and receive
window limits, partial ACK suffix retransmission, control-path fallback and
metadata/MTU/checksum propagation. VibeOS protocol tests additionally exercise
real TCP sessions, one-slot fallback backpressure, sequence wrap and revocation.
Before this main-branch port, on Milk-V Mars, the complete VibeOS direct TSO integration measured 920.18 and
925.13 Mbps in two 20-second TCP transmit runs at MTU 1500. This is a system-level
result, not an isolated measurement of this patch; receive throughput and CPU
efficiency remain separate work.

## DHCP server selection

Ported from the earlier VibeOS 0.13.1 vendor tree when the two lines of work
were merged. Only `src/socket/dhcpv4.rs` is affected:

- REQUESTING and non-rebinding RENEWING ignore replies whose option 54 does
  not match the selected server identifier.
- Successful REBINDING records the responding server for future renewals.
- Unicast requests use the server identifier address, including when the
  offer's IP source differs from that identifier.

[RFC 2131 sections 4.1 and 4.4.5](https://www.rfc-editor.org/rfc/rfc2131.txt)
provide the unicast-address and renewal/rebinding context. Server-ID filtering
is transaction scoping, not cryptographic server authentication: a peer able
to spoof the selected identifier and transaction remains outside this guard.

Regression tests live in VibeOS `components/net-protocol/tests/router_dhcp.rs`
and exercise full DHCP wire messages through the VibeOS control wrapper. Run:

```
cargo test -p vibeos-net-protocol
cargo test --lib --no-default-features \
  --features std,medium-ethernet,proto-ipv4,socket-dhcpv4,socket-tcp,socket-tcp-reno \
  socket::dhcpv4::test
```

Keep this patch explicit when rebasing the fork; do not drop it without
rerunning these failure-reproducing tests.
