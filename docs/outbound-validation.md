# Outbound routing validation record

Local validation on 2026-11-22. Source baseline: `0b6b902` (unmodified main).
Implementation: branch `SOCKS5`. No deployed VPS or production configuration
was accessed or modified; all test endpoints and credentials were synthetic.

## Portable checks

Environment: macOS 27.2.1, ARM64. The repository's Rust 1.97.1 toolchain and
Rust 1.88.0 MSRV were installed in ignored local scratch storage. Python 3.14
and Homebrew OpenSSL were used because the system Python/LibreSSL do not meet
some existing operations-test requirements.

Passed:

- `scripts/check.sh full`: formatting, shell syntax, Clippy with denied
  warnings, ShellCheck, installer/release metadata checks, Python operations
  and performance tests, MSRV, complete Rust workspace tests.
- Final focused routing suite: 12 unit tests, including malformed protocol
  input, authentication downgrade, file snapshots, cancellation, no direct
  fallback, packet budget and active-association limits.
- H2/H3 SOCKS5 integration: 3 tests covering TCP, UDP, native DATAGRAMs,
  capsule fallback, policy denial, failure and control EOF.
- `check_config`'s live status/reload test now verifies external CIDR content
  changes require restart even when the file path is unchanged.
- Real Hysteria2 v2.14.0: isolated TCP/UDP round trips on HTTP/2 and HTTP/3,
  including both H3 datagram transports. Release binary SHA-256 was checked
  against the official release asset digest before execution. Local TLS
  verification remained enabled.
- Optimized workspace build. Clippy, focused tests and syntax checks were
  repeated after final implementation/test adjustments.

Initial failures identified environmental prerequisites (CMake, pinned Rust,
Python and OpenSSL) and two upstream protocol limitations. These were not
hidden by weakening the generic SOCKS5 tests:

- Hysteria2 closes both TCP directions after one relay direction ends. A
  response that requires upload EOF can be lost.
- Hysteria2 rejects empty UDP payloads and uses a 4096-byte internal message
  buffer as well as a 4096-byte SOCKS receive buffer. Internal headers also
  consume space. The documented 4000-byte complete SOCKS packet budget was
  verified with a 3990-byte IPv4 payload through H2; 64/1200-byte payloads
  were checked over both HTTP transports. Generic adapter tests retain
  zero-length and larger-datagram coverage with the deterministic peer.

See [routing configuration and compatibility](outbound-routing.md) for the
operational consequences; these upstream limits remain relevant to deployment.

## Local UDP measurements

Release builds, one H3 shard, two connections, one UDP stream per connection,
64-packet window, 1000 ms expiry, 64/1200-byte application payloads. All targets
and the Hysteria client/server pair ran on loopback. QUIC/target GSO remained
off. Both HTTP transports ran sequentially in each sample.

Fixed offered rate: 1000 packets/s per connection (H3) or stream (H2), 2000
packets/s aggregate, 2 seconds per transport, three repetitions per case.
All 36 transport samples had zero response shortfall. The table gives the
median of each run's histogram upper bound for p95 RTT (microseconds).

| Path | Payload | H3 p95, µs | H2 p95, µs |
| --- | ---: | ---: | ---: |
| Baseline DIRECT | 64 | 672 | 1088 |
| New DIRECT | 64 | 640 | 1088 |
| SOCKS5 + Hysteria2 | 64 | 736 | 1280 |
| Baseline DIRECT | 1200 | 928 | 1408 |
| New DIRECT | 1200 | 928 | 1600 |
| SOCKS5 + Hysteria2 | 1200 | 736 | 1024 |

Exploratory saturation: same connections/window/payloads, no offered-rate cap,
one 2-second repetition. These are observations, not capacity guarantees.

| Path | Payload | H3 received packets/s | H2 received packets/s | H3 / H2 response shortfall |
| --- | ---: | ---: | ---: | --- |
| Baseline DIRECT | 64 | 95183 | 109300 | 0% / 0% |
| New DIRECT | 64 | 95030 | 110652 | 0% / 0% |
| SOCKS5 + Hysteria2 | 64 | 52051 | 54126 | 0% / 0% |
| Baseline DIRECT | 1200 | 59399 | 102813 | 0% / 0% |
| New DIRECT | 1200 | 58322 | 106780 | 0% / 0% |
| SOCKS5 + Hysteria2 | 1200 | 33955 | 36177 | 0.143% / 0.152% |

The MASQUE process's median fixed-rate peak RSS was approximately 28 MiB in
all cases; saturation samples stayed approximately 30 MiB. Process CPU records
include setup and shutdown and exclude the Hysteria processes, so they are not
used to claim whole-system CPU savings. No CPU pinning, host-idle guarantee,
long-duration soak, descriptor sampling or external-path measurement was done.
Measurements preceded the final receive-side packet-budget guard for
IPv4-mapped IPv6 replies; that guard was subsequently covered by unit and
interop checks on both platforms. Docker Desktop was started during the first
fixed-rate repetition; this is an
additional source of noise. Do not infer that the proxy path is faster from
individual local latency measurements. The saturation figures show the added
path's cost, but longer repeated controlled measurements are needed to quantify
it reliably.

Reproduce using `scripts/network-bench.sh` and
`scripts/test-hysteria.py --benchmark` as described in the routing guide.
Raw scratch logs, generated certificates and binaries remain excluded from Git.

## Linux and release gates

Linux ARM64 Docker E2E passed all 12 scenarios, including existing TCP/UDP,
QUIC migration, policy/authentication and isolated CONNECT-IP/TUN forwarding.
The test Compose project and its network were removed afterward. The feature's
own SOCKS5 tests use ordinary sockets without TUN or network privileges.

The Linux ARM64 builder (Rust 1.88, optimized profile) also passed 12 outbound
unit tests, 3 H2/H3 SOCKS5 integration tests, and both real Hysteria2 v2.14.0
interop tests. This exercised the SOCKS5 send path through Linux `sendmmsg`,
with target GSO deliberately disabled for framed upstream traffic. The test
container was removed automatically after completion.

This local work is not authorization for deployment. Before promotion, validate the selected
client mode, country-prefix source/version, actual remote Hysteria path,
service limits, restart/rollback procedure and long-duration resource behavior.
The scheduled ASan/fuzz/resource-pressure release matrix remains a separate
release gate.
