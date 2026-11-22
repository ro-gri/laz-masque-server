# Outbound routing validation record

Validation started locally on 2026-11-22. Source baseline: `0b6b902`
(unmodified main). Implementation: branch `SOCKS5`. The initial series did
not access a VPS. Later Linux sections use an explicitly authorized disposable
test host; production configuration was not changed. All protocol test
endpoints and credentials were synthetic.

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

## Apple Network Relay review (2026-11-22)

Reviewed branch `SOCKS5` at `fb43557` for the topology Apple Network Relay ->
MASQUE A -> country CIDRs DIRECT / local SOCKS5 client -> encrypted exit B.
Apple describes Network Relay as TCP/UDP connection proxying, not an IP VPN:
https://developer.apple.com/videos/play/wwdc2023/10002/
The applicable server paths are CONNECT and CONNECT-UDP; CONNECT-IP can remain
disabled. Both SOCKS5 transport fixtures already disable IP proxying.

Protocol-level fit is confirmed by source review and local tests, not by an
iPhone session. No iOS device/profile was exercised. The actual profile must
match listener TLS identity and authentication, HTTP/3 and HTTP/2 endpoints,
and the configured CONNECT-UDP URI template. Basic authentication requires
preemptive `Proxy-Authorization`; the server does not issue a challenge.
The profile's domain/app scope also determines which traffic reaches A.
System DNS resolution on A is outside the outbound routing policy.

Repeated checks passed: 12 outbound unit tests, 3 focused H2/H3 SOCKS tests,
2 isolated real Hysteria2 tests, and the complete H2/H3 integration suites
(78 + 43 passed; the two real-Hysteria tests are normally ignored and were
run separately). No VPS was accessed. awg-wireproxy interoperability was not
executed; supporting SOCKS5 in principle is not a substitute for that test.

Resource review:

- CIDR intervals are built once and shared, with binary lookup during target
  setup, not per packet. Metrics currently repeat the lookup once per attempt;
  this is minor setup work, not a packet-path cost. There is no online GeoIP
  request, embedded VPN engine, or additional userspace TCP/IP stack.
- TCP reuses the existing relay after SOCKS negotiation. UDP adds one control
  TCP connection per association, framing copies and 10/22-byte SOCKS headers.
  HTTP/2 reuses its send scratch buffer; HTTP/3 reuses bounded send staging.
  Control lifetime is readiness-driven, not a polling loop. Association and
  setup limits bound counts, not total process memory including socket buffers.
- DIRECT keeps the original I/O fast paths. Proxied H3 UDP receives one packet
  per read/channel message instead of the DIRECT native Linux recvmmsg batch.
  It also disables target GSO. This is a real throughput/CPU tradeoff; batching
  framed receive packets is a possible future optimization requiring Linux
  measurements and malformed/truncated-packet regression coverage.
- H3 capsule fallback and H2 may retain roughly 64 KiB receive buffers per
  tunnel even with the Hysteria 4000-byte packet budget. This is bounded but
  not a claim of minimum possible memory at high association counts.
- Hysteria client CPU/memory and kernel socket memory are additional costs.
  Existing MASQUE-only RSS and short loopback benchmarks cannot establish
  total A-side resource use or absence of leaks under a long soak.

Conclusion: the architecture fits Network Relay without TUN, but neither
zero overhead nor fully optimized UDP throughput is established. The upstream
half-close, empty-datagram and packet-size limitations documented above remain.

Fresh fixed-load smoke measurements used 1200-byte payloads, two connections,
2000 packets/s aggregate, and 10 seconds each for H3 and H2, sequentially.
The new server was explicitly rebuilt from the reviewed source. An initial
attempt accidentally used a stale baseline executable in target/release;
its purported new-version results were discarded. The baseline row below is
the successful baseline run; new rows use the verified rebuilt executable.

| Server path | CPU seconds (MASQUE only) | Peak RSS bytes | H3 / H2 response shortfall |
| --- | ---: | ---: | --- |
| Baseline DIRECT | 3.413 | 29720576 | 0 / 0 |
| Current DIRECT | 3.367 | 29687808 | 0 / 0 |
| Current SOCKS5 + Hysteria2 | 2.575 | 29327360 | 0 / 1 of 20000 |

These are single macOS loopback samples, not statistically controlled CPU
comparisons. CPU accounting includes process startup/shutdown and excludes
Hysteria client/server, kernel memory, and load generators. Lower MASQUE-only
CPU on the proxy row is not evidence that the complete proxy path costs less.
One H2 proxied packet expired; its cause was not isolated. This does not
establish loss-free operation or replace a Linux load/soak test. Formatting
and shell quick checks and git diff whitespace checks also passed. No runtime
source or deployed configuration changed during this review.

## DIRECT-only reload validation (2026-11-22)

Implemented `reload-direct-cidrs` over the existing private local socket.
Validated 14 outbound unit tests, including live TCP/UDP survival and retained
setup snapshots, plus a separate evidence-ordering regression test. The real
CLI/status integration verifies changed/unchanged/rejected outcomes, retaining
old data after an invalid file, ignoring changed TOML/file-path settings, and
leaving pending TLS/Basic updates unapplied. Removing the upstream password
file does not prevent a DIRECT-only reload: startup credentials remain loaded.

`scripts/check.sh full` passed (format/shell, Clippy, operations checks, MSRV
and workspace tests). The evidence-ordering test was added afterward and passed
separately; final all-target Clippy and whitespace checks also passed. Both
real Hysteria2 H2/H3 interop tests passed again.

Linux ARM64 release build and all 12 Docker E2E scenarios passed. The first
attempt failed before traffic testing because an existing local test certificate
could not be decoded; retry used freshly generated OpenSSL 3 test certificates
mounted only into the isolated test container. Existing certificates were not
changed. A separate Linux runtime-container test verified the command's
unchanged/update/error rollback behavior and independence from a removed TOML
file. Test containers and their Compose network were removed afterward.

No production endpoint was accessed or deployed. No new per-packet lookup,
lock, polling task or dependency was introduced. Each new TCP/UDP setup clones
one route snapshot under a short read lock; old snapshots remain alive only
while in-flight setups retain them. File loading/sorting is serialized on a
blocking worker. This review does not quantify high-rate connection-setup lock
contention or long-duration memory behavior under repeated reloads.


## SOCKS5 receive-buffer sizing (2026-11-22)

On branch `SOCKS5`, without the experimental receive batching, H2 and H3 now
size their SOCKS5 receive buffer to the smaller of the transport packet bound
and configured upstream packet bound, plus one truncation sentinel byte.
IPv4, IPv6 and IPv4-mapped IPv6 remain accepted. At a 4000-byte upstream limit,
the capsule-path buffer drops from 65550 to 4001 bytes per tunnel, saving
61549 requested allocation bytes (15.03 MiB for 256 tunnels). Native H3 keeps
its smaller transport bound; DIRECT is unchanged. No per-packet lookup,
new allocation, lock, dependency or Hysteria-specific default was added.

Validation: macOS full checks (Clippy, scripts, MSRV, workspace tests), Linux
ARM64 release build and 496 library tests, both real Hysteria2 H2/H3 interop
tests, and all 12 Docker E2E scenarios passed. The new real-socket regression
covers empty, exact-limit, limit-plus-one and larger truncated datagrams,
IPv4/IPv6 and mapped IPv4 headers, preserving the next valid datagram, and
allocation bounds for both 4000 and 65507-byte configurations. An initial
macOS operations-script check selected system LibreSSL and failed on an
unsupported verification option; rerunning the full check with OpenSSL 3
passed. Isolated Linux containers and the E2E network were removed.


Resource comparison uses local macOS ARM64 release binaries, real Hysteria2
v2.14.0 over loopback, one shard, packet budget 4000, window 64 and expiry
1000 ms. H3 then H2 each run for eight seconds in one server process. The
8-tunnel workload uses 1200-byte payloads at 8000 packets/s; the 256-tunnel
workload uses 64-byte payloads at 2560 packets/s (8 connections × 32 streams).
Three repetitions alternate before/after order. Both binaries were freshly
built from the same branch, before and after this buffer-only change:

- Before SHA-256: `65d49b6ea87b6d564362ef57b93ffab4c321090d1bf52b276723705d3cad25cc`
- After SHA-256: `124207d575e3b787dbe6a0608816b3d1fa88e9eec194701ce7d3c502f7c4e275`

CPU and peak RSS cover only MASQUE, including startup/shutdown, excluding
Hysteria, generators and kernel memory. Short runs on a shared developer host
cannot establish statistical significance or predict Linux production RSS.
Raw per-run logs, runner and JSON remain in ignored `work/udp-buffer-results`
and `work/run-udp-buffer-bench.py`. No VPS was accessed or changed.

All 12 samples completed successfully. Medians:

| Workload | CPU seconds before → after | Peak RSS MiB before → after | H3 response shortfall % before → after | H2 response shortfall % before → after |
| --- | ---: | ---: | ---: | ---: |
| 8 tunnels, 1200 B | 5.863 → 5.894 | 29.78 → 29.53 | 0.0016 → 0 | 0 → 0.0016 |
| 256 tunnels, 64 B | 3.274 → 3.219 | 37.92 → 34.73 | 1.5625 → 0.7813 | 2.8320 → 3.9063 |

Median H3/H2 receive rates were 7999.875/7998.875 before and
8000/7999.875 after for the small association count, and 2520/2487.5 before
and 2540/2460 after for 256 tunnels. Median H3/H2 p95 RTT was 768/1472 µs
in both versions for 8 tunnels; for 256 tunnels it was 2176/19456 µs before
and 2560/19456 µs after.

Observed peak RSS fell by 3.19 MiB (8.4%) at 256 tunnels; the physical-memory
saving is smaller than the 15.03 MiB requested-buffer reduction. CPU was
approximately unchanged (+0.5% at 8 tunnels, -1.7% at 256); no CPU speedup
is established. Both versions lose responses at 256 tunnels, with higher H2
shortfall in the new-version median; the cause is not isolated. These runs
therefore support the narrower allocation reduction and observed RSS saving,
not a loss-free, faster or universally lower-resource gateway claim.

## H2 256-tunnel loss diagnosis (2026-11-22)

Scope: local macOS ARM64, the same before/after binaries above, Hysteria2
v2.14.0, 8 H2 connections × 32 UDP streams, 64-byte application payloads,
10 packets/s per stream for eight seconds (20480 requests). No VPS access.
Runtime source was not changed during this diagnosis. Temporary diagnostic
scripts, synthetic endpoint logs and per-run artifacts remain in ignored
`work/h2-loss*`; diagnostic child processes exit with their local test runners.

The original load generator gives every stream the same start instant and
pacing phase (`tools/masque-e2e/src/http2.rs`). Consequently this workload
creates bursts of roughly 256 packets every 100 ms, rather than a uniformly
spaced aggregate 2560 packets/s. The reported shortfall alone does not locate
where a packet disappeared.

### Controls and hop counts

A separate local echo fixture counted every received and sent datagram. A
single preflight probe adds one packet to echo totals; subtract it for the
20480-packet load phase.

- H2 DIRECT: 20480/20480 replies; echo received and sent 20481 packets.
- H2 through Hysteria, default echo socket buffer: 20337 replies; echo received
  and sent 20417 packets. Loss occurred both before and after the echo target.
- Increasing only the echo socket receive buffer to 1 MiB did not eliminate
  loss: 19917 replies with the smaller MASQUE buffer, 19886 with the old
  buffer. This is not evidence of a regression caused by shrinking the buffer.
- A separate Python driver opened 256 SOCKS5 UDP associations directly to
  Hysteria, with MASQUE and HTTP/2 entirely absent. Loss reproduced there too.

Two independent mechanisms were isolated.

### 1. Shared-host UDP port collisions in the local Hysteria fixture

With Hysteria's default dual-stack outbound sockets and every component on
one macOS host, some server-side outgoing UDP ports matched ports of the
client-side SOCKS5 UDP relays. Four associations in a diagnostic run had such
relay-port collisions; precisely those four lost every one of their 80
responses during evenly spread traffic. All 20480 requests reached the echo
fixture, but only 20160 replies reached the driver. A collision with a
connected driver's local port was also observed, without the same loss;
not every repeated numeric port is itself evidence of a failure.

A controlled change to the temporary Hysteria server configuration, an
explicit direct outbound with `mode: "4"` and `bindIPv4: "127.0.0.1"`, removed
the observed collisions and the full-association response losses. The direct
SOCKS5 driver then received 20480/20480 replies when sending groups of eight
every 3.125 ms (same average 2560 packets/s). This setting was applied only
inside the diagnostic fixture. It is not a proposed production IPv4-only
policy and does not prove the same collision occurs on Linux or separate hosts.

### 2. Hysteria QUIC DATAGRAM receive-queue overflow under bursts

Even with the collision removed, synchronized bursts still lost requests.
Enabling `QUIC_GO_LOG_LEVEL=debug` in the isolated Hysteria processes produced
explicit `Discarding received DATAGRAM frame` events on the Hysteria server.
The dependency pinned by Hysteria v2.14.0 has a 128-entry receive queue and
drops newly received DATAGRAM frames when it is full:

- [Pinned dependency](https://github.com/apernet/hysteria/blob/app/v2.14.0/core/go.mod)
- [Queue and discard path](https://github.com/apernet/quic-go/blob/2895f039137a/datagram_queue.go)

This is a queue shared by datagrams on that QUIC connection, not the size of
one MASQUE SOCKS5 receive buffer. The synchronous session-creation/burst path
can outrun the queue consumer. Debug logging changes timing, so traced loss
percentages should not be compared as performance benchmarks.

With explicit IPv4 binding eliminating the first mechanism, the original H2
load showed an exact correspondence between missing replies and upstream
QUIC queue drops:

| MASQUE buffer version | Requests | Echo load packets received/sent | H2 replies | Hysteria server DATAGRAM queue drops | Hysteria client queue drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before | 20480 | 20418 | 20418 | 62 | 0 |
| After | 20480 | 20435 | 20435 | 45 | 0 |

Every request that reached the echo target returned through MASQUE in these
runs. Missing responses were already accounted for upstream, before the echo
target, rather than truncated by the reduced receive buffer. Application
payloads were 64 bytes (74-byte IPv4 SOCKS5 packets), well below both buffer
sizes. The change sizes a userspace single-datagram buffer; it does not change
SO_RCVBUF or the number of datagrams the kernel socket can queue.

### Conclusion and limits

The earlier increase from 2.83% to 3.91% median H2 shortfall does not establish
a buffer-sizing regression. Reproduction without MASQUE, exact upstream drop
accounting with both binaries, and the local port-collision control explain
why those short same-host runs were unsuitable for attributing the difference
to MASQUE. A universal zero-effect performance claim is still unwarranted:
allocation changes can perturb scheduling, and these are short diagnostic runs.

Keep the smaller buffer. For subsequent resource comparisons, isolate client
and server network namespaces/hosts or explicitly bind synthetic loopback
outbounds, report burst and evenly phased workloads separately, and retain
per-hop/drop counters. Do not silently replace the burst stress case with a
smooth workload or interpret DATAGRAM queue drops as reliable H2 data loss.
The original Linux loss was not re-instrumented here; the identified macOS
port-collision mechanism must not be generalized to that earlier run.

## Isolated Linux x86_64 validation (2026-11-22)

Used an explicitly authorized disposable Linux test host; no other VPS was
accessed. Ubuntu 24.04, Linux 6.8, x86_64, 2 vCPUs and approximately 2 GiB RAM.
Hysteria server and the counted echo fixture ran in a separate network
namespace connected by an IPv4 veth pair. MASQUE, the Hysteria client and the
load generator shared the host namespace. No TUN, NAT or forwarding was used.
The physical CPUs remained shared by all test components.

Both server versions were built locally on that host using Rust 1.88.0 and
the repository's normal release profile (fat LTO). The baseline is commit
`8b63556`, before buffer sizing; the candidate contains only the buffer-sizing
runtime changes. The same diagnostic client binary was used for both servers.
Its optional H2 pacing distributes stream start phases across a 100 ms period;
the default still synchronizes all streams. Hysteria v2.14.0's Linux binary
was checked against the release asset SHA-256 before use.

Server binary SHA-256:

- Before: `8ef03aefe691925573411f44497af8f186f81bfc820f0b7ce13304dc799390a7`
- After: `b564466133eefa9fd525678293f7d121c7441011ce12cc4d5ff3cdf0424995cd`

Preserving source timestamps during extraction initially let Cargo reuse a
stale candidate library. This was caught before measurements; the build was
stopped, source timestamps refreshed and the candidate rebuilt. Both distinct
binaries were then tested. No stale-candidate result is included below.

### Checks and measurement controls

- All 496 library tests passed on Linux x86_64.
- Both real Hysteria2 H2/H3 interoperability tests passed.
- Strict Clippy 1.88 did **not** pass: it reported four findings in unchanged
  `src/admission.rs`, `src/connection.rs`, and `src/server/tls.rs` (two boolean
  simplifications and two safety-comment placement findings). Safety comments
  already exist inside those unsafe blocks. The repository-pinned newer
  Clippy previously passed on macOS; this MSRV-Clippy result is not reported
  as a clean Linux static-analysis check. No unrelated code was modified.
- Compilation finished before measurements; temporary build swap was disabled
  and removed. The pre-existing service on the test host was paused for the
  clean series and restored successfully afterward.
- Early exploratory measurements were retained separately and excluded from
  the final series. The clean series contains 34 successful runs.

CPU time uses `wait4` for the MASQUE process only, including startup, warm-up,
setup and teardown. It excludes Hysteria, the echo fixture and generator.
Linux `wait4` peak RSS can retain pre-exec memory usage: a control with an
80 MiB allocation in the launching Python process reported 94208 KiB for a
small exec'ed process. Therefore the clean series sampled MASQUE's post-exec
`/proc/PID/status` every 50 ms, recording `VmHWM` and, for the H2-only cases,
median `VmRSS`. The legacy `wait4` RSS field remains in raw data but is not
used for the table. Median current RSS was added before the H2-only runs;
mixed H3/H2 lifetime medians are intentionally omitted because phase lengths
can move their median between different memory regimes.

The echo fixture requested a 1 MiB socket receive buffer; Linux reported an
effective 425984 bytes under the existing system limit. No global socket limit
was changed. Per-run UDP kernel counters were collected in both namespaces.
CPU steal was present (tens to over a hundred aggregate scheduler ticks per
short run), so small CPU differences are not statistically established gains.

### CPU and memory

Medians of three runs per version, alternating before/after order. Each H2
case uses 8 connections × 32 streams, 64-byte payloads, 2560 packets/s and an
8-second load. The moderate case uses 8 tunnels, 1200-byte payloads and 2000
packets/s, running H3 then H2 for eight seconds each. SOCKS5 packet budget is
4000, window 64, response expiry one second; performance runs have QUIC debug
logging disabled.

| Case | CPU seconds before → after | Post-exec peak RSS MiB before → after | Median current RSS MiB before → after |
| --- | ---: | ---: | ---: |
| 8 tunnels, moderate load, H3 then H2 | 6.744 → 6.672 | 32.12 → 32.20 | Not compared across phases |
| 256 H2 tunnels, synchronized bursts | 3.011 → 2.961 | 28.32 → 28.27 | 13.90 → 12.75 |
| 256 H2 tunnels, evenly phased | 3.279 → 3.178 | 28.25 → 28.23 | 13.73 → 12.61 |

The observed resident-memory saving at 256 tunnels is about 1.1 MiB (roughly
8% of steady process RSS), substantially smaller than the 15.03 MiB reduction
in requested receive-buffer storage. Unused allocation pages need not become
resident. The earlier higher RSS peak is consistent with startup/authentication
(the synthetic Basic account uses a 19 MiB Argon2 memory setting), so reducing
steady buffer storage does not materially reduce that peak here. CPU medians
are close; these runs do not prove a general CPU speedup.

### Load and loss

| Case | H3 shortfall % before → after | H2 shortfall % before → after | Kernel UDP receive-buffer errors |
| --- | ---: | ---: | --- |
| Moderate, 2000 packets/s | 0 → 0 | 0 → 0.0063 | Zero in every run |
| 256 tunnels, synchronized bursts | — | 2.3682 → 2.7344 | Zero in every run |
| 256 tunnels, evenly phased | — | 0.6055 → 0.1416 | Zero in every run |

Median H2 p95 RTT was 86 ms for both burst versions, and 61 → 43 ms for the
phased versions. These are end-to-end results through Hysteria on a shared
2-vCPU machine, not isolated MASQUE latency measurements.

An additional requested 8000-packet/s, 1200-byte case overloaded this setup:
actual receive rates were only about 3.2–3.7 kpackets/s, and kernel receive
buffer errors were 180–374 per run. Its CPU and throughput numbers are
retained in raw data, but are not used to claim an optimization benefit.

The DIRECT H2 control returned all 20480 requests with no kernel UDP errors.
A 60-second phased H2 run on the candidate sent 153600 requests and received
153369 (0.1504% shortfall), with no kernel UDP receive-buffer errors and
median RSS about 12.64 MiB. This is a short stability check, not a leak or
long-soak qualification.

### Queue drops versus late responses

QUIC debug tracing materially changed timing on this small host. With the
original one-second response expiry, one traced candidate run reported
6315 missing responses, although the upstream queue dropped only 118 and
the echo target received/sent 20362 load packets. Received-response p99 was
already at the one-second expiry boundary. Such shortfall cannot be treated
as a count of network drops alone.

Repeating both variants with a five-second expiry (same rate and packet count,
no buffer-code changes) made every missing response exactly accountable to
Hysteria's QUIC DATAGRAM receive-queue drops:

| Trace case | Missing of 20480 | Hysteria server queue drops | Hysteria client queue drops | Kernel receive-buffer errors |
| --- | ---: | ---: | ---: | ---: |
| Before, burst | 246 | 239 | 7 | 0 |
| After, burst | 125 | 125 | 0 | 0 |
| Before, phased | 0 | 0 | 0 | 0 |
| After, phased | 174 | 167 | 7 | 0 |

Thus the Linux runs also show upstream queue loss and, under heavy tracing,
responses exceeding the load generator's deadline. They do not establish a
loss regression from shrinking MASQUE's userspace receive buffer. Neither
raising a diagnostic deadline nor smoothing a benchmark should be represented
as making unreliable UDP delivery guaranteed. The synchronized stress case
remains valuable and must be reported separately.

All diagnostic processes were stopped, the temporary namespace/veth removed,
and the previously running test-host service restored. Compiled binaries,
Rust/toolchain dependencies and build caches were retained on the test host,
as requested. Raw results and reproduction helpers were copied to ignored
`work/linux-lab-results/`; infrastructure identifiers and credentials are not
part of this report. No iOS device or external IPv6 path was tested.

## AmneziaWG via awg-wireproxy

An additional authorized Linux test used the same candidate MASQUE binary
and 2-vCPU test host as the buffer-validation series above. No MASQUE runtime
code changes were needed to replace the SOCKS5 provider.

Versions:

- [awg-wireproxy v2.1.0](https://github.com/bropines/awg-wireproxy/releases/tag/v2.1.0),
  official Linux amd64 release archive, SHA-256
  `aa05dbc67198b56417334e4aa8bfca73cd23ba946eb70e1c7205b2319d618311`.
- [amneziawg-go v3.1.20260828](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828),
  built with Go 1.27.4 as the remote-side userspace server.
- Hysteria2 v2.14.0, using the previously verified binary, as a fresh
  comparison with the same MASQUE candidate and load generator.

Topology: MASQUE and the selected loopback SOCKS5 adapter ran in namespace A;
AmneziaWG/Hysteria and synthetic targets ran in namespace B across a veth.
The AmneziaWG server used a TUN interface **only in B**. A had no TUN,
forwarding, NAT or policy-routing changes. Adapter traffic used the AWG
userspace netstack, with MTU 1420 and tunnel addresses in a synthetic private
subnet. Non-default obfuscation was enabled: Jc 5, Jmin/Jmax 10/50,
S1/S2 20/30 and distinct H1–H4 ranges. This tests that profile, not all AWG
3.x features or arbitrary imported configurations. Domain-based bypass was
not enabled in wireproxy.

### Functional coverage

The existing MASQUE network smoke suite passed with awg-wireproxy and the
generic `udp_max_packet_size = 65507` setting:

- HTTP/2 and HTTP/3 authentication rejection, TCP CONNECT and CONNECT-UDP
  round trips;
- HTTP/3 capability and early TCP-body checks, plus connection migration.

A separate direct SOCKS5 probe, without MASQUE in that probe's path, passed
TCP echo, TCP half-close with the target responding only after EOF, and UDP
echo payloads of 0, 1, 64, 1200, 1380, 4000, 8000, 32000 and 65497 bytes.
The largest payload plus the IPv4 SOCKS5 header is 65507 bytes. Closing the
TCP control connection terminated the UDP association. The large datagrams
crossed the AWG tunnel despite MTU 1420; this is not a promise about arbitrary
WAN fragmentation behavior or large native HTTP/3 DATAGRAM support.

The same standalone probe reproduced the Hysteria limitations: TCP echo and
nonempty UDP through 4000 bytes passed; the half-close response, empty UDP,
and the tested 8000/32000/65497-byte payloads did not return successfully.
These boundary observations belong to the respective provider paths, not
new limits introduced into MASQUE. The full boundary matrix was not repeated
through both MASQUE transports.

### Comparable load and resource measurements

Three fresh adapter runs per provider and scenario, alternating provider
order. Both used the same 4000-byte SOCKS5 packet budget for the comparison,
five-second response expiry, window 64 and no QUIC debug tracing. This
deliberately holds MASQUE's receive-buffer setting constant; awg-wireproxy
does not require the Hysteria budget override.

The moderate scenario runs H3 then H2, each for eight seconds, with eight
tunnels, 1200-byte payloads and 2000 packets/s. H2 burst and phased scenarios
use 8 connections × 32 streams, 64-byte payloads and 2560 packets/s for eight
seconds. The phased diagnostic client staggers stream starts; the burst case
retains synchronized starts.

CPU values below are median CPU seconds, not utilization percentages. MASQUE
includes its benchmark lifetime; adapter CPU is measured over the enclosing
benchmark command using `/proc/PID/stat`. Their sum describes the measured
gateway processes, excluding the remote server, echo and generator. Adapter
RSS is sampled every 50 ms; peak here is the maximum sampled current RSS,
not `wait4`'s inherited high-water mark. Each table cell is the median of
three runs; medians of components need not sum to the median of their sum.

| Scenario / provider | MASQUE CPU s | Adapter CPU s | Gateway CPU s | Adapter median / peak RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| Moderate / awg-wireproxy | 5.768 | 9.280 | 15.164 | 48.48 / 77.75 |
| Moderate / Hysteria2 | 6.668 | 7.940 | 14.647 | 25.20 / 25.87 |
| H2 burst / awg-wireproxy | 2.890 | 5.420 | 8.307 | 41.21 / 66.43 |
| H2 burst / Hysteria2 | 2.875 | 3.180 | 6.055 | 38.79 / 38.96 |
| H2 phased / awg-wireproxy | 3.012 | 5.430 | 8.442 | 41.20 / 57.54 |
| H2 phased / Hysteria2 | 3.300 | 4.320 | 7.638 | 37.15 / 38.15 |

MASQUE's H2 median current RSS stayed around 12.6–12.8 MiB with either
provider. Mixed H3/H2 lifetime RSS medians are not compared because different
phase lengths can move the median between memory regimes. The adapter itself
has a materially different memory profile: wireproxy configures a 256 KiB
SOCKS buffer pool and uses a userspace IP stack. This source observation is
not an allocation-profile attribution of every measured RSS difference.

| Scenario | awg-wireproxy median shortfall % (range) | Hysteria2 median shortfall % (range) |
| --- | ---: | ---: |
| Moderate H3 | 0 (0–0.5125) | 0.00625 (0–0.05) |
| Moderate H2 | 0 (all three runs) | 0 (all three runs) |
| H2 burst | 0 (all three runs) | 1.894531 (1.831055–2.729492) |
| H2 phased | 0.107422 (0–1.572266) | 0.766602 (0–1.396484) |

In the burst scenario all three AWG runs returned all 20480 responses.
Gateway CPU was about 37% higher than Hysteria in that scenario; the moderate
and phased differences were about 4% and 11%. These short shared-host runs
establish neither universal performance rankings nor loss-free AWG delivery.
The remote userspace servers and generator compete for the same two CPUs;
there is no real inter-country link, independent host sizing or kernel-AWG
server comparison here. No per-run kernel/drop tracing was collected in this
series, so its nonzero shortfalls are not assigned a specific root cause.

The result is a compatible alternative with broader observed TCP/UDP
semantics, not a demonstrated CPU/memory optimization. No physical iOS
client, external IPv6 path, reconnect/failure soak or WAN MTU matrix was tested.

All test processes were stopped, the temporary namespace/veth/TUN removed,
and the previously active test-host service restored. Existing and new
compiled binaries, Rust/Go dependencies and build caches were retained.
Raw results and synthetic reproduction helpers are in ignored
`work/awg-validation/`. This step changed documentation only; quick checks
passed, and the prior full workspace validation remains applicable to the
unchanged MASQUE source. The previously documented Linux Clippy 1.88 gap
remains; this provider test does not close it.

### awg-wireproxy CPU and allocation profile

Follow-up profiling used the same 256 synchronized H2 tunnels, 64-byte UDP
payloads and 2560 packets/s, extending each load to 30 seconds. All three
runs returned all 76800 responses. The release control used Linux `perf`
at 99 Hz; its adapter consumed 19.83 CPU seconds. Two Go-profiled runs used
19.35 and 18.33 CPU seconds, with 17.37 and 16.38 seconds of sampled CPU.
These are sampling observations, not an overhead-free benchmark or proof of
zero profiler impact; latency varied materially between runs.

The profiling binary was built from the exact v2.1.0 source commit
`02588433b6328171b594d76f3f16bd3404258a83`, using Go 1.27.1 like the release.
Its only added source was an environment-gated CPU/heap profiling hook. Files
were opened before the adapter applied its normal filesystem restrictions;
no profiling HTTP listener or disabled adapter sandbox was needed. Original
release and MASQUE binaries were retained unchanged. CPU sampling stopped
before the explicitly requested GC and heap/allocation snapshots.

Disjoint grouping of **flat/self** CPU samples by function namespace, rounded
across the two profiles (not overlapping cumulative call-tree percentages):

| Group | Share of sampled CPU |
| --- | ---: |
| System-call functions and wrappers | 37.0–37.8% |
| Go runtime, excluding those syscall functions | 25.7–25.8% |
| gVisor userspace network stack | 16.5–16.6% |
| AWG package functions, excluding their callees | 6.0–6.9% |
| Cryptographic package functions | 1.5–1.6% |
| SOCKS5 package functions, excluding their callees | 0.7–1.3% |
| Other libraries, synchronization and network wrappers | 10.8–12.0% |

The single syscall leaf accounted for 35.8–36.5%. Important call paths were
SOCKS UDP receive → gVisor UDP write → AWG sender, and the reverse path back
to the local SOCKS UDP socket. Small SOCKS self time does not mean its whole
forwarding path is free: its workers include substantial network, runtime
and syscall time attributed to their callees in the table. AWG already calls
`sendmmsg` on its outer transport; any batching proposal must identify the
specific remaining per-datagram boundary.

Go runtime time must not be equated with garbage collection. For example,
`mallocgc` had 5.6–5.7% cumulative CPU and background GC marking had only
0.3–0.4%; these are illustrative, overlapping call-tree observations, not
additional percentages to add to the table. Encryption/decryption routines
together had about 2.3–2.6% cumulative CPU. For these small packets,
cryptography was not the dominant cost. This does not establish its share for
large packets or identify the function-by-function excess over Hysteria,
whose Go CPU profile was not collected.

Sampled allocation volume was approximately 503 and 431 MiB over the process
lifetimes. Of that, the SOCKS 256-KiB buffer pool allocated about 195 and
188 MiB; AWG message buffers allocated about 160 and 85 MiB. These are
allocated bytes, **not RSS** and not necessarily repeated per-packet churn.
Three long-lived 256-KiB SOCKS buffers per active association alone request
192 MiB at 256 associations, consistent with the sampled SOCKS allocation
volume. One of them merely waits on the TCP control stream. Pooled objects
can remain in the heap snapshot after associations close; this snapshot does
not prove a leak. Adapter median RSS in these longer runs was about 84 MiB
for the perf control and 100–105 MiB with Go profiling; use the earlier
unprofiled series for the provider memory comparison.

Concrete follow-up candidates are inside awg-wireproxy and its SOCKS library:
use a small separate control-stream buffer, size UDP buffers to the supported
full datagram budget, and measure copies, wakeups and local SOCKS UDP syscalls
before attempting batching. Preserve maximum-size and empty UDP datagrams,
TCP half-close, bounded queues and portable behavior. None of these potential
optimizations was applied in this profiling task, and no gain is claimed for
them yet.

Profiles, perf data, summaries and run results are retained under ignored
`work/awg-validation/profiles/`; profiling/build helpers accompany the prior
lab helpers. The original test-host service was restored, the temporary
network removed, and all compiled artifacts and dependency caches preserved.

### Standalone AmneziaWG client through Linux TUN

The next experiment removed MASQUE, SOCKS5 and gVisor entirely. A synthetic
UDP generator and official `amneziawg-go` client ran in isolated namespace A;
the same official AWG server and a UDP echo target ran in namespace B. The
generator sent to the server's inner tunnel address through A's Linux TUN.
Only the isolated namespaces received addresses/routes; no host-wide packet
routing, forwarding, NAT or socket-limit settings were changed.

Both AWG processes used the existing official v3.1.20260828 standalone build
with Go 1.27.4. MTU 1420, keys/profile, non-default AWG obfuscation and the
outer veth topology followed the preceding fixtures. The standalone module
dependency graph and Go version differ from wireproxy's Go 1.27.1 build.
This is a measurement of the standalone official client, not a controlled
binary-level ablation of the wireproxy executable.

The generator opened 256 connected UDP sockets and sent synchronized bursts
of 256 packets every 100 ms: 2560 packets/s for 30 seconds, exactly 76800
requests per run. Three runs each used 64- and 1200-byte payloads, alternating
size order, with a fresh client process for every run. A tunnel echo warmup
preceded timed sends. A five-second response drain followed runs with losses.
The Python generator replaced the prior Rust MASQUE load generator; the
logical flow count/rate/burst pattern matches, but arrivals at the AWG
boundary are not guaranteed identical. The server and generator still share
the same two-vCPU machine. No WAN, TCP or physical iOS path is covered.

Client CPU is the delta of `/proc/PID/stat` user and system time, including
generator startup/warmup and any final response drain in the measurement
interval. RSS is sampled every 50 ms. Server and echo CPU were measured
separately, and the generator reports its own process resource usage. All
CPU numbers below are seconds, not CPU utilization percentages; component
medians need not add to the median of their sum.

| Payload / runs | Client CPU s | Client user / system CPU s | Median / sampled peak RSS MiB | Missing responses per run | Median p95 RTT ms |
| --- | ---: | ---: | ---: | --- | ---: |
| 64 bytes / 3 | 10.80 | 4.37 / 6.41 | 13.45 / 17.98 | 0, 0, 0 | 50.98 |
| 1200 bytes / 3 | 10.88 | 4.73 / 6.15 | 14.05 / 16.49 | 64, 29, 93 | 50.16 |

The 64-byte client CPU range was 9.90–10.87 seconds: approximately 36% of
one CPU averaged over the 30-second load, or 18% of a two-CPU host. System
CPU is already included in this figure; the kernel work has not simply been
omitted from the process measurement. Substantial per-packet processing cost
therefore remains even without wireproxy's SOCKS and gVisor components.

To expose work outside the client's process accounting, `/proc/stat` was
also sampled across each run. Median **whole-host** system+IRQ+softirq time
was 17.22 seconds for 64-byte runs and 16.34 for 1200-byte runs, including
softirq time of 1.84 and 1.82 seconds respectively. These totals include
the client, server, generator, echo and background work. They must neither
be assigned entirely to the client nor added to its system CPU, which would
double count work. The three-second idle controls showed very little active
CPU; run steal time remained about 1.4–1.7 aggregate CPU seconds. This fixture
does not provide exact client-only attribution of all asynchronous kernel
work.

For every main-series 1200-byte run, missing responses exactly matched the
server namespace's UDP receive-buffer errors; the client namespace had none.
After the first two such runs, a per-socket check showed 93 drops on the echo
socket and zero on both AWG outer sockets. The requested 1-MiB echo receive
buffer was capped by the existing Linux limit, as in the earlier fixtures.

A separate 1200-byte control used privileged `SO_RCVBUFFORCE` on **only the
synthetic echo socket**, leaving global limits unchanged. It returned all
76800 responses with zero UDP receive-buffer errors in either namespace.
Client CPU was 12.81 seconds (5.49 user + 7.32 system), median RSS 13.49 MiB,
and p95 RTT 56.32 ms. This single control verifies the target-buffer issue;
it is not a three-run performance median or evidence that a larger buffer
reduces CPU. None of these results establishes loss-free behavior on a WAN.

The prior 30-second wireproxy control used 19.83 CPU seconds, but subtracting
10.80 from it would not isolate a pure SOCKS/gVisor overhead: the generator,
kernel-versus-userspace stack, compiler/dependencies, and packet arrival
timing differ. The useful result is the standalone client's measured cost
and its user/system split, without relying on a Hysteria comparison.

Results and synthetic helpers are retained in ignored
`work/awg-validation/direct/` and `work/awg-validation/direct-largebuf/`.
All seven runs completed; the original test-host service was restored and
both temporary namespaces/TUN interfaces removed. Original and profiling
binaries, dependency downloads and build caches were preserved. No MASQUE
runtime source change was made; formatting/syntax and diff checks passed.

### awg-wireproxy SOCKS buffer reduction experiment

On 2026-11-23, an isolated `memory-optimization` branch in the awg-wireproxy
source checkout changed two buffer choices, leaving MASQUE unchanged:

- The application's SOCKS pool uses 64 KiB instead of 256 KiB. This still
  holds ordinary maximum-size UDP datagrams, including SOCKS framing, and
  also supplies streaming TCP copies.
- The SOCKS library's UDP ASSOCIATE TCP control reader uses its own 256-byte
  buffer. It continues draining any control bytes until EOF and closes the
  UDP association on termination, without retaining a full data-plane buffer.

The experiment uses a local, licensed copy of go-socks5 v0.1.3 via a Go
module replacement. Its only runtime code change is the control reader.
Both before/after executables were rebuilt with Go 1.27.1, identical module
versions, flags and the local dependency layout. Profiling was disabled;
the shared module cache was not edited. This removes compiler/dependency
differences from the before/after comparison.

At 256 active single-target UDP associations, the three persistent SOCKS
buffers previously requested 192 MiB. The two data buffers plus the small
control buffer now request about 32.06 MiB. This arithmetic excludes scratch
buffers, the AWG message pools and other allocations; it is not an RSS claim.

Validation passed:

- awg-wireproxy `go test ./...`, including its admin package;
- the local SOCKS dependency's `go test -race -coverprofile=coverage
  -covermode=atomic ./...`, covering the server, buffer pool and codecs;
- direct SOCKS TCP echo, EOF-dependent half-close response, a 2-MiB TCP
  transfer, empty UDP and payload sizes through 65497 bytes;
- continued UDP delivery after 4096 bytes on the TCP control connection,
  and association termination when that connection closes;
- MASQUE TCP/UDP smoke tests over both H2 and H3 for both executables.

The load comparison alternated before/after order across three repetitions.
Each fresh adapter process carried 256 H2 tunnels, 64-byte payloads and
synchronized 2560-packet/s bursts for 30 seconds through the unchanged
MASQUE candidate. All six runs returned all 76800 responses. The SOCKS packet
budget in MASQUE remained 4000 for both versions; functional smoke used the
generic 65507 setting. No compiler, profiler or unit-test run overlapped the
measurements. CPU is adapter process time over the enclosing benchmark;
RSS is sampled every 50 ms. Values below are medians of three runs.

| Adapter metric | Before | After | Change |
| --- | ---: | ---: | ---: |
| Median current RSS, MiB | 100.95 | 86.50 | −14.3% |
| Sampled peak RSS, MiB | 160.07 | 110.58 | −30.9% |
| CPU seconds | 18.77 | 18.21 | −3.0%, not an established speedup |

Before CPU values were 18.77, 18.24 and 20.41 seconds; after values were
17.31, 20.42 and 18.21 seconds. Their overlapping spread is larger than the
median difference. Current RSS was also variable: 75.11–101.85 MiB before
versus 86.04–88.23 MiB after, so current RSS did not improve in every paired
run. Sampled peaks were lower in every pair: 157.60–164.83 MiB before versus
109.73–131.89 MiB after. Maximum observed RSS across all runs fell from
164.83 to 131.89 MiB. Requested allocation savings must not be equated with
resident-memory savings: page residency, allocator/GC behavior and other
AWG pools still contribute.

This is a useful memory reduction with preserved tested semantics, not a
proven CPU optimization. TCP throughput, other load shapes, jumbo UDP,
external IPv6 and long-soak behavior were not benchmarked in this step.
The patch remains an experimental client fork; it was not published upstream
or installed as a persistent service. Raw results and build/test logs are in
ignored `work/awg-validation/memory-results/` and `build-memory.log`.
The test service was restored, temporary network removed, and original/new
binaries and all build caches retained.

## Linux SOCKS5 receive batching (2026-11-22)

Implemented Linux `recvmmsg` reception for SOCKS5 UDP responses in both HTTP
transports, retaining the existing single-packet non-Linux path. Buffers start
at two slots and grow after a full read, up to 16 slots within a 32 KiB payload
storage budget. One full-size packet is always permitted even above that
budget; with the generic 65507-byte upstream limit, large-capsule reception
therefore retains one slot. No timer waits to fill a batch. Each frame is
validated independently before forwarding. Output framing still copies data.
H3's bounded response channel may now retain multiple packets per item;
this optimization does not guarantee lower memory under queued bursts.

Validation passed:

- macOS `scripts/check.sh full`, including portable H2/H3 burst regressions.
- Linux ARM64/MSRV 1.88 release build and 497 library tests, including actual
  socket batching, truncation, malformed frames, empty packets, packet
  boundaries, buffer growth and bounded allocation.
- Three focused Linux SOCKS5 H2/H3 integration tests and both real Hysteria2
  v2.14.0 H2/H3 interoperability tests, with 32-packet burst coverage.
- All 12 isolated Docker E2E scenarios.

Linux Clippy could not run: the offline test image lacks the Clippy component
for Rust 1.88. macOS all-target Clippy passed as part of the full check.
No production endpoint was accessed or changed.

### Before/after resource measurements

Compared the exact local pre-batching source snapshot (including the earlier
DIRECT-only reload work) against the adaptive implementation. Linux ARM64
release binary SHA-256:

- Before: `a80c43228945b7deb50722fa66e1475f5003585333d5a047d9003f4e97a73aa4`
- After: `a1702021f2283020929ade90a8091945664cbb2783dc15db1d5d7d59bb02d4a2`

Docker Desktop Linux, 10 available logical CPUs, no CPU quota or affinity,
loopback real Hysteria2, one MASQUE shard, SOCKS5 packet limit 4000 bytes,
window 64, expiry 1000 ms, target and QUIC GSO disabled. Each sample runs H3
then H2 sequentially. CPU seconds and peak RSS measure only the MASQUE server
process, including startup/shutdown; they exclude Hysteria, generators and
kernel socket memory. Each row is a median of three samples per version,
alternating version order between repetitions. The host was not isolated from
other workloads; these short runs do not establish statistical significance.

| Workload | CPU seconds before → after | Peak RSS MiB before → after |
| --- | ---: | ---: |
| 8 tunnels, 64 B, 8000 packets/s, 8 s per transport | 6.483 → 6.555 | 30.33 → 30.64 |
| 8 tunnels, 1200 B, 8000 packets/s, 8 s per transport | 6.761 → 6.928 | 30.63 → 30.66 |
| 256 tunnels, 64 B, 2560 packets/s, 8 s per transport | 4.279 → 3.935 | 37.96 → 37.00 |
| 2 tunnels, 1200 B, unlimited rate, 5 s per transport | 8.980 → 8.920 | 30.39 → 30.58 |

Throughput, response shortfall and latency are medians independently:

| Workload | H3 packets/s before → after | H2 packets/s before → after | H3 shortfall % before → after | H2 shortfall % before → after | H3 p95 µs before → after | H2 p95 µs before → after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | 8000 → 8000 | 7999 → 7999 | 0 → 0 | 0 → 0 | 768 → 800 | 928 → 864 |
| 1200 B | 8000 → 8000 | 8000 → 7998 | 0.0016 → 0 | 0.0031 → 0.0016 | 864 → 864 | 1088 → 1152 |
| 256 tunnels | 2560 → 2560 | 2391 → 2390 | 0 → 0 | 6.6016 → 6.6455 | 3072 → 3200 | 10752 → 10752 |
| Unlimited | 57105 → 56928 | 61809 → 60789 | 0.0750 → 0.0784 | 0.0673 → 0.0777 | 2560 → 2432 | 2304 → 2432 |

The 256-tunnel H2 loss is present in both versions; its cause was not isolated.
One baseline attempt timed out during preflight before producing load results;
it was retained as a failed log and rerun, and is excluded from the 24 successful
samples. An earlier eager-allocation experiment added roughly 10 MiB at 256
tunnels and was rejected in favor of adaptive allocation; its results are not
mixed into this table. Raw local logs, runner and JSON remain in ignored `work/`.

Normal-load CPU did not improve (observed medians +1.1% and +2.5%); unlimited
throughput also did not improve. The many-tunnel sample used about 8% less CPU
and 0.96 MiB less RSS, but this is not a general performance guarantee. The
change enables syscall amortization when packets are already queued; these
measurements do not prove an overall CPU reduction, total gateway memory
reduction or long-soak stability. No real iOS device test was performed here.
