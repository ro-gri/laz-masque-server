# IP/CIDR outbound routing

CONNECT and CONNECT-UDP can use DIRECT or a local SOCKS5 upstream on both
HTTP/2 and HTTP/3. Hysteria2 remains a separately managed process. No TUN,
packet routing, transparent interception or Linux privileges are needed.
CONNECT-IP is independent and does not use these rules. Check the client uses
CONNECT/CONNECT-UDP before expecting this feature to route its traffic.

## Configuration

Existing configurations remain DIRECT. To send destinations in an externally
maintained Russian IPv4/IPv6 CIDR set directly and everything else via SOCKS5,
add these sections to the server configuration. For a socket-only deployment,
also set `ip_proxy.enabled = false` in the existing `[ip_proxy]` section:

```toml
[outbound]
default_route = "socks5"
direct_cidrs_file = "/etc/masque-server/ru-cidrs.txt"
# Optional additional DIRECT ranges. These do not grant target access.
direct_cidrs = []

[outbound.socks5]
endpoint = "127.0.0.1:1080"
max_connecting = 128
max_udp_associations = 1024
udp_max_packet_size = 4000 # Conservative Hysteria2 packet budget, including header
# Optional RFC 1929 authentication; specify both fields together.
# username = "masque"
# password_file = "/etc/masque-server/socks5-password"
```

The upstream must be a concrete loopback IP with a nonzero port. The password
file contains 1–255 bytes, optionally followed by one LF or CRLF. Protect it
with owner-only permissions. Credentials are loaded once, held in zeroizing
storage, and never included in protocol errors or metric labels.

CIDR input is UTF-8, one IPv4 or IPv6 prefix per line, with optional `#`
comments. Paths must be absolute. A configured file must contain at least one
prefix (or be accompanied by inline prefixes); missing, malformed or oversized
input fails startup and `check-config`. Limits are 8 MiB per CIDR file and
100,000 combined prefixes. Prefixes are merged into sorted disjoint intervals,
so lookup is logarithmic. IPv4-mapped IPv6 addresses use IPv4 rules.

No country database is embedded or downloaded by the server. Obtain an
appropriately licensed country-prefix dataset independently; record provider,
version/date and checksum. Country attribution describes that dataset, not a
guarantee about the physical location or ownership of every service. Include
both address families. Inspect updates before atomically replacing the file.

Route, upstream and file-content changes require a restart. `status` reports
`outbound: restart required`, including when the file path has not changed.
SIGHUP only reloads the existing supported credential/TLS state; it never
silently switches live tunnel routes. A running server retains its immutable
startup snapshot if a file is replaced or removed.

## Selection and failure semantics

1. Authenticate the MASQUE request and enforce tunnel admission.
2. Resolve a hostname once using the existing bounded resolver, or accept an
   IP literal. Validate the entire snapshot against global and listener target
   ACLs and port restrictions. Any denied address still rejects the request.
3. For each allowed candidate, DIRECT wins if it matches `direct_cidrs` or the
   file; otherwise use `default_route` (`direct` or `socks5`).
4. TCP keeps staggered IPv4/IPv6 attempts. Every candidate uses its own route;
   a mixed-country DNS answer may therefore create attempts on both routes.
   Fail-closed means an address assigned SOCKS5 is never retried DIRECT, not
   that another independently DIRECT-eligible candidate is prohibited.
5. UDP pins one IP and route for the tunnel lifetime. UDP socket/association
   setup is not proof that the target responds. There is no per-packet reroute.

SOCKS requests carry the checked IP, never the original hostname. System DNS
queries are separate traffic and do not acquire these outbound rules. A DNS
error maps to 502, target policy denial to 403, setup deadline to 504, and
SOCKS5 rejection/connection failure to 502. Setup shares one deadline across
DNS, capacity waits and all negotiation. No automatic direct fallback exists.

## SOCKS5 adapter and resource ownership

`src/outbound/` implements a bounded RFC 1928/1929 subset with no extra dependency:
CONNECT, UDP ASSOCIATE, no-auth and username/password authentication, IPv4/IPv6
targets. This choice gives the existing raw UDP batching path explicit access
to the socket, framing and control lifetime; a high-level datagram wrapper
would otherwise hide those operations. BIND and SOCKS fragmentation are not
supported. A domain BND.ADDR is accepted as informational for CONNECT, but
UDP relay BND.ADDR must be an IP. Wildcard relay IPs use the TCP peer IP; all
other relay IPs must equal the loopback TCP peer and the port must be nonzero.

TCP returns the negotiated ordinary stream to the existing bounded relay.
Generic SOCKS5 half-close semantics are preserved by the MASQUE side; an
upstream may impose stronger close behavior (see Hysteria compatibility below).
Each UDP tunnel owns one TCP control connection, one connected UDP socket
(with a duplicated send descriptor), and one active-association permit. Failed
setup, cancellation, FIN/reset, connection loss and idle expiry release them.
Control EOF/error ends the association even while response delivery is blocked.
A restart of the sidecar terminates existing sessions; new MASQUE requests can
establish new ones after it returns. Established sessions are not migrated.

Upstream setup has a process-wide semaphore (default 128, maximum 4096).
Active or preparing UDP associations have a separate process-wide ceiling
(default 1024, maximum 65536); exhaustion fails setup promptly. Existing tunnel,
resolver, early-data and response-queue budgets also remain in force.

HTTP/3 sends remain nonblocking. SOCKS headers are added to bounded staging
buffers before existing sends; no extra unbounded sender queue is introduced.
DIRECT preserves its batched receive/send and optional GSO path. SOCKS5 uses
portable asynchronous receive plus existing response queues and disables target
GSO. HTTP/2 preserves capsule framing and flow control. It does not encapsulate
SOCKS headers into MASQUE payloads.

Incoming UDP checks both the connected outer relay and the pinned target
IP/port in the SOCKS header. Malformed RSV/ATYP, FRAG != 0, wrong target and
truncated/oversized packets are discarded. The IP header overhead is 10 bytes
for IPv4 or 22 for IPv6. The local UDP transport's payload ceiling includes
that overhead. `udp_max_packet_size` bounds the complete SOCKS5 packet (23–65507
bytes; default 65507); packets above it are dropped before reaching the proxy.
For Hysteria2 v2.14.0 use a conservative 4000-byte packet budget. Its SOCKS
receive buffer and internal message buffer are both 4096 bytes, but its internal
header also consumes space. This setting allows 3990-byte IPv4 or 3978-byte IPv6
target payloads. Larger packets can be lost or truncated inside that upstream.
Kernel limits and the Hysteria path can be smaller. UDP loss
under pressure or at size limits is expected, without unbounded retries.

Metrics have only fixed route/protocol labels:

- `masque_outbound_attempts_total{protocol="tcp|udp",route="direct|socks5"}`:
  candidate setup attempts, including retries, not completed tunnels.
- `masque_socks5_connecting`: upstream negotiations holding capacity.
- `masque_socks5_udp_associations`: association slots in use, including setup.

## Hysteria2 compatibility

Configure the separately managed client with a loopback SOCKS listener and
UDP enabled (`disableUDP: false`). Use `fastOpen: false`: otherwise a successful
SOCKS CONNECT can precede the remote connection result. Keep certificate
verification enabled. The MASQUE server neither starts nor configures Hysteria.

Hysteria2 v2.14.0's SOCKS TCP implementation closes both directions when either
copy loop finishes. A local interop experiment confirmed that sending upload
FIN before an EOF-delimited target response can lose that response. This is
an upstream limitation, not corrected by delaying or discarding MASQUE FIN.
Ordinary request/response traffic with application framing can be tested
independently; applications requiring TCP half-close need an upstream that
supports it. Source: https://github.com/HyNetworks/hysteria/blob/app/v2.14.0/app/internal/socks5/server.go

Hysteria2 v2.14.0 also rejects zero-length UDP payloads in its internal protocol.
The generic SOCKS5 adapter supports them (covered with the deterministic peer),
but cannot make this upstream deliver them. Source:
https://github.com/HyNetworks/hysteria/blob/app/v2.14.0/core/internal/protocol/proxy.go

## Validation and isolated interop

```sh
scripts/check.sh quick
scripts/check.sh full
cargo test --lib outbound --locked
cargo test --test http2_connect --test client_cert_connect_ip socks5 --locked
cargo test --test check_config --locked
HYSTERIA_BIN=/absolute/path/to/verified/hysteria python3 scripts/test-hysteria.py
```

The last command generates temporary credentials and a trusted self-signed
certificate, starts an isolated client/server pair on ephemeral loopback ports,
checks real TCP/UDP payloads through H2 and H3 MASQUE, and cleans up both processes.
It never downloads software, uses production configuration, or changes routes.
Ordinary H2/H3 tests use an instrumented SOCKS peer and synthetic destinations,
covering H3 native DATAGRAMs and capsule fallback, IPv4/IPv6 addresses, policy
rejection, fail-closed behavior and control-connection teardown. Unit tests
cover authentication, malformed replies, datagram decoding, boundaries,
capacity, cancellation and immutable file snapshots.

Before deployment also run the Linux checks in `testing.md`, real-client H2/H3
probes, and controlled 64/1200-byte UDP benchmarks. Compare unmodified DIRECT,
new DIRECT and SOCKS5 at fixed load and saturation; retain CPU, memory, file
descriptor count, goodput, loss and latency. Local portable tests cannot
validate Linux batching/GSO or predict a remote Hysteria path's performance.

For reproducible local load experiments with an independently verified binary:

```sh
MASQUE_BENCH_MODE=load MASQUE_BENCH_TRANSPORT=both \
MASQUE_LOAD_CONNS=2 MASQUE_LOAD_PAYLOAD=1200 MASQUE_LOAD_DURATION_SECS=5 \
HYSTERIA_BIN=/absolute/path/to/hysteria python3 scripts/test-hysteria.py --benchmark
```

Run `scripts/network-bench.sh` with the same load variables for DIRECT.
`MASQUE_BENCH_SOCKS5_ADDR` also selects an already-running loopback upstream;
the benchmark validates that endpoint and adds only its temporary configuration.

See the [validation record](outbound-validation.md) for executed checks,
measured local load results and remaining release gates.
