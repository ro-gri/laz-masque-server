# Laz MASQUE Server

[![License][license-badge]][license] [![Release][release-badge]][releases] [![Build][build-badge]][build] [![Issues][issues-badge]][issues]

**English** | [Русский](README.ru.md)

[license-badge]: https://img.shields.io/badge/license-MIT-blue
[license]: LICENSE
[release-badge]: https://img.shields.io/github/v/release/ro-gri/laz-masque-server?style=flat-square
[releases]: https://github.com/ro-gri/laz-masque-server/releases
[build-badge]: https://github.com/ro-gri/laz-masque-server/actions/workflows/ci.yml/badge.svg?branch=main
[build]: https://github.com/ro-gri/laz-masque-server/actions/workflows/ci.yml
[issues-badge]: https://img.shields.io/github/issues/ro-gri/laz-masque-server?style=flat-square
[issues]: https://github.com/ro-gri/laz-masque-server/issues

Laz MASQUE Server is a fork of
[zenith-ent/masque-server](https://github.com/zenith-ent/masque-server), a
high-performance MASQUE proxy written in Rust. It carries TCP, UDP and IP traffic
using CONNECT, CONNECT-UDP and CONNECT-IP over HTTP/2 and HTTP/3.

Additions to the original project:

- **SOCKS5 outbound routing** — route TCP and UDP destinations directly or through
  a local SOCKS5 proxy according to IP/CIDR rules. See [routing](docs/outbound-routing.md).
- **HTTP authorization** — authenticate Basic credentials and client certificates
  through an external authorization server, with persistent connections and caching.
  See [authorization](docs/http-authorization.md).
- **Statistics and session control** — retrieve traffic counters and online
  credential UUIDs, and disconnect sessions with `kickAuth` through a local API.
  See [the API contract](docs/accounting.md).

Prebuilt releases target **Linux x86_64 and ARM64**. Downloads and updates use
[this repository's releases][releases]. For bugs and requests, use [Issues][issues].
The original MIT license and copyright notices are preserved.

## Versioning

Release versions use `v<laz-version>+masque.<upstream-version>`, for example
`v0.1.0+masque.0.15.0`:

- `0.1.0` is the Laz MASQUE Server version.
- `masque.0.15.0` identifies the upstream version used as the release's base.

Every new release increments the Laz version, including when the upstream base
changes. Metadata after `+` records the base and does not affect version precedence.
The first release is `v0.1.0+masque.0.15.0`.

## Features

### 🌐 Standard protocols

CONNECT for TCP, [CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298) and
[CONNECT-IP](https://www.rfc-editor.org/rfc/rfc9484). HTTP/3 uses QUIC;
HTTP/2 provides a TCP/TLS transport when UDP is unavailable.
CONNECT-IP forwarding requires Linux TUN and host routing.

### 🔀 Flexible routing

Choose DIRECT or SOCKS5 for CONNECT and CONNECT-UDP by destination IP/CIDR.
Update the DIRECT CIDR file without restarting the server. Global target policies
and per-listener restrictions control access. [Routing guide](docs/outbound-routing.md).

### 🔐 Authentication

Basic credentials or client certificates, with a shared `file` or `http`
authorization source. Each credential has a persistent UUID. Multiple listeners
can serve different transports and authentication modes in one process.
[Configuration](docs/configuration.md#authentication).

### 📊 Traffic and sessions

A local API exposes cumulative traffic counters, online UUIDs and session
control. Optional Prometheus metrics, health checks and structured logs support
monitoring. [Accounting API](docs/accounting.md) · [Monitoring](docs/observability.md).

### ⚡ Performance

Multi-core QUIC processing, bounded queues, backpressure and Linux UDP
optimizations. [Architecture](docs/architecture.md) · [Performance](docs/performance.md).

### 🚀 One-command Linux install

Install the latest stable release on Linux x86_64 or ARM64:

```sh
curl -fsSL https://raw.githubusercontent.com/ro-gri/laz-masque-server/main/install-latest.sh | sudo sh
```

The same command updates an existing installation while preserving its
configuration. [Installation and configuration guide](docs/deployment.md#one-command-install).

## Documentation

- [Configuration](docs/configuration.md) — listeners, credentials and policies.
- [Deployment](docs/deployment.md) — installation, TLS, systemd and updates.
- [SOCKS5 routing](docs/outbound-routing.md) — outbound selection and CIDR reload.
- [HTTP authorization](docs/http-authorization.md) — external authorization and cache.
- [Accounting API](docs/accounting.md) — traffic, online UUIDs and `kickAuth`.
- [Troubleshooting](docs/troubleshooting.md) — `laz-masque-probe`, diagnostics and support bundles.
- [Operations](docs/operations.md) — optional `laz-masque-ops` tools and AI Skill.
- [Protocols](docs/protocols.md) · [Security](docs/security.md) · [Changelog](CHANGELOG.md).

## Development

Build from source:

```sh
cargo build --release --bin laz-masque-server
```

Linux is the production target. Portable HTTP/2 and HTTP/3 paths are also tested
on macOS. See [CONTRIBUTING.md](CONTRIBUTING.md), [architecture](docs/architecture.md)
and [testing](docs/testing.md) for development and validation instructions.

## License

[MIT](LICENSE).
