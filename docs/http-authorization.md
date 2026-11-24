# Local HTTP authorization

The root `[authorization]` table selects one credential source for the entire
server: `backend = "file"` (default) or `backend = "http"`. HTTP mode asks a
separately managed local authorization server for credential decisions and
UUIDs.

Listeners still select `basic` or `client_cert` because that choice determines
whether TLS requires a client certificate on the socket. Basic and certificate
listeners may coexist, using the same authorization server, connection pool and
cache. Existing per-listener file credentials remain in `listeners.auth` only
when the server uses the file backend.

## Basic example

```toml
[authorization]
backend = "http"

[authorization.http]
url = "http://127.0.0.1:9080/authorize"
timeout_ms = 1000
cache_ttl_secs = 300
cache_max_entries = 4096
max_in_flight = 8

[[listeners]]
listen_addr = "0.0.0.0:443"
transport = "http3" # http2 uses the same authorization source
shards = 1

[listeners.auth]
enabled = true
mode = "basic"
```

With HTTP selected, remove all local `id`, `username`, `password_hash` and
`users` fields and the `[[clients]]` roster, including on disabled listeners.
File settings are an invalid configuration: startup and reload reject them.
There is no file fallback or mixture of file and HTTP listeners.
`listeners.auth.enabled = false` still explicitly disables authentication on
that socket; it does not exempt file settings from validation. With the file
backend, specifying `[authorization.http]` is also an error.

## Client certificates

For an HTTP-backed certificate listener use `mode = "client_cert"` and add:

```toml
[authorization.http]
url = "http://127.0.0.1:9080/authorize"
client_ca_path = "/etc/masque/client-ca.pem"
```

This table replaces the Basic example's HTTP table; other HTTP options retain
those defaults. `client_ca_path` is a PEM trust-anchor bundle, not a private
key. It is required when any enabled listener uses client certificates. Basic
listeners can coexist with these listeners and do not request certificates.

TLS verifies the chain against these trust anchors, certificate validity and
client-authentication purpose, and proof of private-key possession. The server
then extracts the canonical P-256 SPKI public key once per connection. Missing,
untrusted or unusable certificates cannot open tunnels. Authorization is a
second gate: each CONNECT request checks the authorization server/cache before
any target socket or CONNECT-IP assignment is created. A successful TLS
handshake alone does not authorize proxy use. Authorization rejection returns
the existing empty 404.

Client certificates must be issued by the configured CA. Issuance and
authorization server registration are external operations; the existing
`enroll-client` output is not a CA enrollment service. The HTTP backend rejects
`enroll-client`. File certificate mode retains its existing public-key roster
verification and does not require a CA.

HTTP certificate listeners disable TLS session resumption so every connection
performs certificate verification again; 0-RTT remains disabled. Established TLS
sessions do not periodically revalidate certificate expiry. The authorization
server owns credential activity and returns its stable UUID. HTTP CONNECT-IP
uses dynamic address-pool assignments; fixed addresses from the file roster are
not applied to HTTP identities.

## Authorization server contract

MASQUE sends HTTP/1.1 `POST` to the configured path, with `Content-Type:
application/json`. The endpoint must use a numeric loopback IP (IPv4, IPv6 or
mapped loopback) and an explicit nonzero port. DNS names, remote addresses, URL
credentials, query parameters and HTTPS are rejected. No proxy environment
variables, redirects or automatic file fallback are used. The authorization
server endpoint is a local trust boundary: protect the host and the
authorization server.

Basic request (UTF-8 credentials):

```json
{"type":"basic","username":"alice","password":"example"}
```

Certificate request (SPKI DER encoded as base64, taken from the TLS peer):

```json
{"type":"client_cert","public_key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}
```

Allow response, HTTP status 200:

```json
{"ok":true,"id":"550e8400-e29b-41d4-a716-446655440000"}
```

Deny response, also status 200:

```json
{"ok":false}
```

The response schema is strict: only `ok` and optional `id` are accepted. Success
requires a non-nil UUID. A non-200 status, oversized body, malformed response,
missing/invalid ID, timeout or connection error denies access. Responses are
limited to 4096 bytes and HTTP header buffering to 8192 bytes. Requests never
log passwords. The UUID identifies the credential, not a person; the
authorization server must keep the same UUID across transports and credential
password rotations. Per-credential traffic statistics are a separate feature,
not supplied here.

## Connection reuse and bounds

All listeners share one reusable HTTP client, bounded connection pool and
success cache. Repeated requests reuse HTTP/1.1 keep-alive connections; the pool
retains at most `max_in_flight` idle connections, with a 60-second idle timeout.
A new connection is opened when necessary after idle expiry or authorization
server closure. There is no application keepalive polling. Up to `max_in_flight`
requests can execute at once; this is a pool, not a single serialized connection
for all users.

The absolute `timeout_ms` covers admission to the authorization server pool,
request and full response. Allowed range is 10–30000 ms. `max_in_flight` is
1–256. Existing global, per-source and per-connection authentication admission
bounds also apply to both H2 and H3. No blocking HTTP call runs on a shard or
Argon2 worker.

Successful decisions are cached by a process-secret HMAC of the full typed
credential request, retaining UUID and expiry rather than plaintext passwords.
`cache_ttl_secs` is 0–3600 (0 disables persistent caching); cache hits never
extend expiry. `cache_max_entries` is 1–65536 with bounded FIFO eviction.
Denials and errors are not cached. Identical in-flight requests share one
result; there are at most 256 distinct in-flight credential checks across all
listeners, in addition to process-wide request admission. Dropping a leader
wakes its waiters with a denial; it cannot leave a permanently pending entry.

No authorization server requests occur during packet forwarding. Valid cached
decisions remain usable during an authorization server outage until expiry.
Blocking a credential in the authorization server therefore affects new tunnels
after cache expiry; existing tunnels continue. Immediate per-ID kick/cache
invalidation is not part of this change.

## Commands and reload

`list-users`, `add-user`, `set-password`, `remove-user` and `enroll-client`
reject the HTTP backend without contacting the authorization server or changing
credentials. `add-listener` inherits the global backend and rejects local
credential flags in HTTP mode. `hash-password` and client configuration export
remain utility commands; they do not manage the authorization server's database.

SIGHUP can replace URL, timeout, cache and concurrency settings of an existing
HTTP backend and starts a fresh shared cache/pool. Requests already awaiting a
result retain their original snapshot, as with file credential verification.
Invalid configuration leaves the previous state active. Backend, auth mode and
client CA path changes require restart. Client CA file contents are loaded at
startup; changing them also requires restart. Local status fingerprints track CA
contents as non-reloadable state. `check-config` validates settings and CA
material without contacting the authorization server; it does not prove
authorization server availability.
