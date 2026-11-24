# Per-credential accounting API

Enable the read-only local API independently of Prometheus:

```toml
[accounting]
listen_addr = "127.0.0.1:9091"
```

Omitting `listen_addr` disables the API and credential counter allocation.
Only loopback addresses are accepted. The endpoint has no authentication and
is intended for trusted local collectors. It is not a public proxy listener.
Changing its configuration requires restart.

`GET /stats` returns JSON and closes the HTTP connection:

```json
{
  "instance_id": "550e8400-e29b-41d4-a716-446655440000",
  "traffic": [
    {
      "id": "123e4567-e89b-42d3-a456-426614174000",
      "rx_bytes": 123456,
      "tx_bytes": 654321
    }
  ],
  "online": ["123e4567-e89b-42d3-a456-426614174000"]
}
```

`instance_id` is generated once at server startup. It stays unchanged across
SIGHUP, authorization-cache expiry/eviction, password changes and reconnects.
Every new server instance gets a new ID, even if it binds the same address.
A collector must use this ID to distinguish cumulative counters from a new
instance rather than comparing values across a restart.

`traffic` contains cumulative unsigned 64-bit payload byte counters keyed by
credential UUID. File Basic users, file certificate identities and HTTP
authorization responses supply the same typed UUID throughout authorization
and tunnel dispatch. Counters aggregate all listeners, H2/H3 and CONNECT,
CONNECT-UDP and CONNECT-IP tunnels for that UUID. Authentication-disabled
listeners have no credential identity and do not appear in this API.
Failed authentication creates no entry. An authorized setup that later fails
may leave a zero-valued traffic entry, but never makes the credential online.

RX means client-to-target and TX means target-to-client, from the MASQUE
server's perspective. TCP counts stream payload, UDP counts datagram payload,
and CONNECT-IP counts complete inner IP packets after policy validation.
MASQUE capsules and Context IDs, TLS/QUIC framing, SOCKS5 headers and transport
retransmissions are excluded. DIRECT and SOCKS5 payloads are counted once.
Counters record payload admitted to the relay buffers; they are not proof of
remote application delivery. A reset, local I/O failure or UDP congestion may
discard already counted data. CONNECT-IP address-assignment and other control
capsules do not count as traffic.

`online` is a set of unique credential UUIDs with at least one established,
not-yet-torn-down tunnel. Idle open tunnels count; an authenticated transport
connection with no open tunnel does not. Multiple tunnels or connections with
the same credential produce one UUID. After the last tunnel closes, the UUID
leaves `online` but its traffic counters remain. This is not a device count.
Empty `traffic` and `online` are valid, complete observations.

Entries are never evicted, expired, cleared by a read, or removed on credential
revocation. There is no UUID limit or admission rejection imposed by accounting.
Memory therefore grows with the number of distinct admitted credential UUIDs
since startup, including credentials no longer present in the authorization
source. History and destinations are not stored. Stopping the process loses
its in-memory counters; bytes not yet collected can be lost. This API has no
ACK, durable journal, or per-credential reset operation.

Responses stream in batches of at most 128 entries without constructing a
complete JSON document in memory. At most four requests run concurrently,
request headers are limited to 8 KiB and each request has a 30-second deadline.
A timed-out response is incomplete and must not be applied by a collector.
The initial entry count bounds a response: credentials added during the read
appear on the next poll. Counters and online are sampled while traffic keeps
flowing; the response is not a single transactional snapshot. In particular,
a tunnel may close between its traffic row and the online pass. Scraping takes
brief registry locks per batch; packet accounting uses retained counter
references and atomic increments without UUID lookups or HTTP calls.

An external collector can poll this endpoint and associate each UUID with its
credential record. Keep the previous counters together with `instance_id` to
calculate traffic deltas; a changed instance ID starts a new counter baseline.
