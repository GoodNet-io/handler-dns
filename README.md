# `gn.handler.dns`

Real DNS service for a GoodNet cluster. Typed RR storage on top of
`gn.handler.store`, three-tier resolver cascade (local store → cache
→ upstream via c-ares), and a published `gn.dns` extension surface
so in-process callers (notably `link-ice` for SRV expansion of
`stun:<host>` configs) reach the cascade without round-tripping
through the wire.

Storage is delegated to `gn.handler.store` over the host_api
extension boundary; this plugin owns only the DNS-typed schema
layer and resolver logic.

## What ships

* **Typed RR layer** — A / AAAA / SRV / TXT / PTR / CNAME / NS / MX
  encoders and parsers in `dns_records.{hpp,cpp}`. RR-type numeric
  values match the IANA DNS-parameters registry. RFC 1035 §3.1
  name codec without compression (pointers belong inside DNS
  messages, not stand-alone rdata).
* **Store-key shape** `<u16 type-byte BE>/<name>` — one
  `gn.handler.store` namespace multiplexes every RR type. Two-byte
  prefix leaves headroom for future IANA allocations.
* **Resolver cascade** in `dns_resolver.{hpp,cpp}`. Tier 1 = store /
  cache (honours per-record TTL; `ttl_s == 0` marks an
  operator-curated permanent record). Tier 2 = upstream via c-ares
  (full RR-type support; 3 s query timeout × 2 retries; 5 s overall
  wall). Tier 3 = cache-back using the response's own TTL.
* **`gn.store` consumer** — thin `StoreClient` proxy over
  `host_api->query_extension_checked("gn.store",
  GN_EXT_STORE_VERSION, ...)`. Pattern mirrors
  `sdk/cpp/link_carrier.hpp`. Graceful degradation when the store
  plugin isn't loaded.
* **`IUpstreamResolver` injection point** — tests script answers
  via `MockUpstreamResolver`; production binds
  `AresUpstreamResolver`. The interface lets a future deployment
  swap c-ares for a stub / hosts-file / DoT / DoH client without
  touching the cascade.
* **`gn.dns` extension surface** — `resolve` / `put_record` /
  `delete_record` slots backed by the resolver. `link-ice` uses
  this for `_stun._udp.<host>` SRV expansion.
* **`GOODNET_DNS_WITH_UPSTREAM` CMake option** (default ON) gates
  the c-ares dependency. Air-gapped deployments can build the
  store-only flavour with no upstream tier.

## Relation to `gn.handler.store`

`store` is the generic KV primitive (sqlite + memory backends,
prefix queries, subscribe-and-notify). `dns` is the DNS-specific
service layered on top: it queries `store` through the extension
ABI rather than carrying its own backend code. An operator who
loads `dns` must also load `store` first — load order is enforced
through the plugin manifest's `requires` slot once manifest-v2
ships; until then the kernel's load-by-filename order suffices.

The two share an msg-id neighbourhood — `store` keeps the legacy
`0x0600..0x0606` range, `dns` lives at `0x0610..0x0616`.

## Wire format

Byte-layout tables for every envelope live in
[`docs/contracts/dns.en.md`](../../../docs/contracts/dns.en.md) in the
kernel monorepo. TL;DR: big-endian length-prefixed binary. The
wire surface dispatches all seven envelopes today — DNS_PUT /
DNS_GET / DNS_RESULT / DNS_DELETE / DNS_SUBSCRIBE / DNS_NOTIFY /
DNS_SYNC. Wire-side records use `RrType::TXT` as the implicit
type since the locked v1.x layout has no explicit type field;
the typed extension surface (`gn.dns` vtable) keeps the full RR
taxonomy. Both routes share the same backend through the
internal Resolver so local + remote callers stay coherent on
the stored bytes.

DNS_GET supports all three modes — exact (through the typed
Resolver) and prefix + since (direct store walks with the
TXT-prefixed key, decoded results filtered to TXT). DNS_SUBSCRIBE
accepts exact + prefix; subscribers receive DNS_NOTIFY whenever
a wire-side PUT/DELETE matches their key, and the conn-state
DISCONNECTED channel prunes subscribers that vanish without an
explicit teardown.

Wire and extension surfaces share notification coherence on the
TXT type: an in-process caller using the `gn.dns` extension's
`put_record` / `delete_record` on a TXT record also fans out
DNS_NOTIFY to matching wire subscribers, so local writes are
visible to wire-level observers. Non-TXT RR types stay
extension-only since the wire surface has no type field to
distinguish them.

## Not to be confused with

* `sdk/cpp/dns.hpp` (the SDK hostname-resolver helper —
  pure-function `tcp://example.com:443` → IP literal rewrite at
  connect time). See
  [`docs/contracts/hostname-resolver.en.md`](../../../docs/contracts/hostname-resolver.en.md).

## Roadmap

* **UDP RFC 1035 server listener** — full nameserver mode for a
  cluster's authoritative zone. Adds `dns_wire.{hpp,cpp}` (full
  message codec with in-message compression) and
  `dns_server.{hpp,cpp}` (UDP bind + dispatch).
* **mDNS / DNS-SD multicast layer** — local-link discovery.
* **CNAME-direct upstream path** — c-ares lacks a direct CNAME
  parser; raw-message parsing alongside the UDP server work covers
  it.

Explicitly out of scope: DNSSEC validation (we trust ourselves
within the cluster; upstream stays plain c-ares) and any
DHT-backed store backend (that belongs in `gn.handler.store`).

## Building standalone

```sh
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH=$GOODNET_INSTALL_DIR
cmake --build . -j
ctest
```
