# `gn.handler.dns`

Real DNS service for a GoodNet cluster. Typed RR storage on top of
`gn.handler.store`, three-tier resolver cascade (local store → cache
→ upstream via c-ares), and an optional RFC 1035 UDP server-side
listener so the plugin can act as a nameserver for a cluster's
authoritative zone.

This plugin is the answer to two distinct asks at once:

* **C.1 from the master plan** — `_stun._udp.<host>` SRV resolution
  for `link-ice`. Operators configure `stun:example.com` and ICE
  reaches into `gn.dns` to expand the SRV record.
* **Legacy `goodnetd-dns` surface** — every node publishes records
  (peer descriptors, service announcements, capability TXT records)
  and other nodes subscribe + resolve them through the same wire
  surface a real DNS resolver speaks.

Storage is delegated to `gn.handler.store` over the host_api
extension boundary; this plugin owns only the DNS-typed schema
layer and resolver/server logic.

## Roadmap

| Slice | Subject | Status |
|---|---|---|
| D-DNS.1 | Cleanup: drop duplicate KV backends | _this commit_ |
| D-DNS.2 | Store consumer via `host_api->query_extension("gn.store")` | pending |
| D-DNS.3 | Typed records: A / AAAA / SRV / TXT / PTR / CNAME / MX | pending |
| D-DNS.4 | Resolver cascade (local → cache → c-ares upstream) | pending |
| D-DNS.5 | `link-ice` integration — closes plan §C.1 | pending |
| D-DNS.6 | RFC 1035 UDP listener — full nameserver mode | pending |

The plugin compiles and registers after every slice; only the
surfaces specified by later slices are absent until they land.

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

Once D-DNS.3 lands, byte-layout tables for every envelope will live
in
[`docs/contracts/dns.md`](../../../docs/contracts/dns.en.md) in
the kernel monorepo. TL;DR: big-endian length-prefixed binary,
RFC-1035 name encoding for record bodies.

## Not to be confused with

* `sdk/cpp/dns.hpp` (the SDK hostname-resolver helper —
  pure-function `tcp://example.com:443` → IP literal rewrite at
  connect time). See
  [`docs/contracts/hostname-resolver.md`](../../../docs/contracts/hostname-resolver.en.md).

## Building standalone

```sh
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH=$GOODNET_INSTALL_DIR
cmake --build . -j
ctest
```
