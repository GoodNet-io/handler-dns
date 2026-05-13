# `gn.handler.dns`

Distributed DNS-style record database surfaced as a v1 GoodNet
handler plugin. Brings the legacy `apps/store` layer forward —
the surface the `goodnetd-dns` binary exposed. A pluggable
`IDnsBackend` (memory reference + sqlite reference) sits behind a
wire dispatcher that covers seven `DNS_*` envelope types. Local
callers reach the same surface through the `gn.dns` extension
vtable.

> Not to be confused with `sdk/cpp/dns.hpp`, the SDK helper that
> rewrites `tcp://example.com:443` into an IP literal at connect
> time. That helper is a pure-function URI rewrite; this plugin
> is a networked record store. See
> [`docs/contracts/hostname-resolver.md`](../../../docs/contracts/hostname-resolver.en.md)
> for the URI rewriter contract and
> [`docs/contracts/dns.md`](../../../docs/contracts/dns.en.md) for
> this plugin's wire format.

## What ships

- `MemoryDnsBackend` — hash-map, TTL, prefix sweep, since-timestamp
  filter. Production builds use it for short-lived nodes whose
  records are rebuilt on restart.
- `SqliteDnsBackend` — file-backed reference with seven prepared
  statements cached on the connection. WAL journal, `synchronous=
  NORMAL`, `busy_timeout=5000`. Gated by `GOODNET_DNS_WITH_SQLITE`
  (default ON).
- `DnsHandler` — wire dispatcher for the seven `DNS_*` msg_ids
  (0x0600..0x0606 under `protocol_id = "gnet-v1"`). Subscribe-and-
  notify on PUT + DELETE, both per-conn (wire) and per-callback
  (in-process).
- `gn.dns` extension vtable for in-process callers
  (`sdk/extensions/dns.h`).
- 38 unit tests across the backend semantics, the extension
  surface, and the wire dispatcher.

## Planned

- DHT backend (Kademlia over GoodNet itself) — every node holds
  a slice of the global namespace.
- Redis backend — clustered, hot failover.
- `gdns` CLI helper for ad-hoc lookups + bulk import / export.
- Manifest config knob `dns.backend` (memory|sqlite) +
  `dns.db_path` so backend selection is a manifest concern.

## Relation to `gn.handler.store`

`handler-store` is the same code lineage shipped as a different
plugin name — a generic key-value store with no DNS-specific
semantics. The two trees were forked at slice 2 (commit `79ec8b3`
in `handler-store.git`). Going forward they diverge by intent:

* `store` keeps the generic surface — applications that want a
  cluster-wide KV with prefix queries and pub/sub use the `store`
  plugin and read records with their own semantics.
* `dns` adds DNS-specific evolution — typed record schemas
  (A / AAAA / SRV / TXT-style entries), peer-pubkey aware lookup,
  service announcements, and (later) DHT replication keyed on a
  Kademlia ID space.

Operators choose either, both, or neither at manifest time. Wire
ids `0x0600..0x0606` belong to whichever the operator loads
first; loading both into the same kernel needs the second one's
manifest to remap its msg_ids (planned).

## Wire format

Full byte-layout tables live in
[`docs/contracts/dns.md`](../../../docs/contracts/dns.en.md).
TL;DR: big-endian length-prefixed binary, 256-byte key cap, 64 KiB
value cap, 256 records per query.

## Building standalone

```sh
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH=$GOODNET_INSTALL_DIR
cmake --build . -j
ctest
```

The CMakeLists auto-falls back to `find_package(GoodNet REQUIRED)`
when invoked outside the kernel monorepo.
