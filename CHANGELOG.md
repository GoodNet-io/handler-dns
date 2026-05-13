# Changelog — goodnet-handler-dns

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_handler_vtable_t` /
`gn_dns_api_t`.

## [1.0.0-rc1] — 2026-05-13

### Added

- Initial release. Brings the legacy `apps/store` layer forward as
  the DNS-specific evolution of the v1 GoodNet record store
  plugin. Forked from `goodnet-io/handler-store` at slice 2
  (commit `79ec8b3`) so the two trees share a wire format and an
  `IDnsBackend` abstraction; this plugin diverges by intent —
  typed record schemas, peer-pubkey aware lookup, and (later) DHT
  replication keyed on a Kademlia ID space.
- `gn.dns` extension vtable with `put / get / query / del /
  subscribe / unsubscribe / cleanup_expired` plus the `ctx` /
  `_reserved` ABI footer. Size-prefixed per `abi-evolution.md`
  §3, version `0x00010000`.
- `MemoryDnsBackend` reference backend — hash-map, TTL, prefix
  sweep, since-timestamp filter. Per-process monotonic clock
  wrapper guarantees strictly-increasing timestamps even when
  `system_clock` ticks coincide.
- `SqliteDnsBackend` reference backend — file-backed, seven
  prepared statements cached on the connection. WAL journal,
  `synchronous=NORMAL`, `busy_timeout=5000`. Gated by CMake
  option `GOODNET_DNS_WITH_SQLITE` (default ON).
- Wire dispatcher for seven `DNS_*` envelopes under
  `protocol_id = "gnet-v1"`, `msg_id` range `0x0600..0x0606`.
  Big-endian length-prefixed binary; 256-byte key cap, 64 KiB
  value cap, 256 records per query.
- 38 unit tests covering backend semantics (22 memory + 16
  sqlite), the extension surface, and the wire dispatcher.
- Wire contract published at `docs/contracts/dns.md` in the
  kernel monorepo.

### Planned

- **DhtDnsBackend** — Kademlia replication keyed on the peer
  pubkey ID space; every node holds a slice of the global
  namespace.
- **RedisDnsBackend** — clustered, hot failover for high-fanout
  deployments.
- **`gdns` CLI** — ad-hoc lookups + bulk import / export.
- **Manifest config** `dns.backend` (memory|sqlite|dht|redis) +
  `dns.db_path` so backend selection is a manifest concern.
