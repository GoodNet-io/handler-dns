# Changelog — goodnet-handler-dns

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_handler_vtable_t` /
`gn_dns_api_t`.

## [Unreleased] — refactor into a real DNS service

### Changed

- Plugin rebuilt as a real DNS service over the `gn.handler.store`
  primitive. The previous shape (a renamed copy of handler-store's
  KV machinery) was throwaway scaffolding; the new shape exposes
  DNS-typed records (A / AAAA / SRV / TXT / PTR / CNAME / MX) with
  a resolver cascade local → cache → upstream and an optional
  RFC 1035 UDP server-side listener. See
  [`docs/contracts/dns.md`](../../../docs/contracts/dns.en.md) in
  the kernel monorepo for the slice plan.

### Removed in D-DNS.1

- `sqlite_backend.{hpp,cpp}` and `MemoryDnsBackend` — KV storage
  now lives in the `gn.handler.store` plugin; this plugin reaches
  it through `host_api->query_extension("gn.store")` instead of
  carrying its own backends.
- `IDnsBackend` abstract interface — replaced by a thin
  `StoreClient` proxy that lands in D-DNS.2.
- `GOODNET_DNS_WITH_SQLITE` CMake option — sqlite is no longer a
  direct dep of this plugin.
- `tests/test_dns_sqlite_backend.cpp` — the backend test matrix
  moves under the store plugin where it belongs.

### Pending slices

| Slice | Subject |
|---|---|
| D-DNS.2 | `store_client.{hpp,cpp}` — proxy over `gn.store` extension. |
| D-DNS.3 | `dns_records.{hpp,cpp}` — typed RR encoders/decoders. |
| D-DNS.4 | `dns_resolver.{hpp,cpp}` — three-tier cascade with c-ares. Rewrites `sdk/extensions/dns.h` to the typed API. |
| D-DNS.5 | `link-ice` integration — closes plan §C.1 (SRV resolution). |
| D-DNS.6 | `dns_wire.{hpp,cpp}` + `dns_server.{hpp,cpp}` — RFC 1035 encoder + UDP listener for full nameserver mode. |

## [1.0.0-rc1] — 2026-05-13

### Throwaway checkpoint

- Initial shape: a renamed fork of handler-store with no DNS-
  specific surface. Kept in git history (`015c287`) as the
  refactor base for the rebuilding work above; no operator should
  deploy this revision.
