# Changelog — goodnet-handler-dns

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_handler_vtable_t` /
`gn_dns_api_t`.

## [Unreleased]

### Wire dispatch — all 7 envelopes live

`handle_message` previously returned `GN_PROPAGATION_CONTINUE`
for every msg_id; local callers reached the resolver only
through the `gn.dns` extension vtable. This release ships full
wire-side dispatch covering the seven `DNS_*` envelopes per
`docs/contracts/dns.en.md`:

- `DNS_PUT` (0x0610) — write through `Resolver::put_record`
  with implicit type = `RrType::TXT` (the wire treats values
  as opaque bytes per the locked v1.x contract).
- `DNS_GET` (0x0611) — exact mode through the typed Resolver;
  prefix + since modes walk the store directly via
  `StoreClient::get_prefix` / `get_since` with the TXT-prefixed
  key, decoded results filtered to TXT.
- `DNS_RESULT` (0x0612) — response envelope shape per §3.3 + §3.6.
- `DNS_DELETE` (0x0613) — routed through `Resolver::delete_record`.
- `DNS_SUBSCRIBE` (0x0614) — exact + prefix modes; subscribers
  recorded under `wire_subs_`, pruned via the kernel's
  conn-state DISCONNECTED channel.
- `DNS_NOTIFY` (0x0615) — auto-dispatched whenever a wire-side
  or extension-side TXT PUT/DELETE matches a subscriber's key.
- `DNS_SYNC` (0x0616) — symmetric envelope; request carries
  `record_count = 0`, reply appends records from
  `StoreClient::get_since` filtered to TXT.

### msg_id constant rename to match the contract

The constants `kMsgResolve` / `kMsgPutRecord` / `kMsgRecordResult`
had value-pair inverted from `docs/contracts/dns.en.md` §2.2.
Renamed to `kMsgPut` / `kMsgGet` / `kMsgResult` so the names match
the contract's `DNS_PUT` / `DNS_GET` / `DNS_RESULT` mapping. The
remaining four (`kMsgDelete`, `kMsgSubscribe`, `kMsgNotify`,
`kMsgSync`) already matched.

### Wire/extension notification coherence on TXT

Extension-API callers using `gn.dns.put_record` /
`gn.dns.delete_record` on `RrType::TXT` records now also fan out
`DNS_NOTIFY` to matching wire subscribers. Without this hook,
an in-process write (e.g. `link-ice`'s SRV resolver) would
update a record under the hood while wire subscribers stayed
stale. Non-TXT writes remain extension-only — the wire surface
has no type field and cannot interpret non-TXT records anyway.

## [1.0.0-rc1] — 2026-05-13

Plugin shipped as a real DNS service over the `gn.handler.store`
primitive — the `015c287` checkpoint shape (a renamed fork of
handler-store) is no longer the head of `main`. The published
surface is enough for `link-ice` to expand `_stun._udp.<host>` SRV
records through the `gn.dns` extension; that integration lives in
`link-ice.git`.

### Added

- **Typed RR layer** (commit `24aed35`): A / AAAA / SRV / TXT /
  PTR / CNAME / NS / MX encoders and parsers in
  `dns_records.{hpp,cpp}`. RR-type numeric values match the IANA
  DNS-parameters registry. RFC 1035 §3.1 name codec without
  compression (pointers belong inside DNS messages, not stand-
  alone rdata).

- **Store-key shape** `<u16 type-byte BE>/<name>` — one
  `gn.handler.store` namespace multiplexes every RR type. Two-byte
  prefix leaves headroom for future IANA allocations.

- **Resolver cascade** (commit `2c141f6`): three-tier walk in
  `dns_resolver.{hpp,cpp}`. Tier 1 = store / cache (honours
  per-record TTL; `ttl_s == 0` marks an operator-curated permanent
  record). Tier 2 = upstream via c-ares (full RR-type support; 3 s
  query timeout × 2 retries; 5 s overall wall). Tier 3 = cache-back
  using the response's own TTL.

- **`gn.store` consumer** (commit `ad78aea`): thin `StoreClient`
  proxy over `host_api->query_extension_checked("gn.store",
  GN_EXT_STORE_VERSION, ...)`. Pattern mirrors
  `sdk/cpp/link_carrier.hpp`. Graceful degradation when the store
  plugin isn't loaded.

- **`IUpstreamResolver` injection point** — tests script answers
  via `MockUpstreamResolver`; production binds
  `AresUpstreamResolver`. The interface lets a future deployment
  swap c-ares for a stub / hosts-file / DoT / DoH client without
  touching the cascade.

- **`gn.dns` extension surface** — `resolve` / `put_record` /
  `delete_record` published through `host_api->register_extension`.
  Local callers (notably `link-ice`) reach the resolver through
  this vtable.

- **`GOODNET_DNS_WITH_UPSTREAM` CMake option** (default ON) gates
  the c-ares dependency. Air-gapped deployments can build the
  store-only flavour with no upstream tier.

- **51 unit tests** across `test_dns` (skeleton) + `test_dns_
  store_client` (proxy round-trip + degradation) + `test_dns_
  records` (RR codec round-trips + malformed-input guards) +
  `test_dns_resolver` (cascade hit / miss / TTL-expiry /
  cache-back / no-upstream / no-store / permanent-record /
  delete). Full kernel ctest 1201/1201 at the plugin's HEAD.

### Removed

- `sqlite_backend.{hpp,cpp}` + `MemoryDnsBackend` + `IDnsBackend`
  (commit `5404ca9`). KV storage moved to the store plugin;
  reaching it through extension query instead.
- `GOODNET_DNS_WITH_SQLITE` CMake option — sqlite is no longer a
  direct dep.
- `tests/test_dns_sqlite_backend.cpp` — the backend test matrix
  belongs under the store plugin.

### Explicitly out of scope

- **DNS server-side daemon** (RFC 1035 UDP listener) — a planned
  follow-up; will live as a standalone application in the spirit
  of legacy `goodnetd-dns`, or as a server-listener add-on inside
  this plugin, when an operator flags the work.
- **mDNS / DNS-SD multicast layer** — same standalone-app
  destination.
- DNSSEC — within the cluster we trust ourselves; upstream is
  plain c-ares without validation for now.
- DHT-backed store backend — would live in handler-store, not
  here.

## [1.0.0-rc0] — 2026-05-13 (throwaway, do not deploy)

Initial shape (`015c287`): a renamed fork of handler-store with
no DNS-specific surface. Kept in git history as the refactor base
for the 1.0.0-rc1 work above.
