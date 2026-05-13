# Changelog — goodnet-handler-dns

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_handler_vtable_t` /
`gn_dns_api_t`.

## [1.0.0-rc1] — 2026-05-13

Plugin shipped as a real DNS service over the `gn.handler.store`
primitive — the `015c287` checkpoint shape (a renamed fork of
handler-store) is no longer the head of `main`. Four slices land
the production scope; the fifth (link-ice integration) lives in
`link-ice.git` and closes the master plan's §C.1.

### Added

- **Typed RR layer** (D-DNS.3 — commit `24aed35`): A / AAAA / SRV /
  TXT / PTR / CNAME / NS / MX encoders and parsers in
  `dns_records.{hpp,cpp}`. RR-type numeric values match the IANA
  DNS-parameters registry. RFC 1035 §3.1 name codec without
  compression (pointers belong inside DNS messages, not stand-
  alone rdata).

- **Store-key shape** `<u16 type-byte BE>/<name>` — one
  `gn.handler.store` namespace multiplexes every RR type. Two-byte
  prefix leaves headroom for future IANA allocations.

- **Resolver cascade** (D-DNS.4 — commit `2c141f6`): three-tier
  walk in `dns_resolver.{hpp,cpp}`. Tier 1 = store / cache (honours
  per-record TTL; `ttl_s == 0` marks an operator-curated permanent
  record). Tier 2 = upstream via c-ares (full RR-type support; 3 s
  query timeout × 2 retries; 5 s overall wall). Tier 3 = cache-back
  using the response's own TTL.

- **`gn.store` consumer** (D-DNS.2 — commit `ad78aea`): thin
  `StoreClient` proxy over `host_api->query_extension_checked
  ("gn.store", GN_EXT_STORE_VERSION, ...)`. Pattern mirrors
  `sdk/cpp/link_carrier.hpp`. Graceful degradation when the store
  plugin isn't loaded.

- **`IUpstreamResolver` injection point** — tests script answers
  via `MockUpstreamResolver`; production binds
  `AresUpstreamResolver`. The interface lets a future deployment
  swap c-ares for stub / hosts-file / DoT / DoH without touching
  the cascade.

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
  (D-DNS.1 — commit `5404ca9`). KV storage moved to the store
  plugin; reaching it through extension query instead.
- `GOODNET_DNS_WITH_SQLITE` CMake option — sqlite is no longer a
  direct dep.
- `tests/test_dns_sqlite_backend.cpp` — the backend test matrix
  belongs under the store plugin.

### Pending (separate scope)

- **link-ice integration** (D-DNS.5) lives in `link-ice.git`,
  consumes the `gn.dns` extension to expand `stun:<hostname>`
  configs via SRV. Closes master-plan §C.1.

### Explicitly out of scope

- **DNS server-side daemon** (RFC 1035 UDP listener) — that's a
  standalone application in the spirit of legacy `goodnetd-dns`,
  not a handler-plugin feature. Lives in a future
  `apps/goodnet-dnsd/` or its own git when an operator flags
  the work.
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
