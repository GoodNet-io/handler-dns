// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/dns_resolver.hpp
/// @brief  Three-tier DNS resolver cascade — local store, cache,
///         upstream via c-ares. The store and the cache are the
///         same `gn.store` namespace; upstream answers get written
///         back so the next lookup hits the cache tier without
///         reaching c-ares again.
///
/// `Resolver::resolve(name, type)` walks the tiers in order. A
/// nullopt return from a tier falls through to the next. Empty
/// vector means the chain ran out and we know the name doesn't
/// resolve.
///
/// The upstream tier sits behind an `IUpstreamResolver` so tests
/// can inject `MockUpstreamResolver` without c-ares. Production
/// builds wire `AresUpstreamResolver` when the CMake option
/// `GOODNET_DNS_WITH_UPSTREAM` is ON (default).

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dns_records.hpp"
#include "store_client.hpp"

#include <sdk/host_api.h>

namespace gn::handler::dns {

/// A typed DNS record after resolution. Owns its rdata bytes so
/// caller doesn't worry about backing storage.
struct ResolvedRecord {
    RrType                     type;
    std::string                name;
    std::vector<std::uint8_t>  rdata;        ///< type-specific wire body
    std::uint32_t              ttl_s;        ///< remaining lifetime
    std::uint64_t              timestamp_us; ///< wall-clock of last update
};

/// Wall-clock injection point. Tests script time; production binds
/// to `default_clock_us` defined in `dns_resolver.cpp`.
using ClockNowUs = std::uint64_t (*)() noexcept;

/// Wall-clock reading microseconds from `std::chrono::system_clock`
/// with a per-process monotonic tie-break so two consecutive
/// resolves can't write records sharing a `timestamp_us`. Same
/// shape as `monotonic_default_clock_us` in handler-store, kept
/// distinct so the two plugins evolve independently.
[[nodiscard]] std::uint64_t default_clock_us() noexcept;

/// Abstract upstream resolver. Returns the records for `(name,
/// type)` or an empty vector when the upstream couldn't answer.
/// Implementations must be re-entrant: `Resolver` may call into
/// multiple `IUpstreamResolver` instances concurrently from
/// different threads.
class IUpstreamResolver {
public:
    virtual ~IUpstreamResolver() = default;

    [[nodiscard]] virtual std::vector<ResolvedRecord>
    resolve(std::string_view name, RrType type) = 0;
};

/// Resolver cascade. Glue between the store proxy and an upstream
/// resolver. Both pointers are borrowed for the lifetime of the
/// Resolver; pass `nullptr` for either to disable that tier.
class Resolver {
public:
    Resolver(const StoreClient*   store,
             IUpstreamResolver*    upstream,
             ClockNowUs            clock = &default_clock_us) noexcept
        : store_(store), upstream_(upstream),
          clock_(clock != nullptr ? clock : &default_clock_us) {}

    /// Look up @p name with rrtype @p type. Result is at most
    /// @p max_results long; pass 0 for "no cap" (still bounded by
    /// the store's own `GN_STORE_QUERY_MAX_RESULTS`).
    [[nodiscard]] std::vector<ResolvedRecord>
    resolve(std::string_view name, RrType type,
            std::uint32_t max_results = 0);

    /// Install a typed record into the store under
    /// `<type-byte>/<name>` with the supplied TTL. Used by the
    /// wire-side `DNS_PUT_RECORD` envelope and by the cascade's
    /// own cache-back step.
    [[nodiscard]] bool
    put_record(std::string_view name, RrType type,
               std::span<const std::uint8_t> rdata,
               std::uint32_t ttl_s, std::uint8_t flags) const;

    /// Remove a typed record. Returns true when a record existed.
    [[nodiscard]] bool
    delete_record(std::string_view name, RrType type) const;

    [[nodiscard]] bool has_store()    const noexcept { return store_    != nullptr; }
    [[nodiscard]] bool has_upstream() const noexcept { return upstream_ != nullptr; }

private:
    /// Return the cached record from the store tier when the
    /// timestamp + TTL still has time-to-live left.
    std::optional<ResolvedRecord>
    lookup_store(std::string_view name, RrType type) const;

    const StoreClient*   store_;
    IUpstreamResolver*   upstream_;
    ClockNowUs           clock_;
};

#ifdef GOODNET_DNS_WITH_UPSTREAM

/// Production upstream resolver that drives c-ares synchronously.
/// One channel per instance (cheap — `ares_init` is sub-millisecond
/// on the second call). Thread-safe through the channel's internal
/// queue; concurrent `resolve` calls are serialised by the channel
/// mutex c-ares maintains.
///
/// `ares_library_init` is global per-process; this class refcounts
/// init / cleanup so creating + destroying many instances doesn't
/// race against the library teardown.
class AresUpstreamResolver final : public IUpstreamResolver {
public:
    /// Returns `nullopt` if c-ares can't be initialised
    /// (`/etc/resolv.conf` unreadable, no nameservers configured).
    [[nodiscard]] static std::unique_ptr<AresUpstreamResolver> create();
    ~AresUpstreamResolver() override;

    AresUpstreamResolver(const AresUpstreamResolver&)            = delete;
    AresUpstreamResolver& operator=(const AresUpstreamResolver&) = delete;

    [[nodiscard]] std::vector<ResolvedRecord>
    resolve(std::string_view name, RrType type) override;

private:
    explicit AresUpstreamResolver(void* channel) noexcept;
    void* channel_;  ///< type-erased `ares_channel` — keeps the header c-ares-clean
};

#endif  // GOODNET_DNS_WITH_UPSTREAM

}  // namespace gn::handler::dns
