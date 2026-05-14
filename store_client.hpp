// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/store_client.hpp
/// @brief  Thin proxy over the `gn.store` extension. handler-dns
///         delegates KV storage to the store plugin through this
///         proxy instead of carrying its own backend code.
///
/// Pattern mirrors `sdk/cpp/link_carrier.hpp:58-75` — query the
/// host_api for a versioned extension, hold the returned vtable
/// for the lifetime of the owning handler, and provide typed C++
/// wrappers around the C ABI slots. The vtable pointer is
/// `@borrowed` from the store plugin and stays valid until the
/// store plugin unregisters (host_api guarantee per
/// `host-api.md` §query_extension).

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/extensions/store.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::handler::dns {

/// In-memory copy of a record retrieved from the store. The
/// extension hands `gn_store_entry_t` as @borrowed pointers; we
/// copy into owned strings/vectors during the proxy boundary so
/// callers don't have to reason about extension-owned buffer
/// lifetimes.
struct StoreRecord {
    std::string                key;
    std::vector<std::uint8_t>  value;
    std::uint64_t              timestamp_us = 0;
    std::uint64_t              ttl_s        = 0;
    std::uint8_t               flags        = 0;
};

/// Proxy over the `gn.store` extension. Construct through `query`;
/// instances are move-only and stay valid until the owning
/// store plugin unregisters.
class StoreClient {
public:
    /// Look up `gn.store` at `GN_EXT_STORE_VERSION`. Returns
    /// `nullopt` when the extension is absent or its version
    /// disagrees, so a caller can degrade gracefully.
    [[nodiscard]] static std::optional<StoreClient>
    query(const host_api_t* api);

    StoreClient(const StoreClient&)            = delete;
    StoreClient& operator=(const StoreClient&) = delete;
    StoreClient(StoreClient&&) noexcept        = default;
    StoreClient& operator=(StoreClient&&) noexcept = default;

    /// Insert or overwrite `(key, value)`.
    [[nodiscard]] bool put(std::string_view key,
                            std::span<const std::uint8_t> value,
                            std::uint64_t ttl_s,
                            std::uint8_t flags) const;

    /// Exact-match lookup. Returns `nullopt` on miss.
    [[nodiscard]] std::optional<StoreRecord>
    get(std::string_view key) const;

    /// Prefix sweep. Returns up to @p max_results matches.
    [[nodiscard]] std::vector<StoreRecord>
    get_prefix(std::string_view prefix, std::uint32_t max_results) const;

    /// Sync window — records with `timestamp_us > since_us`.
    [[nodiscard]] std::vector<StoreRecord>
    get_since(std::uint64_t since_us, std::uint32_t max_results) const;

    /// Remove the record. Returns true when a record existed.
    [[nodiscard]] bool del(std::string_view key) const;

    /// Drop expired records. Returns the number dropped.
    [[nodiscard]] std::uint64_t cleanup_expired() const;

    /// Access the underlying vtable for advanced callers (e.g.
    /// `subscribe` which hands callbacks the proxy can't easily
    /// type-erase). Borrowed; lifetime tied to the extension
    /// provider.
    [[nodiscard]] const gn_store_api_t* vtable() const noexcept { return vt_; }

private:
    StoreClient(const host_api_t* api, const gn_store_api_t* vt) noexcept
        : api_(api), vt_(vt) {}

    /// Drive `query` with @p mode + @p key into a `std::vector` by
    /// passing a lambda through the C `emit` callback. Used by
    /// `get_prefix` / `get_since` and any future query path.
    [[nodiscard]] std::vector<StoreRecord>
    drain_query(gn_store_query_t mode,
                std::string_view key,
                std::uint64_t since_us,
                std::uint32_t max_results) const;

    const host_api_t*    api_;
    const gn_store_api_t* vt_;
};

}  // namespace gn::handler::dns
