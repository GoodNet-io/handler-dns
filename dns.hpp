// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/dns.hpp
/// @brief  DNS handler — real DNS service that uses gn.handler.store
///         for its record backing. The plugin owns the DNS-typed
///         schema layer, the upstream resolver cascade, and (in
///         D-DNS.6) a UDP server-side listener. Storage primitives
///         live in the store plugin and reach us through the
///         `gn.store` extension.
///
/// Wire surface (`protocol_id = "gnet-v1"`, msg_id allocation):
///
///   * 0x0610  DNS_RESOLVE      — client → server: resolve (name, type)
///   * 0x0611  DNS_PUT_RECORD   — client → server: install a typed record
///   * 0x0612  DNS_RECORD_RESULT — server → client: response envelope
///   * 0x0613  DNS_DELETE       — client → server: remove a typed record
///   * 0x0614  DNS_SUBSCRIBE    — client → server: watch a name / prefix
///   * 0x0615  DNS_NOTIFY       — server → subscriber: change event
///   * 0x0616  DNS_SYNC         — symmetric: replicate the typed namespace
///
/// The wire layout for each envelope is published in
/// `docs/contracts/dns.md`. Slice D-DNS.1 wires only the handler
/// vtable + the on-wire scaffold so the kernel can register us;
/// real semantics arrive in D-DNS.2 (store consumer) through D-DNS.4
/// (resolver). The plugin compiles after this slice but every
/// `handle_message` returns `GN_PROPAGATION_CONTINUE` (no-op).

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "dns_resolver.hpp"
#include "store_client.hpp"

#include <sdk/extensions/dns.h>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::handler::dns {

/// On-wire identifiers for the seven DNS_* envelopes. The
/// `0x0610..0x0616` block sits next to the legacy `0x0600..0x0606`
/// range that `gn.handler.store` keeps, so a node hosting both
/// plugins routes traffic unambiguously by `msg_id`.
inline constexpr std::uint32_t kMsgResolve     = 0x0610;
inline constexpr std::uint32_t kMsgPutRecord   = 0x0611;
inline constexpr std::uint32_t kMsgRecordResult = 0x0612;
inline constexpr std::uint32_t kMsgDelete      = 0x0613;
inline constexpr std::uint32_t kMsgSubscribe   = 0x0614;
inline constexpr std::uint32_t kMsgNotify      = 0x0615;
inline constexpr std::uint32_t kMsgSync        = 0x0616;

/// Stable protocol-id this handler binds to.
inline constexpr const char* kProtocolId = "gnet-v1";

/// DNS handler — slice D-DNS.1 ships only the scaffold. Real
/// dispatch arrives in later slices (store consumer / resolver
/// cascade / server-side).
class DnsHandler {
public:
    explicit DnsHandler(const host_api_t* api);
    ~DnsHandler();

    DnsHandler(const DnsHandler&)            = delete;
    DnsHandler& operator=(const DnsHandler&) = delete;

    /// Static metadata read by `GN_HANDLER_PLUGIN`.
    static constexpr const char*    protocol_id() noexcept { return kProtocolId; }
    static constexpr std::uint32_t  msg_id()      noexcept { return kMsgResolve; }
    static constexpr std::uint8_t   priority()    noexcept { return 200; }

    /// Extension surface metadata read by `GN_HANDLER_PLUGIN` to
    /// publish the `gn.dns` vtable through `host_api->register_extension`.
    static constexpr const char*    extension_name()    noexcept { return GN_EXT_DNS; }
    static constexpr std::uint32_t  extension_version() noexcept { return GN_EXT_DNS_VERSION; }

    /// Wire dispatch entry point. D-DNS.1 returns CONTINUE for
    /// every msg_id; subsequent slices fill in the cases.
    [[nodiscard]] gn_propagation_t handle_message(const gn_message_t* env);
    [[nodiscard]] gn_propagation_t handle_message(const gn_message_t& env) {
        return handle_message(&env);
    }

    /// True when `gn.store` was reachable at construction.
    /// Diagnostics + tests rely on this; resolver paths (D-DNS.4)
    /// degrade to upstream-only when store is absent.
    [[nodiscard]] bool has_store() const noexcept { return store_.has_value(); }

    /// Access to the store proxy. Returns nullptr when `gn.store`
    /// is not registered.
    [[nodiscard]] const StoreClient* store() const noexcept {
        return store_ ? &*store_ : nullptr;
    }

    /// Access to the typed resolver. Always non-null after
    /// construction — the cascade still works as a passthrough
    /// when neither store nor upstream is available (it just
    /// returns empty for everything).
    [[nodiscard]] Resolver& resolver() noexcept { return resolver_; }

    /// Pointer to the published extension vtable. Reads by the
    /// macro-generated `gn_plugin_register` entry point.
    [[nodiscard]] const gn_dns_api_t* extension_vtable() const noexcept {
        return &ext_vtable_;
    }

private:
    /// Extension thunks bridging the C ABI to the Resolver.
    static int  ext_resolve(void* ctx, const char* name, size_t name_len,
                             std::uint16_t type, std::uint32_t max_results,
                             gn_dns_emit_cb_t emit, void* emit_user);
    static int  ext_put_record(void* ctx, const char* name, size_t name_len,
                                std::uint16_t type,
                                const std::uint8_t* rdata, size_t rdata_len,
                                std::uint32_t ttl_s, std::uint8_t flags);
    static int  ext_delete_record(void* ctx, const char* name, size_t name_len,
                                   std::uint16_t type);

    const host_api_t*               api_;
    std::optional<StoreClient>      store_;
    std::unique_ptr<IUpstreamResolver> upstream_;  ///< nullptr if no c-ares
    Resolver                        resolver_;
    gn_dns_api_t                    ext_vtable_{};
};

}  // namespace gn::handler::dns
