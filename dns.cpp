// SPDX-License-Identifier: GPL-2.0-only
#include "dns.hpp"

#include "dns_records.hpp"

namespace gn::handler::dns {

namespace {

/// Resolve the upstream tier on construction. When the plugin
/// was built without c-ares (`-DGOODNET_DNS_WITH_UPSTREAM=OFF`)
/// the resolver runs store-only; same when c-ares is present but
/// `/etc/resolv.conf` can't be read.
std::unique_ptr<IUpstreamResolver> make_upstream() {
#ifdef GOODNET_DNS_WITH_UPSTREAM
    return AresUpstreamResolver::create();
#else
    return nullptr;
#endif
}

}  // namespace

DnsHandler::DnsHandler(const host_api_t* api)
    : api_(api),
      store_(StoreClient::query(api)),
      upstream_(make_upstream()),
      resolver_(store_ ? &*store_ : nullptr,
                upstream_.get()) {
    /// Build the published vtable. The thunks below convert C ABI
    /// arguments into the `Resolver`'s C++ surface and re-emit the
    /// owned records as borrowed `gn_dns_record_t` views the caller
    /// can copy during the callback.
    ext_vtable_.api_size      = sizeof(gn_dns_api_t);
    ext_vtable_.resolve       = &DnsHandler::ext_resolve;
    ext_vtable_.put_record    = &DnsHandler::ext_put_record;
    ext_vtable_.delete_record = &DnsHandler::ext_delete_record;
    ext_vtable_.ctx           = this;
}

DnsHandler::~DnsHandler() = default;

gn_propagation_t DnsHandler::handle_message(const gn_message_t* env) {
    /// Wire-side dispatch (DNS_RESOLVE / DNS_PUT_RECORD / ...) lands
    /// alongside the SDK ABI extension once D-DNS.5 has consumers
    /// over the wire. The extension vtable above already exposes
    /// `resolve` / `put_record` / `delete_record` to local callers
    /// — link-ice's gn.dns query path uses that and does not
    /// require the wire envelopes.
    (void)env;
    return GN_PROPAGATION_CONTINUE;
}

// ── extension thunks ────────────────────────────────────────────────────────

int DnsHandler::ext_resolve(void* ctx, const char* name, size_t name_len,
                              std::uint16_t type, std::uint32_t max_results,
                              gn_dns_emit_cb_t emit, void* emit_user) {
    if (ctx == nullptr || emit == nullptr) return 0;
    if (!is_known_rrtype(type)) return 0;
    auto* self = static_cast<DnsHandler*>(ctx);

    auto records = self->resolver_.resolve(
        std::string_view{name ? name : "", name_len},
        static_cast<RrType>(type), max_results);

    for (const auto& r : records) {
        gn_dns_record_t view{};
        view.type         = static_cast<std::uint16_t>(rrtype_value(r.type));
        view.name         = r.name.data();
        view.name_len     = r.name.size();
        view.rdata        = r.rdata.data();
        view.rdata_len    = r.rdata.size();
        view.ttl_s        = r.ttl_s;
        view.timestamp_us = r.timestamp_us;
        view.flags        = 0;
        emit(emit_user, &view);
    }
    return static_cast<int>(records.size());
}

int DnsHandler::ext_put_record(void* ctx,
                                 const char* name, size_t name_len,
                                 std::uint16_t type,
                                 const std::uint8_t* rdata, size_t rdata_len,
                                 std::uint32_t ttl_s, std::uint8_t flags) {
    if (ctx == nullptr || name == nullptr) return -1;
    if (!is_known_rrtype(type)) return -1;
    auto* self = static_cast<DnsHandler*>(ctx);
    if (!self->resolver_.put_record(
            std::string_view{name, name_len},
            static_cast<RrType>(type),
            {rdata, rdata_len},
            ttl_s, flags)) {
        return -2;
    }
    return 0;
}

int DnsHandler::ext_delete_record(void* ctx,
                                    const char* name, size_t name_len,
                                    std::uint16_t type) {
    if (ctx == nullptr || name == nullptr) return -2;
    if (!is_known_rrtype(type)) return -2;
    auto* self = static_cast<DnsHandler*>(ctx);
    return self->resolver_.delete_record(
        std::string_view{name, name_len},
        static_cast<RrType>(type)) ? 0 : -1;
}

}  // namespace gn::handler::dns
