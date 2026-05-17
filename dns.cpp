// SPDX-License-Identifier: GPL-2.0-only
#include "dns.hpp"

#include "dns_records.hpp"

#include <sdk/cpp/endian.hpp>

#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

/// DNS_RESULT status codes per `docs/contracts/dns.en.md` §3.3.
constexpr std::uint8_t kStatusOk           = 0;
constexpr std::uint8_t kStatusBadSize      = 1;
constexpr std::uint8_t kStatusNotFound     = 2;
constexpr std::uint8_t kStatusBackendError = 3;

/// DNS_PUT header layout per §3.1: req(8) + ttl(8) + flags(1) +
/// reserved(1) + key_len(2) + value_len(4) = 24 bytes.
constexpr std::size_t kHeaderPut = 24;

/// Parsed view of a DNS_PUT envelope payload. The key + value
/// spans borrow from the wire bytes — caller copies before any
/// re-entry into the handler's backend.
struct PutView {
    std::uint64_t            request_id;
    std::uint64_t            ttl_s;
    std::uint8_t             flags;
    std::string_view         key;
    std::span<const std::uint8_t> value;
};

[[nodiscard]] std::optional<PutView>
parse_put(std::span<const std::uint8_t> payload) {
    if (payload.size() < kHeaderPut) return std::nullopt;
    PutView v{};
    v.request_id = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 0, 8});
    v.ttl_s = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 8, 8});
    v.flags = payload[16];
    // payload[17] reserved
    const auto key_len = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 18, 2});
    const auto value_len = gn::endian::read_be<std::uint32_t>(
        {payload.data() + 20, 4});
    if (kHeaderPut + key_len + value_len != payload.size()) {
        return std::nullopt;
    }
    if (key_len == 0 || key_len > 256) return std::nullopt;
    if (value_len > 65'536) return std::nullopt;

    v.key = std::string_view(
        reinterpret_cast<const char*>(payload.data() + kHeaderPut),
        key_len);
    v.value = std::span<const std::uint8_t>(
        payload.data() + kHeaderPut + key_len, value_len);
    return v;
}

/// Serialize a DNS_RESULT envelope. Layout per §3.3: req(8) +
/// status(1) + reserved(1) + record_count(2) + records (omitted
/// for PUT / DELETE acks).
[[nodiscard]] std::vector<std::uint8_t>
encode_result_ack(std::uint64_t request_id, std::uint8_t status) {
    std::vector<std::uint8_t> out(12, 0);
    gn::endian::write_be<std::uint64_t>(
        {out.data() + 0, 8}, request_id);
    out[8] = status;
    // out[9]   reserved zero
    // out[10..12] record_count == 0
    return out;
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
    if (env == nullptr || env->payload == nullptr) {
        return GN_PROPAGATION_CONTINUE;
    }

    const std::span<const std::uint8_t> payload{
        env->payload, env->payload_size};
    const gn_conn_id_t sender = env->conn_id;

    switch (env->msg_id) {
    case kMsgPut: {
        /// The wire `value` is opaque bytes per the contract
        /// (§3.1). Internally we route the write through the
        /// typed `Resolver` using `RrType::TXT` (16) — the
        /// well-known DNS record for arbitrary text bytes — so
        /// wire-side DNS_PUT/GET round-trips through the same
        /// backend records the extension API exposes. A future
        /// minor of the contract can promote the wire `value` to
        /// carry an explicit `type` prefix; right now the wire
        /// is a generic KV with TXT as the only legible type.
        const auto v = parse_put(payload);
        if (!v) {
            const auto resp = encode_result_ack(/*req*/ 0, kStatusBadSize);
            (void)reply(sender, resp);
            return GN_PROPAGATION_CONSUMED;
        }
        /// `Resolver::put_record` takes `uint32_t ttl_s`; the wire
        /// carries `uint64_t` for future expansion. Clamp to the
        /// backend's accepted range and treat zero as "permanent".
        const std::uint32_t ttl = v->ttl_s > 0xFFFFFFFFu
            ? 0xFFFFFFFFu
            : static_cast<std::uint32_t>(v->ttl_s);
        const bool ok = resolver_.put_record(
            v->key, RrType::TXT, v->value, ttl, v->flags);
        const auto resp = encode_result_ack(
            v->request_id, ok ? kStatusOk : kStatusBackendError);
        (void)reply(sender, resp);
        return GN_PROPAGATION_CONSUMED;
    }

    default:
        /// Remaining envelopes (GET / RESULT / DELETE / SUBSCRIBE /
        /// NOTIFY / SYNC) land in follow-up commits.
        return GN_PROPAGATION_CONTINUE;
    }
}

gn_result_t DnsHandler::reply(gn_conn_id_t conn,
                                std::span<const std::uint8_t> payload) {
    if (api_ == nullptr || api_->send == nullptr) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return api_->send(api_->host_ctx, conn, kMsgResult,
                       payload.data(), payload.size());
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
