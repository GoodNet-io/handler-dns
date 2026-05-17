// SPDX-License-Identifier: GPL-2.0-only
#include "dns.hpp"

#include "dns_records.hpp"

#include <sdk/cpp/endian.hpp>

#include <chrono>
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
/// DNS_GET header layout per §3.2: req(8) + mode(1) + reserved(1)
/// + max_results(2) + reserved(4) + since_us(8) + key_len(2) +
/// reserved(2) = 28 bytes.
constexpr std::size_t kHeaderGet = 28;

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

/// DNS_DELETE header layout per §3.4: req(8) + key_len(2) +
/// reserved(6) = 16 bytes.
constexpr std::size_t kHeaderDelete = 16;
/// DNS_SUBSCRIBE header layout per §3.5: req(8) + mode(1) +
/// reserved(1) + key_len(2) + reserved(4) = 16 bytes.
constexpr std::size_t kHeaderSubscribe = 16;
/// DNS_SYNC header layout per §3.8: req(8) + since_us(8) +
/// max_results(2) + record_count(2) = 20 bytes. The request
/// carries record_count = 0; the reply appends N records.
constexpr std::size_t kHeaderSync = 20;

/// DNS_NOTIFY event kinds per §3.7.
constexpr std::uint8_t kEventPut    = 0;
constexpr std::uint8_t kEventDelete = 1;

struct SyncView {
    std::uint64_t request_id;
    std::uint64_t since_us;
    std::uint16_t max_results;
};

[[nodiscard]] std::optional<SyncView>
parse_sync_request(std::span<const std::uint8_t> payload) {
    if (payload.size() < kHeaderSync) return std::nullopt;
    SyncView v{};
    v.request_id  = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 0, 8});
    v.since_us    = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 8, 8});
    v.max_results = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 16, 2});
    /// record_count at offset 18 must be 0 on a request.
    const auto rec_count = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 18, 2});
    if (rec_count != 0) return std::nullopt;
    return v;
}

/// Encode a DNS_SYNC reply: shares the §3.8 header with the
/// request and appends `record_count` records per §3.6.
[[nodiscard]] std::vector<std::uint8_t>
encode_sync_reply(std::uint64_t request_id, std::uint64_t since_us,
                   std::uint16_t max_results,
                   const std::vector<ResolvedRecord>& records) {
    std::size_t total = kHeaderSync;
    for (const auto& r : records) {
        total += 24 + r.name.size() + r.rdata.size();
    }
    std::vector<std::uint8_t> out(total, 0);
    gn::endian::write_be<std::uint64_t>(
        {out.data() + 0, 8}, request_id);
    gn::endian::write_be<std::uint64_t>(
        {out.data() + 8, 8}, since_us);
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 16, 2}, max_results);
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 18, 2},
        static_cast<std::uint16_t>(records.size()));

    std::size_t off = kHeaderSync;
    for (const auto& r : records) {
        gn::endian::write_be<std::uint64_t>(
            {out.data() + off + 0, 8}, r.timestamp_us);
        gn::endian::write_be<std::uint64_t>(
            {out.data() + off + 8, 8},
            static_cast<std::uint64_t>(r.ttl_s));
        out[off + 16] = 0;  // flags
        out[off + 17] = 0;  // reserved
        gn::endian::write_be<std::uint16_t>(
            {out.data() + off + 18, 2},
            static_cast<std::uint16_t>(r.name.size()));
        gn::endian::write_be<std::uint32_t>(
            {out.data() + off + 20, 4},
            static_cast<std::uint32_t>(r.rdata.size()));
        std::memcpy(out.data() + off + 24,
                    r.name.data(), r.name.size());
        std::memcpy(out.data() + off + 24 + r.name.size(),
                    r.rdata.data(), r.rdata.size());
        off += 24 + r.name.size() + r.rdata.size();
    }
    return out;
}

struct SubscribeView {
    std::uint64_t    request_id;
    std::uint8_t     mode;
    std::string_view key;
};

[[nodiscard]] std::optional<SubscribeView>
parse_subscribe(std::span<const std::uint8_t> payload) {
    if (payload.size() < kHeaderSubscribe) return std::nullopt;
    SubscribeView v{};
    v.request_id = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 0, 8});
    v.mode = payload[8];
    if (v.mode > 1) return std::nullopt;  // since-mode disallowed for sub
    // payload[9] reserved
    const auto key_len = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 10, 2});
    // payload[12..16] reserved
    if (kHeaderSubscribe + key_len != payload.size()) return std::nullopt;
    if (key_len > 256) return std::nullopt;
    v.key = std::string_view(
        reinterpret_cast<const char*>(payload.data() + kHeaderSubscribe),
        key_len);
    return v;
}

/// Encode a DNS_NOTIFY envelope per §3.7: timestamp(8) + event(1)
/// + reserved(1) + Record per §3.6.
[[nodiscard]] std::vector<std::uint8_t>
encode_notify(std::uint64_t timestamp_us, std::uint8_t event,
               std::string_view name,
               std::span<const std::uint8_t> rdata,
               std::uint64_t ttl_s, std::uint8_t flags) {
    const std::size_t record_size = 24 + name.size() + rdata.size();
    std::vector<std::uint8_t> out(10 + record_size, 0);
    gn::endian::write_be<std::uint64_t>(
        {out.data() + 0, 8}, timestamp_us);
    out[8] = event;
    // out[9] reserved
    /// Record §3.6.
    std::size_t r = 10;
    gn::endian::write_be<std::uint64_t>(
        {out.data() + r + 0, 8}, timestamp_us);
    gn::endian::write_be<std::uint64_t>(
        {out.data() + r + 8, 8}, ttl_s);
    out[r + 16] = flags;
    // out[r + 17] reserved
    gn::endian::write_be<std::uint16_t>(
        {out.data() + r + 18, 2},
        static_cast<std::uint16_t>(name.size()));
    gn::endian::write_be<std::uint32_t>(
        {out.data() + r + 20, 4},
        static_cast<std::uint32_t>(rdata.size()));
    std::memcpy(out.data() + r + 24, name.data(), name.size());
    std::memcpy(out.data() + r + 24 + name.size(),
                rdata.data(), rdata.size());
    return out;
}

struct DeleteView {
    std::uint64_t    request_id;
    std::string_view key;
};

[[nodiscard]] std::optional<DeleteView>
parse_delete(std::span<const std::uint8_t> payload) {
    if (payload.size() < kHeaderDelete) return std::nullopt;
    DeleteView v{};
    v.request_id = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 0, 8});
    const auto key_len = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 8, 2});
    // payload[10..16] reserved
    if (kHeaderDelete + key_len != payload.size()) return std::nullopt;
    if (key_len == 0 || key_len > 256) return std::nullopt;
    v.key = std::string_view(
        reinterpret_cast<const char*>(payload.data() + kHeaderDelete),
        key_len);
    return v;
}

struct GetView {
    std::uint64_t   request_id;
    std::uint8_t    mode;
    std::uint16_t   max_results;
    std::uint64_t   since_us;
    std::string_view key;
};

[[nodiscard]] std::optional<GetView>
parse_get(std::span<const std::uint8_t> payload) {
    if (payload.size() < kHeaderGet) return std::nullopt;
    GetView v{};
    v.request_id  = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 0, 8});
    v.mode        = payload[8];
    // payload[9] reserved
    v.max_results = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 10, 2});
    // payload[12..16] reserved
    v.since_us    = gn::endian::read_be<std::uint64_t>(
        {payload.data() + 16, 8});
    const auto key_len = gn::endian::read_be<std::uint16_t>(
        {payload.data() + 24, 2});
    // payload[26..28] reserved
    if (kHeaderGet + key_len != payload.size()) return std::nullopt;
    if (key_len > 256) return std::nullopt;
    v.key = std::string_view(
        reinterpret_cast<const char*>(payload.data() + kHeaderGet),
        key_len);
    return v;
}

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

/// Encode a DNS_RESULT with N records per §3.3 + §3.6.
[[nodiscard]] std::vector<std::uint8_t>
encode_result_records(std::uint64_t request_id, std::uint8_t status,
                       const std::vector<ResolvedRecord>& records) {
    /// Pre-compute total size to avoid mid-build reallocation.
    std::size_t total = 12;  // header
    for (const auto& r : records) {
        total += 24 + r.name.size() + r.rdata.size();
    }
    std::vector<std::uint8_t> out(total, 0);
    gn::endian::write_be<std::uint64_t>(
        {out.data() + 0, 8}, request_id);
    out[8] = status;
    // out[9] reserved zero
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 10, 2}, static_cast<std::uint16_t>(records.size()));

    std::size_t off = 12;
    for (const auto& r : records) {
        /// Record layout §3.6: timestamp(8) + ttl(8) + flags(1) +
        /// reserved(1) + key_len(2) + value_len(4) + key + value.
        gn::endian::write_be<std::uint64_t>(
            {out.data() + off + 0, 8}, r.timestamp_us);
        gn::endian::write_be<std::uint64_t>(
            {out.data() + off + 8, 8},
            static_cast<std::uint64_t>(r.ttl_s));
        out[off + 16] = 0;  // flags — wire records carry no flag bits
        out[off + 17] = 0;  // reserved
        gn::endian::write_be<std::uint16_t>(
            {out.data() + off + 18, 2},
            static_cast<std::uint16_t>(r.name.size()));
        gn::endian::write_be<std::uint32_t>(
            {out.data() + off + 20, 4},
            static_cast<std::uint32_t>(r.rdata.size()));
        std::memcpy(out.data() + off + 24,
                    r.name.data(), r.name.size());
        std::memcpy(out.data() + off + 24 + r.name.size(),
                    r.rdata.data(), r.rdata.size());
        off += 24 + r.name.size() + r.rdata.size();
    }
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

    /// Prune wire-side subscribers whose owning connection
    /// disconnects without sending an explicit unsubscribe. The
    /// kernel publishes DISCONNECTED on the conn-state channel;
    /// the callback walks `wire_subs_` and drops every entry
    /// whose `conn` matches. Without this, dropped peers leak
    /// rows forever.
    if (api_ != nullptr && api_->subscribe_conn_state != nullptr) {
        const auto rc = api_->subscribe_conn_state(
            api_->host_ctx,
            [](void* user, const gn_conn_event_t* ev) noexcept {
                if (ev == nullptr ||
                    ev->kind != GN_CONN_EVENT_DISCONNECTED) return;
                auto* self = static_cast<DnsHandler*>(user);
                std::lock_guard lk(self->sub_mu_);
                std::erase_if(self->wire_subs_,
                    [conn = ev->conn](const WireSubscriber& s) {
                        return s.conn == conn;
                    });
            },
            this,
            /*ud_destroy*/ nullptr,
            &conn_state_sub_);
        if (rc != GN_OK) conn_state_sub_ = GN_INVALID_SUBSCRIPTION_ID;
    }
}

DnsHandler::~DnsHandler() {
    if (api_ != nullptr && api_->unsubscribe != nullptr &&
        conn_state_sub_ != GN_INVALID_SUBSCRIPTION_ID) {
        (void)api_->unsubscribe(api_->host_ctx, conn_state_sub_);
    }
}

std::size_t DnsHandler::subscription_count() const noexcept {
    std::lock_guard lk(sub_mu_);
    return wire_subs_.size();
}

gn_propagation_t DnsHandler::handle_message(const gn_message_t* env) {
    if (env == nullptr || env->payload == nullptr) {
        return GN_PROPAGATION_CONTINUE;
    }

    const std::span<const std::uint8_t> payload{
        env->payload, env->payload_size};
    const gn_conn_id_t sender = env->conn_id;

    switch (env->msg_id) {
    case kMsgDelete: {
        const auto v = parse_delete(payload);
        if (!v) {
            const auto resp = encode_result_ack(0, kStatusBadSize);
            (void)reply(sender, resp);
            return GN_PROPAGATION_CONSUMED;
        }
        const bool ok = resolver_.delete_record(v->key, RrType::TXT);
        const auto resp = encode_result_ack(
            v->request_id, ok ? kStatusOk : kStatusNotFound);
        (void)reply(sender, resp);
        if (ok) {
            notify_wire_subscribers(v->key, {}, /*ttl*/ 0,
                                     /*flags*/ 0,
                                     /*timestamp*/ 0,
                                     kEventDelete);
        }
        return GN_PROPAGATION_CONSUMED;
    }

    case kMsgSync: {
        const auto v = parse_sync_request(payload);
        if (!v) {
            const auto resp = encode_result_ack(0, kStatusBadSize);
            (void)reply(sender, resp);
            return GN_PROPAGATION_CONSUMED;
        }
        std::vector<ResolvedRecord> records;
        if (store_.has_value()) {
            const auto cap = v->max_results == 0 ? 256u
                : static_cast<std::uint32_t>(v->max_results);
            auto raw = store_->get_since(v->since_us, cap);
            records.reserve(raw.size());
            for (const auto& r : raw) {
                /// Decode the type-prefixed store key back into
                /// (RrType, name). Filter to TXT — that's what
                /// the wire surface uses for DNS_PUT records.
                if (auto pair = parse_store_key(r.key)) {
                    if (pair->first != RrType::TXT) continue;
                    ResolvedRecord rec;
                    rec.name         = std::move(pair->second);
                    rec.type         = pair->first;
                    rec.rdata        = std::move(r.value);
                    rec.ttl_s        = static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(r.ttl_s, 0xFFFFFFFFu));
                    rec.timestamp_us = r.timestamp_us;
                    records.push_back(std::move(rec));
                }
            }
        }
        const auto resp = encode_sync_reply(
            v->request_id, v->since_us, v->max_results, records);
        if (api_ != nullptr && api_->send != nullptr) {
            (void)api_->send(api_->host_ctx, sender, kMsgSync,
                              resp.data(), resp.size());
        }
        return GN_PROPAGATION_CONSUMED;
    }

    case kMsgSubscribe: {
        const auto v = parse_subscribe(payload);
        if (!v) {
            const auto resp = encode_result_ack(0, kStatusBadSize);
            (void)reply(sender, resp);
            return GN_PROPAGATION_CONSUMED;
        }
        {
            std::lock_guard lk(sub_mu_);
            wire_subs_.push_back(WireSubscriber{
                sender, v->mode, std::string{v->key}});
        }
        const auto resp = encode_result_ack(v->request_id, kStatusOk);
        (void)reply(sender, resp);
        return GN_PROPAGATION_CONSUMED;
    }

    case kMsgGet: {
        /// Exact mode is the only one wired today. Prefix and
        /// since modes require backend operations the Resolver
        /// does not expose yet — they ack with kStatusBadSize as
        /// a documented placeholder until the resolver grows the
        /// surface.
        const auto v = parse_get(payload);
        if (!v) {
            const auto resp = encode_result_ack(0, kStatusBadSize);
            (void)reply(sender, resp);
            return GN_PROPAGATION_CONSUMED;
        }
        if (v->mode != 0) {  // only exact-mode supported
            const auto resp = encode_result_ack(
                v->request_id, kStatusBadSize);
            (void)reply(sender, resp);
            return GN_PROPAGATION_CONSUMED;
        }
        auto records = resolver_.resolve(
            v->key, RrType::TXT,
            v->max_results == 0 ? 1u
                                : static_cast<std::uint32_t>(v->max_results));
        const auto status = records.empty()
            ? kStatusNotFound : kStatusOk;
        const auto resp = encode_result_records(
            v->request_id, status, records);
        (void)reply(sender, resp);
        return GN_PROPAGATION_CONSUMED;
    }

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
        if (ok) {
            /// The handler does not have a clock injection seam
            /// yet, so the timestamp on the dispatched record is
            /// best-effort (`steady_clock` µs since epoch is not
            /// meaningful across nodes). Subscribers reading the
            /// timestamp_us field should treat it as approximate.
            const auto now = std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
            notify_wire_subscribers(v->key, v->value, v->ttl_s,
                                     v->flags,
                                     static_cast<std::uint64_t>(now),
                                     kEventPut);
        }
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

void DnsHandler::notify_wire_subscribers(
    std::string_view name,
    std::span<const std::uint8_t> rdata,
    std::uint64_t ttl_s,
    std::uint8_t flags,
    std::uint64_t timestamp_us,
    std::uint8_t event) {
    if (api_ == nullptr || api_->send == nullptr) return;

    /// Snapshot the matching subscribers under the lock, then
    /// release the lock before dispatching sends — otherwise a
    /// subscriber callback that re-enters the handler (e.g.
    /// through synchronous send delivery in test fixtures)
    /// deadlocks.
    std::vector<gn_conn_id_t> targets;
    {
        std::lock_guard lk(sub_mu_);
        for (const auto& s : wire_subs_) {
            const bool match =
                (s.mode == 0)
                    ? (name == s.key)
                    : (name.size() >= s.key.size() &&
                       name.compare(0, s.key.size(), s.key) == 0);
            if (match) targets.push_back(s.conn);
        }
    }
    if (targets.empty()) return;

    const auto wire = encode_notify(
        timestamp_us, event, name, rdata, ttl_s, flags);
    for (const auto conn : targets) {
        (void)api_->send(api_->host_ctx, conn, kMsgNotify,
                          wire.data(), wire.size());
    }
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
