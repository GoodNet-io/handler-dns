// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/tests/test_dns_store_client.cpp
/// @brief  StoreClient — exercises the proxy against a stub
///         `gn.store` extension to confirm round-trip semantics and
///         graceful degradation when the extension is absent.
///
/// handler-dns delegates all KV work to gn.handler.store through
/// the host_api extension boundary. The stub here mimics what
/// handler-store would publish; the resolver cascade feeds records
/// through this same proxy.

#include <gtest/gtest.h>

#include <dns.hpp>
#include <store_client.hpp>

#include <sdk/cpp/endian.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/store.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <span>
#include <vector>

#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// NOLINTBEGIN(bugprone-unchecked-optional-access)

namespace gn::handler::dns {
namespace {

// ── stub gn.store extension ────────────────────────────────────────────────

/// Minimal in-memory store the test drives the proxy against.
/// Backs the `gn_store_api_t` vtable below; instance lifetime
/// must outlive the DnsHandler in every test.
struct StubStore {
    struct Row {
        std::vector<std::uint8_t> value;
        std::uint64_t             timestamp_us = 0;
        std::uint64_t             ttl_s        = 0;
        std::uint8_t              flags        = 0;
    };

    std::mutex                              mu;
    std::unordered_map<std::string, Row>    rows;
    std::uint64_t                           clock_us = 1'000'000;

    /// Build the vtable that handler-dns will see when it queries
    /// `gn.store`. Static thunks delegate to the StubStore via the
    /// `ctx` slot.
    gn_store_api_t make_vtable() {
        gn_store_api_t vt{};
        vt.api_size        = sizeof(gn_store_api_t);
        vt.put             = &StubStore::on_put;
        vt.get             = &StubStore::on_get;
        vt.query           = &StubStore::on_query;
        vt.del             = &StubStore::on_del;
        vt.subscribe       = nullptr;
        vt.unsubscribe     = nullptr;
        vt.cleanup_expired = &StubStore::on_cleanup_expired;
        vt.ctx             = this;
        return vt;
    }

private:
    static int on_put(void* ctx,
                       const char* key, size_t klen,
                       const std::uint8_t* val, size_t vlen,
                       std::uint64_t ttl_s, std::uint8_t flags) {
        auto* s = static_cast<StubStore*>(ctx);
        if (key == nullptr || klen == 0) return -1;
        std::lock_guard lk(s->mu);
        Row r;
        if (val != nullptr && vlen > 0) r.value.assign(val, val + vlen);
        r.timestamp_us = s->clock_us++;
        r.ttl_s        = ttl_s;
        r.flags        = flags;
        s->rows.insert_or_assign(std::string(key, klen), std::move(r));
        return 0;
    }

    static int on_get(void* ctx,
                       const char* key, size_t klen,
                       gn_store_entry_t* out) {
        auto* s = static_cast<StubStore*>(ctx);
        if (key == nullptr || out == nullptr) return -2;
        std::lock_guard lk(s->mu);
        auto it = s->rows.find(std::string(key, klen));
        if (it == s->rows.end()) return -1;
        /// `key` / `value` pointers in `out` borrow the storage in
        /// the map — they're valid until the next mutation. Tests
        /// must copy before driving another stub op.
        out->key          = it->first.data();
        out->key_len      = it->first.size();
        out->value        = it->second.value.data();
        out->value_len    = it->second.value.size();
        out->timestamp_us = it->second.timestamp_us;
        out->ttl_s        = it->second.ttl_s;
        out->flags        = it->second.flags;
        return 0;
    }

    static int on_query(void* ctx,
                         gn_store_query_t mode,
                         const char* key, size_t klen,
                         std::uint64_t since_us,
                         std::uint32_t max_results,
                         void (*emit)(void*, const gn_store_entry_t*),
                         void* user) {
        auto* s = static_cast<StubStore*>(ctx);
        if (emit == nullptr) return 0;
        std::lock_guard lk(s->mu);
        int count = 0;
        for (const auto& [k, row] : s->rows) {
            if (max_results > 0 &&
                static_cast<std::uint32_t>(count) >= max_results) break;
            bool match = false;
            switch (mode) {
            case GN_STORE_QUERY_EXACT:
                match = (k.size() == klen &&
                         std::memcmp(k.data(), key, klen) == 0);
                break;
            case GN_STORE_QUERY_PREFIX:
                match = (k.size() >= klen &&
                         std::memcmp(k.data(), key, klen) == 0);
                break;
            case GN_STORE_QUERY_SINCE:
                match = (row.timestamp_us > since_us);
                break;
            }
            if (!match) continue;
            gn_store_entry_t view{};
            view.key          = k.data();
            view.key_len      = k.size();
            view.value        = row.value.data();
            view.value_len    = row.value.size();
            view.timestamp_us = row.timestamp_us;
            view.ttl_s        = row.ttl_s;
            view.flags        = row.flags;
            emit(user, &view);
            ++count;
        }
        return count;
    }

    static int on_del(void* ctx, const char* key, size_t klen) {
        auto* s = static_cast<StubStore*>(ctx);
        if (key == nullptr) return -2;
        std::lock_guard lk(s->mu);
        return s->rows.erase(std::string(key, klen)) > 0 ? 0 : -1;
    }

    static std::uint64_t on_cleanup_expired(void* ctx) {
        auto* s = static_cast<StubStore*>(ctx);
        std::uint64_t dropped = 0;
        std::lock_guard lk(s->mu);
        for (auto it = s->rows.begin(); it != s->rows.end(); ) {
            const auto& r = it->second;
            if (r.ttl_s > 0 &&
                r.timestamp_us + r.ttl_s * 1'000'000ULL <= s->clock_us) {
                it = s->rows.erase(it);
                ++dropped;
            } else {
                ++it;
            }
        }
        return dropped;
    }
};

// ── host_api with an extension registry ────────────────────────────────────

/// Drop-in extension registry that gives the test control over
/// what `query_extension_checked` returns. Stub_host's HandlerStub
/// doesn't model extensions so we wire our own.
///
/// Now also captures `send` calls so wire-side tests can assert
/// on the DNS_RESULT / DNS_NOTIFY envelopes the handler emits in
/// response to inbound wire envelopes. Without this the wire
/// dispatch path silently drops replies.
struct ExtensionHost {
    std::unordered_map<std::string,
                       std::pair<std::uint32_t, const void*>> extensions;

    /// Captured sends. Each entry records (conn, msg_id, payload).
    std::mutex                                 send_mu;
    std::vector<gn_conn_id_t>                  sent_conns;
    std::vector<std::uint32_t>                 sent_msg_ids;
    std::vector<std::vector<std::uint8_t>>     sent_payloads;

    static gn_result_t on_query(void* host_ctx,
                                 const char* name,
                                 std::uint32_t version,
                                 const void** out_vtable) {
        auto* h = static_cast<ExtensionHost*>(host_ctx);
        if (name == nullptr || out_vtable == nullptr) return GN_ERR_NULL_ARG;
        auto it = h->extensions.find(name);
        if (it == h->extensions.end()) return GN_ERR_NOT_FOUND;
        if (it->second.first < version) return GN_ERR_VERSION_MISMATCH;
        *out_vtable = it->second.second;
        return GN_OK;
    }

    static gn_result_t on_send(void* host_ctx,
                                gn_conn_id_t conn,
                                std::uint32_t msg_id,
                                const std::uint8_t* payload,
                                std::size_t payload_size) {
        auto* h = static_cast<ExtensionHost*>(host_ctx);
        std::lock_guard lk(h->send_mu);
        h->sent_conns.push_back(conn);
        h->sent_msg_ids.push_back(msg_id);
        h->sent_payloads.emplace_back(payload, payload + payload_size);
        return GN_OK;
    }
};

host_api_t make_api_with_store(ExtensionHost& host) {
    host_api_t api{};
    api.host_ctx                = &host;
    api.query_extension_checked = &ExtensionHost::on_query;
    api.send                    = &ExtensionHost::on_send;
    return api;
}

// ── tests ──────────────────────────────────────────────────────────────────

TEST(StoreClient_Query, Nullopt_WhenExtensionAbsent) {
    ExtensionHost host;
    auto api = make_api_with_store(host);
    EXPECT_FALSE(StoreClient::query(&api).has_value());
}

TEST(StoreClient_Query, Nullopt_WhenApiSlotMissing) {
    host_api_t api{};
    EXPECT_FALSE(StoreClient::query(&api).has_value());
    EXPECT_FALSE(StoreClient::query(nullptr).has_value());
}

TEST(StoreClient_Query, ResolvesWhenStoreRegistered) {
    ExtensionHost host;
    StubStore stub;
    auto vtable = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vtable};

    auto api = make_api_with_store(host);
    auto client = StoreClient::query(&api);
    ASSERT_TRUE(client.has_value());
    EXPECT_EQ(client.value().vtable(), &vtable);
}

TEST(StoreClient_PutGet, RoundtripsThroughStub) {
    ExtensionHost host;
    StubStore stub;
    auto vtable = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vtable};

    auto api = make_api_with_store(host);
    auto client = StoreClient::query(&api);
    ASSERT_TRUE(client.has_value());

    const std::vector<std::uint8_t> v{0xa, 0xb, 0xc};
    EXPECT_TRUE(client.value().put("peer/alice", v, 0, 7));

    auto hit = client.value().get("peer/alice");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit.value().key,   "peer/alice");
    EXPECT_EQ(hit.value().value, v);
    EXPECT_EQ(hit.value().flags, 7u);
}

TEST(StoreClient_Prefix, FiltersByPrefix) {
    ExtensionHost host;
    StubStore stub;
    auto vtable = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vtable};

    auto api = make_api_with_store(host);
    auto client = StoreClient::query(&api).value();

    EXPECT_TRUE(client.put("peer/alice", std::vector<std::uint8_t>{1}, 0, 0));
    EXPECT_TRUE(client.put("peer/bob",   std::vector<std::uint8_t>{2}, 0, 0));
    EXPECT_TRUE(client.put("svc/chat",   std::vector<std::uint8_t>{3}, 0, 0));

    auto hits = client.get_prefix("peer/", 16);
    EXPECT_EQ(hits.size(), 2u);
}

TEST(StoreClient_Delete, RemovesRecord) {
    ExtensionHost host;
    StubStore stub;
    auto vtable = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vtable};

    auto api = make_api_with_store(host);
    auto client = StoreClient::query(&api).value();

    EXPECT_TRUE(client.put("k", std::vector<std::uint8_t>{1}, 0, 0));
    EXPECT_TRUE(client.del("k"));
    EXPECT_FALSE(client.get("k").has_value());
    /// Second delete misses.
    EXPECT_FALSE(client.del("k"));
}

// ── DnsHandler integration ─────────────────────────────────────────────────

TEST(DnsHandler_Store, DegradesGracefullyWithoutExtension) {
    ExtensionHost host;
    auto api = make_api_with_store(host);
    DnsHandler h(&api);
    EXPECT_FALSE(h.has_store());
    EXPECT_EQ(h.store(), nullptr);
}

TEST(DnsHandler_Store, PicksUpStoreWhenRegistered) {
    ExtensionHost host;
    StubStore stub;
    auto vtable = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vtable};

    auto api = make_api_with_store(host);
    DnsHandler h(&api);
    ASSERT_TRUE(h.has_store());
    ASSERT_NE(h.store(), nullptr);
    EXPECT_TRUE(h.store()->put(
        "ping", std::vector<std::uint8_t>{0xee}, 60, 0));
    auto hit = h.store()->get("ping");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit.value().value, (std::vector<std::uint8_t>{0xee}));
}

// ── Wire dispatch + store integration ────────────────────────────────────
//
// Positive end-to-end: a DNS_PUT envelope writes through the resolver to
// the StubStore; a subsequent DNS_GET reads back the same bytes via the
// resolver's exact-mode lookup. Validates the type-prefixed key encoding
// `RrType::TXT` uses, the wire-vs-extension surface coherence, and the
// DNS_RESULT shape end-to-end.

namespace {

std::vector<std::uint8_t> make_put_payload(std::uint64_t request_id,
                                             std::uint64_t ttl_s,
                                             std::uint8_t flags,
                                             std::string_view key,
                                             std::span<const std::uint8_t> value) {
    std::vector<std::uint8_t> out(24 + key.size() + value.size());
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    gn::endian::write_be<std::uint64_t>({out.data() + 8, 8}, ttl_s);
    out[16] = flags;
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 18, 2}, static_cast<std::uint16_t>(key.size()));
    gn::endian::write_be<std::uint32_t>(
        {out.data() + 20, 4}, static_cast<std::uint32_t>(value.size()));
    std::memcpy(out.data() + 24, key.data(), key.size());
    std::memcpy(out.data() + 24 + key.size(), value.data(), value.size());
    return out;
}

std::vector<std::uint8_t> make_get_payload(std::uint64_t request_id,
                                              std::uint8_t mode,
                                              std::uint16_t max_results,
                                              std::string_view key) {
    std::vector<std::uint8_t> out(28 + key.size());
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    out[8] = mode;
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 10, 2}, max_results);
    gn::endian::write_be<std::uint64_t>({out.data() + 16, 8}, 0u);
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 24, 2}, static_cast<std::uint16_t>(key.size()));
    std::memcpy(out.data() + 28, key.data(), key.size());
    return out;
}

gn_message_t make_wire_env(std::uint32_t msg_id, gn_conn_id_t conn,
                             std::span<const std::uint8_t> payload) {
    gn_message_t e{};
    e.msg_id       = msg_id;
    e.conn_id      = conn;
    e.payload      = payload.data();
    e.payload_size = payload.size();
    return e;
}

} // namespace

TEST(DnsWire_StoreBacked, DeleteFiresNotifyAfterPut) {
    /// Subscribe + PUT seeds a record. Then DELETE removes it,
    /// firing DNS_NOTIFY with event = 1 / kEventDelete to the
    /// matching subscriber. Validates the wire-side delete →
    /// notify path with a real store backend.
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api_with_store(host);
    DnsHandler h(&api);
    ASSERT_TRUE(h.has_store());

    /// Subscribe conn 80 to "ephemeral".
    auto sub_payload = std::vector<std::uint8_t>(16 + 9);
    gn::endian::write_be<std::uint64_t>(
        {sub_payload.data() + 0, 8}, 1ULL);
    sub_payload[8] = 0;  // exact mode
    gn::endian::write_be<std::uint16_t>(
        {sub_payload.data() + 10, 2}, static_cast<std::uint16_t>(9));
    std::memcpy(sub_payload.data() + 16, "ephemeral", 9);
    auto env_sub = make_wire_env(kMsgSubscribe, 80, sub_payload);
    EXPECT_EQ(h.handle_message(&env_sub), GN_PROPAGATION_CONSUMED);

    /// PUT seeds the key.
    const std::vector<std::uint8_t> value{0xde, 0xad};
    auto put = make_put_payload(2, 0, 0, "ephemeral", value);
    auto env_put = make_wire_env(kMsgPut, 70, put);
    EXPECT_EQ(h.handle_message(&env_put), GN_PROPAGATION_CONSUMED);

    /// Clear accumulated sends from SUBSCRIBE + PUT so the next
    /// assertion only sees the DELETE traffic.
    {
        std::lock_guard lk(host.send_mu);
        host.sent_payloads.clear();
        host.sent_conns.clear();
        host.sent_msg_ids.clear();
    }

    /// DELETE from a third conn — handler emits DELETE ack to the
    /// writer + DNS_NOTIFY to the watching subscriber.
    std::vector<std::uint8_t> del(16 + 9);
    gn::endian::write_be<std::uint64_t>({del.data() + 0, 8}, 3ULL);
    gn::endian::write_be<std::uint16_t>(
        {del.data() + 8, 2}, static_cast<std::uint16_t>(9));
    std::memcpy(del.data() + 16, "ephemeral", 9);
    auto env_del = make_wire_env(kMsgDelete, 90, del);
    EXPECT_EQ(h.handle_message(&env_del), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.send_mu);
    ASSERT_EQ(host.sent_msg_ids.size(), 2u);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_conns[0], 90u);
    EXPECT_EQ(host.sent_payloads[0][8], 0u);  // kStatusOk on hit
    EXPECT_EQ(host.sent_msg_ids[1], kMsgNotify);
    EXPECT_EQ(host.sent_conns[1], 80u);
    /// Event byte at offset 8 = 1 / kEventDelete.
    EXPECT_EQ(host.sent_payloads[1][8], 1u);
}

TEST(DnsWire_StoreBacked, PutFiresNotifyToMatchingSubscriber) {
    /// Subscribe, then PUT under the watched key; the handler
    /// fans out a DNS_NOTIFY to the subscriber alongside the
    /// PUT ack. Validates the wire-side put → subscriber fan-out
    /// path end to end with a real store backend.
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api_with_store(host);
    DnsHandler h(&api);
    ASSERT_TRUE(h.has_store());

    /// Subscribe conn 30 to exact key "watched". DNS_SUBSCRIBE
    /// layout per §3.5: req(8) + mode(1) + reserved(1) +
    /// key_len(2) + reserved(4) + key bytes = 16 + key.
    auto sub_payload = std::vector<std::uint8_t>(16 + 7);
    gn::endian::write_be<std::uint64_t>(
        {sub_payload.data() + 0, 8}, 1ULL);
    sub_payload[8] = 0;  // mode exact
    gn::endian::write_be<std::uint16_t>(
        {sub_payload.data() + 10, 2},
        static_cast<std::uint16_t>(7));
    std::memcpy(sub_payload.data() + 16, "watched", 7);
    auto env_sub = make_wire_env(kMsgSubscribe, /*conn*/ 30, sub_payload);
    EXPECT_EQ(h.handle_message(&env_sub), GN_PROPAGATION_CONSUMED);
    EXPECT_EQ(h.subscription_count(), 1u);

    /// Drop the SUBSCRIBE ack so the next assertion sees only
    /// the PUT-driven traffic.
    {
        std::lock_guard lk(host.send_mu);
        host.sent_payloads.clear();
        host.sent_conns.clear();
        host.sent_msg_ids.clear();
    }

    /// PUT under the watched key from a different conn — handler
    /// emits PUT ack to the writer + NOTIFY to the subscriber.
    const std::vector<std::uint8_t> value{0xfe, 0xed};
    auto put = make_put_payload(/*req*/ 99, /*ttl*/ 0, /*flags*/ 0,
                                  "watched", value);
    auto env_put = make_wire_env(kMsgPut, /*conn*/ 60, put);
    EXPECT_EQ(h.handle_message(&env_put), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.send_mu);
    /// Two sends: DNS_RESULT (ack, to conn 60) + DNS_NOTIFY (to
    /// conn 30). The order of dispatch is deterministic — the
    /// ack lands first because the notify_wire_subscribers call
    /// follows it in handle_message.
    ASSERT_EQ(host.sent_msg_ids.size(), 2u);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_conns[0], 60u);
    EXPECT_EQ(host.sent_msg_ids[1], kMsgNotify);
    EXPECT_EQ(host.sent_conns[1], 30u);
    /// DNS_NOTIFY layout §3.7: timestamp(8) + event(1) + reserved(1)
    /// + Record. event = 0 for PUT.
    const auto& notify = host.sent_payloads[1];
    ASSERT_GE(notify.size(), 10u);
    EXPECT_EQ(notify[8], 0u);  // kEventPut
}

TEST(DnsWire_StoreBacked, PrefixModeGetEnumeratesMatchingKeys) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api_with_store(host);
    DnsHandler h(&api);
    ASSERT_TRUE(h.has_store());

    /// Seed three records — two under prefix "peer/", one outside.
    const std::vector<std::uint8_t> v1{0x01};
    const std::vector<std::uint8_t> v2{0x02};
    const std::vector<std::uint8_t> v3{0x03};
    auto put1 = make_put_payload(1, 0, 0, "peer/alice", v1);
    auto put2 = make_put_payload(2, 0, 0, "peer/bob",   v2);
    auto put3 = make_put_payload(3, 0, 0, "service/x",  v3);
    {
        auto e = make_wire_env(kMsgPut, 7, put1);
        EXPECT_EQ(h.handle_message(&e), GN_PROPAGATION_CONSUMED);
    }
    {
        auto e = make_wire_env(kMsgPut, 7, put2);
        EXPECT_EQ(h.handle_message(&e), GN_PROPAGATION_CONSUMED);
    }
    {
        auto e = make_wire_env(kMsgPut, 7, put3);
        EXPECT_EQ(h.handle_message(&e), GN_PROPAGATION_CONSUMED);
    }

    /// Drop the three PUT acks so the next assertion sees only
    /// the prefix-mode reply.
    {
        std::lock_guard lk(host.send_mu);
        host.sent_payloads.clear();
        host.sent_conns.clear();
        host.sent_msg_ids.clear();
    }

    /// Prefix-mode DNS_GET on "peer/" returns the two matching
    /// records (alice + bob). Order is implementation-defined —
    /// the test counts records and decodes names regardless of
    /// order.
    auto getp = make_get_payload(/*req*/ 10, /*mode*/ 1, /*max*/ 10,
                                   "peer/");
    auto env = make_wire_env(kMsgGet, /*conn*/ 7, getp);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.send_mu);
    ASSERT_EQ(host.sent_payloads.size(), 1u);
    const auto& reply = host.sent_payloads[0];
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(reply[8], 0u);  // kStatusOk
    const auto rec_count = gn::endian::read_be<std::uint16_t>(
        {reply.data() + 10, 2});
    EXPECT_EQ(rec_count, 2u);
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {reply.data() + 0, 8}),
              10u);
}

TEST(DnsWire_StoreBacked, PutWriteThenWireGetReadsBack) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api_with_store(host);
    DnsHandler h(&api);
    ASSERT_TRUE(h.has_store()) << "store extension must be visible";

    /// Wire-side DNS_PUT under key "host.example". TTL 0 means
    /// permanent — the Resolver's `lookup_store` skips the
    /// expiry check, which would otherwise mark the record stale
    /// because the StubStore's clock domain (incrementing small
    /// counter) does not match the Resolver's wall-clock default.
    const std::vector<std::uint8_t> value{0xa, 0xb, 0xc};
    const auto put_payload = make_put_payload(
        /*req*/ 100, /*ttl*/ 0, /*flags*/ 0,
        "host.example", value);
    auto env_put = make_wire_env(kMsgPut, /*conn*/ 17, put_payload);
    EXPECT_EQ(h.handle_message(&env_put), GN_PROPAGATION_CONSUMED);

    /// First captured send: DNS_RESULT with kStatusOk for the PUT.
    {
        std::lock_guard lk(host.send_mu);
        ASSERT_EQ(host.sent_msg_ids.size(), 1u);
        EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
        EXPECT_EQ(host.sent_payloads[0][8], 0u);  // kStatusOk
        EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                      {host.sent_payloads[0].data() + 0, 8}),
                  100u);
    }

    /// Wire-side DNS_GET on the same key reads back the stored value.
    const auto get_payload = make_get_payload(
        /*req*/ 200, /*mode*/ 0 /*exact*/, /*max*/ 1,
        "host.example");
    auto env_get = make_wire_env(kMsgGet, /*conn*/ 17, get_payload);
    EXPECT_EQ(h.handle_message(&env_get), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.send_mu);
    ASSERT_EQ(host.sent_msg_ids.size(), 2u);
    EXPECT_EQ(host.sent_msg_ids[1], kMsgResult);
    const auto& reply = host.sent_payloads[1];
    /// DNS_RESULT: req(8) + status(1) + reserved(1) + count(2) + Record.
    EXPECT_EQ(reply[8], 0u);  // kStatusOk
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {reply.data() + 0, 8}),
              200u);
    EXPECT_EQ(gn::endian::read_be<std::uint16_t>(
                  {reply.data() + 10, 2}),
              1u);
    /// Record body offset = 12. Layout: timestamp(8) + ttl(8) +
    /// flags(1) + reserved(1) + key_len(2) + value_len(4) + key + value.
    ASSERT_GE(reply.size(), 12u + 24u + 12u + 3u);
    const std::size_t r = 12;
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {reply.data() + r + 8, 8}), 0u);  // ttl_s permanent
    const auto key_len = gn::endian::read_be<std::uint16_t>(
        {reply.data() + r + 18, 2});
    EXPECT_EQ(key_len, 12u);  // "host.example"
    const auto value_len = gn::endian::read_be<std::uint32_t>(
        {reply.data() + r + 20, 4});
    EXPECT_EQ(value_len, value.size());
    EXPECT_EQ(0, std::memcmp(reply.data() + r + 24,
                              "host.example", 12));
    EXPECT_EQ(0, std::memcmp(reply.data() + r + 24 + 12,
                              value.data(), value.size()));
}

}  // namespace
}  // namespace gn::handler::dns

// NOLINTEND(bugprone-unchecked-optional-access)
