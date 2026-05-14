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

#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/store.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

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
struct ExtensionHost {
    std::unordered_map<std::string,
                       std::pair<std::uint32_t, const void*>> extensions;

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
};

host_api_t make_api_with_store(ExtensionHost& host) {
    host_api_t api{};
    api.host_ctx                = &host;
    api.query_extension_checked = &ExtensionHost::on_query;
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

}  // namespace
}  // namespace gn::handler::dns

// NOLINTEND(bugprone-unchecked-optional-access)
