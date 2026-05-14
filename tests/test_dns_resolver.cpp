// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/tests/test_dns_resolver.cpp
/// @brief  Resolver cascade — store hit / miss / TTL-expiry / cache-
///         back / no-upstream paths via a scripted MockUpstreamResolver.
///         AresUpstreamResolver is not exercised here (it talks to
///         real DNS infrastructure); end-to-end CI integration
///         coverage runs through `link-ice` once that consumer
///         drives the cascade in production.

#include <gtest/gtest.h>

#include <dns_records.hpp>
#include <dns_resolver.hpp>
#include <store_client.hpp>

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// NOLINTBEGIN(bugprone-unchecked-optional-access)

namespace gn::handler::dns {
namespace {

// ── shared scripted stub (same shape as test_dns_store_client) ─────────────

struct StubStore {
    struct Row {
        std::vector<std::uint8_t> value;
        std::uint64_t             timestamp_us = 0;
        std::uint64_t             ttl_s        = 0;
        std::uint8_t              flags        = 0;
    };

    std::mutex                              mu;
    std::unordered_map<std::string, Row>    rows;
    /// Stub uses the same monotonic wall clock the Resolver reads
    /// so TTL math agrees across both sides. A test that wants
    /// deterministic time injects its own clock through
    /// MockClock + the Resolver ctor's third arg; the stub's
    /// stamps stay on the real timeline regardless.
    std::uint64_t (*clock_us)() noexcept = &default_clock_us;

    gn_store_api_t make_vtable() {
        gn_store_api_t vt{};
        vt.api_size        = sizeof(gn_store_api_t);
        vt.put             = &StubStore::on_put;
        vt.get             = &StubStore::on_get;
        vt.query           = &StubStore::on_query;
        vt.del             = &StubStore::on_del;
        vt.cleanup_expired = nullptr;
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
        r.timestamp_us = s->clock_us();
        r.ttl_s        = ttl_s;
        r.flags        = flags;
        s->rows.insert_or_assign(std::string(key, klen), std::move(r));
        return 0;
    }
    static int on_get(void* ctx, const char* key, size_t klen,
                       gn_store_entry_t* out) {
        auto* s = static_cast<StubStore*>(ctx);
        std::lock_guard lk(s->mu);
        auto it = s->rows.find(std::string(key, klen));
        if (it == s->rows.end()) return -1;
        out->key          = it->first.data();
        out->key_len      = it->first.size();
        out->value        = it->second.value.data();
        out->value_len    = it->second.value.size();
        out->timestamp_us = it->second.timestamp_us;
        out->ttl_s        = it->second.ttl_s;
        out->flags        = it->second.flags;
        return 0;
    }
    static int on_query(void*, gn_store_query_t, const char*, size_t,
                         std::uint64_t, std::uint32_t,
                         void (*)(void*, const gn_store_entry_t*), void*) {
        return 0;  // resolver uses get/put/del only
    }
    static int on_del(void* ctx, const char* key, size_t klen) {
        auto* s = static_cast<StubStore*>(ctx);
        std::lock_guard lk(s->mu);
        return s->rows.erase(std::string(key, klen)) > 0 ? 0 : -1;
    }
};

struct ExtensionHost {
    std::unordered_map<std::string,
                       std::pair<std::uint32_t, const void*>> extensions;
    static gn_result_t on_query(void* host_ctx, const char* name,
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

host_api_t make_api(ExtensionHost& host) {
    host_api_t api{};
    api.host_ctx                = &host;
    api.query_extension_checked = &ExtensionHost::on_query;
    return api;
}

// ── scripted upstream ──────────────────────────────────────────────────────

class MockUpstreamResolver final : public IUpstreamResolver {
public:
    struct Key {
        std::string name;
        RrType      type;
        bool operator==(const Key& o) const {
            return name == o.name && type == o.type;
        }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return std::hash<std::string>{}(k.name)
                 ^ (std::hash<std::uint16_t>{}(rrtype_value(k.type)) << 1);
        }
    };

    /// Script an answer set for `(name, type)`. Empty vector
    /// programs an explicit "no records" response, distinct from
    /// "not scripted" (which returns empty + bumps the unanswered
    /// counter).
    void script(std::string_view name, RrType type,
                std::vector<ResolvedRecord> records) {
        scripted_[{std::string(name), type}] = std::move(records);
    }

    int call_count() const { return calls_; }
    int unanswered_count() const { return unanswered_; }

    std::vector<ResolvedRecord>
    resolve(std::string_view name, RrType type) override {
        ++calls_;
        auto it = scripted_.find({std::string(name), type});
        if (it == scripted_.end()) {
            ++unanswered_;
            return {};
        }
        return it->second;
    }

private:
    std::unordered_map<Key, std::vector<ResolvedRecord>, KeyHash> scripted_;
    int calls_      = 0;
    int unanswered_ = 0;
};

// ── helpers ────────────────────────────────────────────────────────────────

std::vector<std::uint8_t> a_rdata(std::array<std::uint8_t, 4> octets) {
    ARecord r{octets};
    return encode_a(r);
}

ResolvedRecord make_a_record(std::string name,
                              std::array<std::uint8_t, 4> octets,
                              std::uint32_t ttl_s) {
    ResolvedRecord r;
    r.type  = RrType::A;
    r.name  = std::move(name);
    r.rdata = a_rdata(octets);
    r.ttl_s = ttl_s;
    return r;
}

// ── tests ──────────────────────────────────────────────────────────────────

TEST(Resolver_StoreTier, ReturnsCachedWithoutUpstream) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    MockUpstreamResolver upstream;
    Resolver r(&store.value(), &upstream);

    /// Pre-populate the store.
    ASSERT_TRUE(r.put_record("peer.local", RrType::A,
        a_rdata({10, 0, 0, 7}), 60 /*ttl_s*/, 0));

    auto records = r.resolve("peer.local", RrType::A);
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].type, RrType::A);
    EXPECT_EQ(records[0].rdata.size(), 4u);
    EXPECT_EQ(upstream.call_count(), 0)
        << "store hit should not reach upstream";
}

TEST(Resolver_StoreTier, MissFallsToUpstreamWhenAvailable) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    MockUpstreamResolver upstream;
    upstream.script("upstream.example.com", RrType::A,
        {make_a_record("upstream.example.com", {93, 184, 216, 34}, 300)});

    Resolver r(&store.value(), &upstream);
    auto records = r.resolve("upstream.example.com", RrType::A);
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(upstream.call_count(), 1);
}

TEST(Resolver_CacheBack, UpstreamAnswerIsStored) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    MockUpstreamResolver upstream;
    upstream.script("svc.example.com", RrType::A,
        {make_a_record("svc.example.com", {1, 2, 3, 4}, 60)});

    Resolver r(&store.value(), &upstream);

    /// First call hits upstream, caches.
    auto first = r.resolve("svc.example.com", RrType::A);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_EQ(upstream.call_count(), 1);

    /// Second call returns from the store; upstream call_count
    /// stays at 1.
    auto second = r.resolve("svc.example.com", RrType::A);
    ASSERT_EQ(second.size(), 1u);
    EXPECT_EQ(upstream.call_count(), 1)
        << "cache-back path should suppress the second upstream call";
}

/// Synthetic monotonic clock so the TTL-expiry test is
/// deterministic regardless of the host's system_clock.
struct MockClock {
    static std::atomic<std::uint64_t> now;
    static std::uint64_t value() noexcept {
        return now.load(std::memory_order_relaxed);
    }
};
std::atomic<std::uint64_t> MockClock::now{1'000'000};

TEST(Resolver_TTL, ExpiredCacheTriggersUpstreamRefresh) {
    ExtensionHost host;
    StubStore stub;
    /// Point both the store stamps and the Resolver's "now" reader
    /// at the same mock clock so TTL math is fully deterministic.
    stub.clock_us = &MockClock::value;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    MockUpstreamResolver upstream;
    upstream.script("ephemeral.example.com", RrType::A,
        {make_a_record("ephemeral.example.com", {9, 9, 9, 9}, 30)});

    MockClock::now.store(1'000'000);
    Resolver r(&store.value(), &upstream, &MockClock::value);

    /// Plant a record with TTL=10s under the mock clock.
    ASSERT_TRUE(r.put_record("ephemeral.example.com", RrType::A,
        a_rdata({8, 8, 8, 8}), 10, 0));

    /// First call inside the TTL window — store hit, no upstream.
    MockClock::now.store(1'000'000 + 5'000'000);  // +5 s
    auto fresh = r.resolve("ephemeral.example.com", RrType::A);
    ASSERT_EQ(fresh.size(), 1u);
    EXPECT_EQ(upstream.call_count(), 0);

    /// Advance past TTL — store entry expired, upstream gets hit.
    MockClock::now.store(1'000'000 + 60'000'000);  // +60 s
    auto refreshed = r.resolve("ephemeral.example.com", RrType::A);
    ASSERT_EQ(refreshed.size(), 1u);
    EXPECT_EQ(upstream.call_count(), 1);
}

TEST(Resolver_NoUpstream, MissReturnsEmpty) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    Resolver r(&store.value(), /*upstream=*/nullptr);
    auto records = r.resolve("unknown.example.com", RrType::A);
    EXPECT_TRUE(records.empty());
    EXPECT_FALSE(r.has_upstream());
    EXPECT_TRUE(r.has_store());
}

TEST(Resolver_NoStore, DegradesToUpstreamOnly) {
    MockUpstreamResolver upstream;
    upstream.script("u.example.com", RrType::A,
        {make_a_record("u.example.com", {1, 1, 1, 1}, 60)});

    Resolver r(/*store=*/nullptr, &upstream);
    auto records = r.resolve("u.example.com", RrType::A);
    ASSERT_EQ(records.size(), 1u);
    EXPECT_FALSE(r.has_store());

    /// Without a store there's no cache-back; a second call
    /// re-hits upstream.
    (void)r.resolve("u.example.com", RrType::A);
    EXPECT_EQ(upstream.call_count(), 2);
}

TEST(Resolver_PermanentRecord, IgnoresTtlExpiry) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    MockUpstreamResolver upstream;
    Resolver r(&store.value(), &upstream);

    /// ttl_s == 0 marks the record permanent (operator-curated
    /// cluster records). Even if we advance the wall clock the
    /// record stays valid.
    ASSERT_TRUE(r.put_record("static.cluster.local", RrType::A,
        a_rdata({10, 0, 0, 1}), /*ttl_s*/ 0, 0));

    auto records = r.resolve("static.cluster.local", RrType::A);
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(upstream.call_count(), 0);
}

TEST(Resolver_Delete, RemovesCached) {
    ExtensionHost host;
    StubStore stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_STORE] = {GN_EXT_STORE_VERSION, &vt};

    auto api = make_api(host);
    auto store = StoreClient::query(&api);
    ASSERT_TRUE(store.has_value());

    MockUpstreamResolver upstream;
    Resolver r(&store.value(), &upstream);

    ASSERT_TRUE(r.put_record("doomed.local", RrType::A,
        a_rdata({1, 2, 3, 4}), 60, 0));
    EXPECT_TRUE(r.delete_record("doomed.local", RrType::A));
    /// Second delete misses.
    EXPECT_FALSE(r.delete_record("doomed.local", RrType::A));

    /// Subsequent resolve falls through to upstream (which has
    /// nothing scripted, so we get an empty answer + bumped
    /// unanswered counter).
    (void)r.resolve("doomed.local", RrType::A);
    EXPECT_EQ(upstream.call_count(), 1);
    EXPECT_EQ(upstream.unanswered_count(), 1);
}

}  // namespace
}  // namespace gn::handler::dns

// NOLINTEND(bugprone-unchecked-optional-access)
