// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/tests/test_dns.cpp
/// @brief  Skeleton tests covering construction + the no-op
///         wire-dispatch path. Real wire-side semantics belong to
///         a future remote-envelope consumer; the store consumer,
///         resolver cascade, and typed RR codec have their own
///         dedicated test TUs.

#include <gtest/gtest.h>

#include <dns.hpp>

#include <sdk/cpp/endian.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <cstring>
#include <vector>

namespace gn::handler::dns {
namespace {

using StubHost = ::gn::sdk::test::HandlerStub;

inline host_api_t make_stub_api(StubHost& h) noexcept {
    return ::gn::sdk::test::make_handler_host_api(h);
}

TEST(DnsHandler_Skeleton, ConstructsAndDestructs) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);
    /// The plugin compiles, registers, and tears down cleanly.
    /// Store-proxy, resolver-cascade, and RR-codec semantics are
    /// validated by the dedicated test TUs in this directory.
    SUCCEED();
}

TEST(DnsHandler_Skeleton, NullPayloadReturnsContinue) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    /// A handler invoked with a null payload (defensive call site,
    /// torn-down conn race) must not crash and must return CONTINUE
    /// so any downstream handler in the chain gets a chance.
    gn_message_t env{};
    env.msg_id = kMsgPut;
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONTINUE);
}

TEST(DnsHandler_Skeleton, UnknownMsgIdReturnsContinue) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    /// Envelopes for msg_ids the handler does not (yet) implement
    /// flow through unchanged. Pending wire-dispatch commits for
    /// GET / DELETE / SUBSCRIBE / NOTIFY / SYNC land in follow-ups.
    const std::uint8_t junk = 0;
    gn_message_t env{};
    env.msg_id       = 0x9999;
    env.payload      = &junk;
    env.payload_size = 1;
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONTINUE);
}

// ── DNS_PUT wire dispatch ────────────────────────────────────────────────

std::vector<std::uint8_t> make_put_payload(std::uint64_t request_id,
                                             std::uint64_t ttl_s,
                                             std::uint8_t flags,
                                             std::string_view key,
                                             std::span<const std::uint8_t> value) {
    std::vector<std::uint8_t> out(24 + key.size() + value.size());
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    gn::endian::write_be<std::uint64_t>({out.data() + 8, 8}, ttl_s);
    out[16] = flags;
    // out[17] reserved
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 18, 2}, static_cast<std::uint16_t>(key.size()));
    gn::endian::write_be<std::uint32_t>(
        {out.data() + 20, 4}, static_cast<std::uint32_t>(value.size()));
    std::memcpy(out.data() + 24, key.data(), key.size());
    std::memcpy(out.data() + 24 + key.size(),
                 value.data(), value.size());
    return out;
}

gn_message_t make_env(std::uint32_t msg_id, gn_conn_id_t conn,
                       std::span<const std::uint8_t> payload) {
    gn_message_t e{};
    e.msg_id       = msg_id;
    e.conn_id      = conn;
    e.payload      = payload.data();
    e.payload_size = payload.size();
    return e;
}

TEST(DnsWire, PutEnvelopeWithoutStoreAcksBackendError) {
    /// No store extension is registered on this StubHost, so
    /// `Resolver::put_record` returns false. The handler still
    /// frames a DNS_RESULT — the caller's request_id correlation
    /// completes; the status byte tells them the backend is
    /// unavailable. The wire-format shape (request_id echo,
    /// status at offset 8, DNS_RESULT msg_id) is the same
    /// assertion shape `PutEnvelopeAcksWithOk` will use once a
    /// store stub feeds `Resolver` through the extension
    /// registry — landing alongside the store-backed wire tests.
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const std::vector<std::uint8_t> value{0x10, 0x20, 0x30};
    const auto payload = make_put_payload(
        /*req*/ 42, /*ttl*/ 0, /*flags*/ 0,
        "host.example", value);
    auto env = make_env(kMsgPut, /*conn*/ 7, payload);

    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_conns[0], 7u);
    ASSERT_GE(host.sent_payloads[0].size(), 12u);
    /// DNS_RESULT: req(8) + status(1) + reserved(1) + count(2).
    /// Status at offset 8 is kStatusBackendError (3) because no
    /// store is wired.
    EXPECT_EQ(host.sent_payloads[0][8], 3u);
    /// request_id echoed at offset 0 regardless of status.
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {host.sent_payloads[0].data() + 0, 8}),
              42u);
}

std::vector<std::uint8_t> make_get_payload(std::uint64_t request_id,
                                              std::uint8_t mode,
                                              std::uint16_t max_results,
                                              std::uint64_t since_us,
                                              std::string_view key) {
    std::vector<std::uint8_t> out(28 + key.size());
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    out[8] = mode;
    // out[9] reserved
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 10, 2}, max_results);
    // out[12..16] reserved
    gn::endian::write_be<std::uint64_t>(
        {out.data() + 16, 8}, since_us);
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 24, 2}, static_cast<std::uint16_t>(key.size()));
    // out[26..28] reserved
    std::memcpy(out.data() + 28, key.data(), key.size());
    return out;
}

std::vector<std::uint8_t> make_delete_payload(std::uint64_t request_id,
                                                 std::string_view key) {
    std::vector<std::uint8_t> out(16 + key.size());
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 8, 2}, static_cast<std::uint16_t>(key.size()));
    // out[10..16] reserved
    std::memcpy(out.data() + 16, key.data(), key.size());
    return out;
}

std::vector<std::uint8_t> make_subscribe_payload(std::uint64_t request_id,
                                                    std::uint8_t mode,
                                                    std::string_view key) {
    std::vector<std::uint8_t> out(16 + key.size());
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    out[8] = mode;
    // out[9] reserved
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 10, 2}, static_cast<std::uint16_t>(key.size()));
    // out[12..16] reserved
    std::memcpy(out.data() + 16, key.data(), key.size());
    return out;
}

TEST(DnsWire, SubscribeAcksAndRecordsSubscriber) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);
    EXPECT_EQ(h.subscription_count(), 0u);

    const auto sub = make_subscribe_payload(
        /*req*/ 7, /*mode*/ 0 /*exact*/, "k");
    auto env = make_env(kMsgSubscribe, /*conn*/ 11, sub);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    EXPECT_EQ(h.subscription_count(), 1u);
    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_payloads[0][8], 0u);  // kStatusOk
}

std::vector<std::uint8_t> make_sync_request(std::uint64_t request_id,
                                               std::uint64_t since_us,
                                               std::uint16_t max_results) {
    std::vector<std::uint8_t> out(20);
    gn::endian::write_be<std::uint64_t>({out.data() + 0, 8}, request_id);
    gn::endian::write_be<std::uint64_t>({out.data() + 8, 8}, since_us);
    gn::endian::write_be<std::uint16_t>(
        {out.data() + 16, 2}, max_results);
    /// record_count == 0 on a request.
    gn::endian::write_be<std::uint16_t>({out.data() + 18, 2}, 0);
    return out;
}

TEST(DnsWire, SyncRequestRepliesWithEmptyWindow) {
    /// Without a store extension the handler still answers SYNC
    /// with a well-formed reply carrying zero records. The
    /// envelope echoes request_id / since_us / max_results so
    /// the caller's correlation completes.
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const auto req = make_sync_request(/*req*/ 5, /*since*/ 1000,
                                          /*max*/ 32);
    auto env = make_env(kMsgSync, /*conn*/ 9, req);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgSync);
    const auto& reply = host.sent_payloads[0];
    ASSERT_GE(reply.size(), 20u);
    /// Echoed fields.
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {reply.data() + 0, 8}), 5u);
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {reply.data() + 8, 8}), 1000u);
    EXPECT_EQ(gn::endian::read_be<std::uint16_t>(
                  {reply.data() + 16, 2}), 32u);
    /// Zero records.
    EXPECT_EQ(gn::endian::read_be<std::uint16_t>(
                  {reply.data() + 18, 2}), 0u);
}

TEST(DnsWire, SyncRequestRejectsNonZeroRecordCount) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    auto req = make_sync_request(/*req*/ 1, 0, 0);
    /// Set record_count to 1 — invalid on a request.
    gn::endian::write_be<std::uint16_t>({req.data() + 18, 2}, 1);
    auto env = make_env(kMsgSync, /*conn*/ 9, req);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    /// The handler returns DNS_RESULT with kStatusBadSize on
    /// the malformed request — not DNS_SYNC.
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_payloads[0][8], 1u);  // kStatusBadSize
}

TEST(DnsWire, DeleteFiresNotifyToMatchingSubscribers) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    /// Subscribe conn 50 to exact key "watched".
    const auto sub = make_subscribe_payload(/*req*/ 1, /*mode*/ 0, "watched");
    auto env_sub = make_env(kMsgSubscribe, /*conn*/ 50, sub);
    EXPECT_EQ(h.handle_message(&env_sub), GN_PROPAGATION_CONSUMED);

    /// Delete the watched key. The handler's delete path always
    /// emits a DNS_NOTIFY to matching subscribers even when the
    /// underlying resolver had no record — the notification is
    /// about the EVENT (a peer issued a delete), not about the
    /// data state. In this fixture without a store backend the
    /// delete returns not-found, so no notify fires.
    const auto del = make_delete_payload(/*req*/ 2, "watched");
    auto env_del = make_env(kMsgDelete, /*conn*/ 60, del);
    EXPECT_EQ(h.handle_message(&env_del), GN_PROPAGATION_CONSUMED);

    /// Without a store, delete reports not-found; only the ack
    /// is sent. With a store, the notify would fire too.
    std::lock_guard lk(host.mu);
    /// One ack for SUBSCRIBE + one ack for DELETE = 2 sends.
    /// No NOTIFY because the resolver has no store-backed entry.
    EXPECT_EQ(host.send_calls.load(), 2);
}

TEST(DnsWire, SubscribeRejectsSinceMode) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    /// Mode 2 (since) is invalid for SUBSCRIBE per §3.5.
    const auto sub = make_subscribe_payload(/*req*/ 1, /*mode*/ 2, "k");
    auto env = make_env(kMsgSubscribe, /*conn*/ 11, sub);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);
    EXPECT_EQ(h.subscription_count(), 0u);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_payloads[0][8], 1u);  // kStatusBadSize
}

TEST(DnsWire, DeleteEnvelopeBadSizeAcks) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const std::vector<std::uint8_t> truncated{0x00};
    auto env = make_env(kMsgDelete, /*conn*/ 9, truncated);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_payloads[0][8], 1u);  // kStatusBadSize
}

TEST(DnsWire, DeleteEnvelopeNotFoundWhenEmpty) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const auto payload = make_delete_payload(/*req*/ 5, "missing");
    auto env = make_env(kMsgDelete, /*conn*/ 9, payload);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_payloads[0][8], 2u);  // kStatusNotFound
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {host.sent_payloads[0].data() + 0, 8}),
              5u);
}

TEST(DnsWire, GetEnvelopeBadSizeAcks) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const std::vector<std::uint8_t> truncated{0x00, 0x00};
    auto env = make_env(kMsgGet, /*conn*/ 9, truncated);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_payloads[0][8], 1u);  // kStatusBadSize
}

TEST(DnsWire, GetEnvelopePrefixModeWithoutStoreEmpty) {
    /// Prefix mode is now wired but needs a store extension to
    /// have anything to return. Without a store the handler
    /// replies with DNS_RESULT carrying kStatusNotFound and zero
    /// records — the caller's correlation completes regardless.
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const auto payload = make_get_payload(
        /*req*/ 11, /*mode*/ 1 /*prefix*/, /*max*/ 5,
        /*since*/ 0, "p/");
    auto env = make_env(kMsgGet, /*conn*/ 9, payload);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_payloads[0][8], 2u);  // kStatusNotFound
    EXPECT_EQ(gn::endian::read_be<std::uint64_t>(
                  {host.sent_payloads[0].data() + 0, 8}),
              11u);
    /// Zero records on the empty-store path.
    EXPECT_EQ(gn::endian::read_be<std::uint16_t>(
                  {host.sent_payloads[0].data() + 10, 2}),
              0u);
}

TEST(DnsWire, GetEnvelopeSinceModeWithoutStoreEmpty) {
    /// Since mode mirrors prefix: wired but requires a store to
    /// produce records. Without one, replies with NotFound + zero
    /// records.
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const auto payload = make_get_payload(
        /*req*/ 22, /*mode*/ 2 /*since*/, /*max*/ 10,
        /*since*/ 1000, "");
    auto env = make_env(kMsgGet, /*conn*/ 9, payload);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_payloads[0][8], 2u);  // kStatusNotFound
}

TEST(DnsWire, GetEnvelopeNotFoundWithEmptyResolver) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    const auto payload = make_get_payload(
        /*req*/ 99, /*mode*/ 0 /*exact*/, /*max*/ 1,
        /*since*/ 0, "absent");
    auto env = make_env(kMsgGet, /*conn*/ 9, payload);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    EXPECT_EQ(host.sent_payloads[0][8], 2u);  // kStatusNotFound
    /// record_count at offset 10..12 must be zero on not-found.
    EXPECT_EQ(gn::endian::read_be<std::uint16_t>(
                  {host.sent_payloads[0].data() + 10, 2}),
              0u);
}

TEST(DnsWire, PutEnvelopeBadSizeAcksWithBadSize) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    /// A payload smaller than the 24-byte header returns
    /// kStatusBadSize. The handler still sends a DNS_RESULT so the
    /// caller's request_id correlation does not hang.
    const std::vector<std::uint8_t> truncated{0x01, 0x02};
    auto env = make_env(kMsgPut, /*conn*/ 7, truncated);
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONSUMED);

    std::lock_guard lk(host.mu);
    ASSERT_EQ(host.send_calls.load(), 1);
    EXPECT_EQ(host.sent_msg_ids[0], kMsgResult);
    /// Status at offset 8 is kStatusBadSize (1).
    EXPECT_EQ(host.sent_payloads[0][8], 1u);
}

}  // namespace
}  // namespace gn::handler::dns
