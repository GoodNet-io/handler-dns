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
