// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/tests/test_dns.cpp
/// @brief  Skeleton tests after D-DNS.1 cleanup. Real semantics
///         (store consumer, resolver cascade, server-side) land in
///         D-DNS.2 through D-DNS.6 with their own test TUs.

#include <gtest/gtest.h>

#include <dns.hpp>

#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

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
    /// Wire-level semantics are validated by per-slice tests
    /// landing in D-DNS.2 onward.
    SUCCEED();
}

TEST(DnsHandler_Skeleton, HandleMessageReturnsContinueForNow) {
    StubHost host;
    auto api = make_stub_api(host);
    DnsHandler h(&api);

    /// D-DNS.1 stub returns CONTINUE for every envelope so the
    /// dispatch chain isn't accidentally consumed before the real
    /// handler code lands.
    gn_message_t env{};
    env.msg_id = kMsgResolve;
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONTINUE);

    env.msg_id = kMsgPutRecord;
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONTINUE);

    env.msg_id = 0x9999;  // unknown
    EXPECT_EQ(h.handle_message(&env), GN_PROPAGATION_CONTINUE);
}

}  // namespace
}  // namespace gn::handler::dns
