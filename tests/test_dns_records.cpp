// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/tests/test_dns_records.cpp
/// @brief  Round-trip + edge-case coverage for typed DNS RR codecs.
///         Pins the wire bytes per type so the resolver cascade
///         and any future server-side layer build on a stable
///         serialisation contract.

#include <gtest/gtest.h>

#include <dns_records.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// NOLINTBEGIN(bugprone-unchecked-optional-access)

namespace gn::handler::dns {
namespace {

// ── name codec ─────────────────────────────────────────────────────────────

TEST(DnsName_Encode, EmptyEncodesToRootTerminator) {
    auto out = encode_name("");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out.value(), (std::vector<std::uint8_t>{0}));
}

TEST(DnsName_Encode, DotEncodesToRootTerminator) {
    auto out = encode_name(".");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out.value(), (std::vector<std::uint8_t>{0}));
}

TEST(DnsName_Encode, SingleLabelRoundtrips) {
    auto out = encode_name("example");
    ASSERT_TRUE(out.has_value());
    /// Wire layout: length(7), 'e','x','a','m','p','l','e', 0
    EXPECT_EQ(out.value(),
              (std::vector<std::uint8_t>{
                  7, 'e','x','a','m','p','l','e', 0}));
}

TEST(DnsName_Encode, MultiLabelRoundtrips) {
    auto out = encode_name("example.com");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out.value(),
              (std::vector<std::uint8_t>{
                  7, 'e','x','a','m','p','l','e',
                  3, 'c','o','m', 0}));
}

TEST(DnsName_Encode, AcceptsTrailingDotForFqdn) {
    auto out = encode_name("peer.cluster.local.");
    ASSERT_TRUE(out.has_value());
    auto roundtrip = decode_name(out.value());
    ASSERT_TRUE(roundtrip.has_value());
    /// The trailing dot is canonical FQDN syntax; the decoder
    /// drops it so round-trip yields the input minus the dot.
    EXPECT_EQ(roundtrip.value(), "peer.cluster.local");
}

TEST(DnsName_Encode, RejectsLabelOver63Bytes) {
    std::string huge(kMaxLabelLen + 1, 'a');
    EXPECT_FALSE(encode_name(huge).has_value());
}

TEST(DnsName_Encode, RejectsEmptyMiddleLabel) {
    /// "foo..bar" — zero-length label in the middle is malformed
    /// per RFC 1035 §3.1 (only the root terminator is zero).
    EXPECT_FALSE(encode_name("foo..bar").has_value());
}

TEST(DnsName_Decode, RejectsTruncatedInput) {
    /// Length byte says 5, but only 3 bytes follow before the buffer ends.
    std::vector<std::uint8_t> truncated{5, 'a', 'b', 'c'};
    EXPECT_FALSE(decode_name(truncated).has_value());
}

TEST(DnsName_Decode, RejectsMissingTerminator) {
    /// Label present, no following length-byte / terminator.
    std::vector<std::uint8_t> no_term{3, 'a', 'b', 'c'};
    EXPECT_FALSE(decode_name(no_term).has_value());
}

TEST(DnsName_Decode, RejectsCompressionPointer) {
    /// Top 2 bits set on a length byte — RFC 1035 §4.1.4
    /// compression pointer, illegal in stored rdata.
    std::vector<std::uint8_t> ptr{0xC0, 0x0C, 0};
    EXPECT_FALSE(decode_name(ptr).has_value());
}

TEST(DnsName_Decode, EmptyInputIsMalformed) {
    /// No bytes at all — no terminator either.
    EXPECT_FALSE(decode_name({}).has_value());
}

TEST(DnsName_Decode, JustTerminatorYieldsEmpty) {
    std::vector<std::uint8_t> root{0};
    auto out = decode_name(root);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out.value(), "");
}

// ── A / AAAA ───────────────────────────────────────────────────────────────

TEST(DnsA_Roundtrip, EncodeParse) {
    ARecord r{ {93, 184, 216, 34} };  // example.com circa 2024
    auto wire = encode_a(r);
    EXPECT_EQ(wire.size(), 4u);
    auto back = parse_a(wire);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value().octets, r.octets);
}

TEST(DnsA_Parse, RejectsWrongLength) {
    EXPECT_FALSE(parse_a(std::vector<std::uint8_t>{1, 2, 3}).has_value());
    EXPECT_FALSE(parse_a(std::vector<std::uint8_t>{1, 2, 3, 4, 5}).has_value());
}

TEST(DnsAAAA_Roundtrip, EncodeParse) {
    AAAARecord r{};
    for (std::uint8_t i = 0; i < 16; ++i) r.octets[i] = i;
    auto wire = encode_aaaa(r);
    EXPECT_EQ(wire.size(), 16u);
    auto back = parse_aaaa(wire);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value().octets, r.octets);
}

TEST(DnsAAAA_Parse, RejectsWrongLength) {
    EXPECT_FALSE(parse_aaaa(std::vector<std::uint8_t>(15, 0)).has_value());
    EXPECT_FALSE(parse_aaaa(std::vector<std::uint8_t>(17, 0)).has_value());
}

// ── SRV ────────────────────────────────────────────────────────────────────

TEST(DnsSrv_Roundtrip, EncodeParse) {
    SrvRecord r{};
    r.priority = 10;
    r.weight   = 60;
    r.port     = 3478;
    r.target   = "stun.example.com";
    auto wire = encode_srv(r);
    ASSERT_TRUE(wire.has_value());

    auto back = parse_srv(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value().priority, 10);
    EXPECT_EQ(back.value().weight,   60);
    EXPECT_EQ(back.value().port,     3478);
    EXPECT_EQ(back.value().target,   "stun.example.com");
}

TEST(DnsSrv_Roundtrip, RootTargetSurvives) {
    /// SRV with an explicit "no target" — RFC 2782 §1 says use
    /// root label `.` to indicate no service available.
    SrvRecord r{};
    r.priority = 0; r.weight = 0; r.port = 0;
    r.target = "";
    auto wire = encode_srv(r);
    ASSERT_TRUE(wire.has_value());
    EXPECT_EQ(wire.value().size(), 7u);  // 6-byte hdr + root

    auto back = parse_srv(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value().target, "");
}

TEST(DnsSrv_Parse, RejectsTruncated) {
    /// 6 bytes header alone — no name follows.
    std::vector<std::uint8_t> tiny(6, 0);
    EXPECT_FALSE(parse_srv(tiny).has_value());
}

// ── MX ─────────────────────────────────────────────────────────────────────

TEST(DnsMx_Roundtrip, EncodeParse) {
    MxRecord r{};
    r.preference = 20;
    r.exchange   = "mail.example.com";
    auto wire = encode_mx(r);
    ASSERT_TRUE(wire.has_value());

    auto back = parse_mx(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value().preference, 20);
    EXPECT_EQ(back.value().exchange,   "mail.example.com");
}

// ── CNAME / PTR / NS ───────────────────────────────────────────────────────

TEST(DnsCname_Roundtrip, EncodeParse) {
    auto wire = encode_cname("alias.example.com");
    ASSERT_TRUE(wire.has_value());
    auto back = parse_cname(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value(), "alias.example.com");
}

TEST(DnsPtr_Roundtrip, EncodeParse) {
    auto wire = encode_ptr("host.local");
    ASSERT_TRUE(wire.has_value());
    auto back = parse_ptr(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value(), "host.local");
}

TEST(DnsNs_Roundtrip, EncodeParse) {
    auto wire = encode_ns("ns1.example.com");
    ASSERT_TRUE(wire.has_value());
    auto back = parse_ns(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value(), "ns1.example.com");
}

// ── TXT ────────────────────────────────────────────────────────────────────

TEST(DnsTxt_Roundtrip, SingleSegment) {
    std::vector<std::string> segs{"v=goodnet1; peer-id=abc123"};
    auto wire = encode_txt(segs);
    ASSERT_TRUE(wire.has_value());

    auto back = parse_txt(wire.value());
    ASSERT_TRUE(back.has_value());
    ASSERT_EQ(back.value().size(), 1u);
    EXPECT_EQ(back.value()[0], "v=goodnet1; peer-id=abc123");
}

TEST(DnsTxt_Roundtrip, MultipleSegmentsPreserved) {
    std::vector<std::string> segs{"first", "second", "third"};
    auto wire = encode_txt(segs);
    ASSERT_TRUE(wire.has_value());

    auto back = parse_txt(wire.value());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value(), segs);
}

TEST(DnsTxt_Encode, RejectsOversizedSegment) {
    std::string huge(kMaxTxtSegmentLen + 1, 'x');
    EXPECT_FALSE(encode_txt(std::array{huge}).has_value());
}

TEST(DnsTxt_Encode, RejectsEmptyVector) {
    EXPECT_FALSE(encode_txt(std::span<const std::string>{}).has_value());
}

TEST(DnsTxt_Parse, RejectsTruncatedSegment) {
    /// Length byte 5, but only 3 bytes follow.
    std::vector<std::uint8_t> tw{5, 'a', 'b', 'c'};
    EXPECT_FALSE(parse_txt(tw).has_value());
}

// ── store-key codec ────────────────────────────────────────────────────────

TEST(DnsStoreKey_Roundtrip, EncodesDecodes) {
    const auto key = make_store_key(RrType::SRV, "_stun._udp.example.com");
    /// Two-byte BE type prefix + slash + name.
    /// SRV = 33 → high byte 0x00, low byte 0x21.
    ASSERT_GE(key.size(), 3u);
    EXPECT_EQ(static_cast<std::uint8_t>(key[0]), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(key[1]), 33u);
    EXPECT_EQ(key[2], '/');

    auto back = parse_store_key(key);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back.value().first,  RrType::SRV);
    EXPECT_EQ(back.value().second, "_stun._udp.example.com");
}

TEST(DnsStoreKey_Parse, RejectsTruncatedPrefix) {
    EXPECT_FALSE(parse_store_key("").has_value());
    EXPECT_FALSE(parse_store_key(std::string("\x00", 1)).has_value());
    EXPECT_FALSE(parse_store_key(std::string("\x00\x01", 2)).has_value());
}

TEST(DnsStoreKey_Parse, RejectsMissingSlash) {
    /// First two bytes look like a valid type (1 = A), but the
    /// third character isn't `/`.
    std::string bad{'\x00', '\x01', 'x'};
    EXPECT_FALSE(parse_store_key(bad).has_value());
}

TEST(DnsStoreKey_Parse, RejectsUnknownType) {
    /// 0xFF / 0xFF — unallocated. Defensive against a peer that
    /// publishes records under an RR type we don't speak yet.
    std::string bad{'\xff', '\xff', '/', 'x'};
    EXPECT_FALSE(parse_store_key(bad).has_value());
}

TEST(DnsStoreKey_Roundtrip, AllKnownTypes) {
    for (const auto t : {RrType::A, RrType::NS, RrType::CNAME,
                          RrType::PTR, RrType::MX, RrType::TXT,
                          RrType::AAAA, RrType::SRV}) {
        const auto key = make_store_key(t, "anything.example.com");
        auto back = parse_store_key(key);
        ASSERT_TRUE(back.has_value()) << "type=" << rrtype_value(t);
        EXPECT_EQ(back.value().first, t);
        EXPECT_EQ(back.value().second, "anything.example.com");
    }
}

}  // namespace
}  // namespace gn::handler::dns

// NOLINTEND(bugprone-unchecked-optional-access)
