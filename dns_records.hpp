// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/dns_records.hpp
/// @brief  Typed DNS resource records — encoders, decoders, and
///         the `<type>/<name>` store-key shape that lets one
///         gn.store namespace multiplex every RR type.
///
/// Slice D-DNS.3 introduces the in-plugin typed layer. The SDK
/// extension ABI keeps its KV-style shape until D-DNS.4 rewrites
/// `sdk/extensions/dns.h` around the resolver cascade; in the
/// meantime callers reach the typed codecs through the C++ symbols
/// here.
///
/// Name encoding follows RFC 1035 §3.1 *without* compression
/// (RFC 1035 §4.1.4 pointers only appear inside DNS messages — a
/// pointer in stored rdata would dangle once the surrounding
/// message is gone). Compression is reintroduced in D-DNS.6 inside
/// the `dns_wire.{hpp,cpp}` message codec, scoped to a single
/// message buffer.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gn::handler::dns {

/// Stable RR-type identifiers. Numeric values match the IANA DNS
/// parameters registry (RFC 1035 §3.2.2 / RFC 3596 §2.1 /
/// RFC 2782 §1) so debug logs, wire dumps, and `dig` output line
/// up. New types are added by appending — the enum stays open
/// for future RFC additions.
enum class RrType : std::uint16_t {
    A     = 1,    ///< IPv4 address (RFC 1035 §3.4.1)
    NS    = 2,    ///< authoritative nameserver (RFC 1035 §3.3.11)
    CNAME = 5,    ///< canonical name alias (RFC 1035 §3.3.1)
    PTR   = 12,   ///< pointer (RFC 1035 §3.3.12)
    MX    = 15,   ///< mail exchange (RFC 1035 §3.3.9)
    TXT   = 16,   ///< text strings (RFC 1035 §3.3.14)
    AAAA  = 28,   ///< IPv6 address (RFC 3596 §2.1)
    SRV   = 33,   ///< service location (RFC 2782 §1)
};

[[nodiscard]] constexpr std::uint16_t rrtype_value(RrType t) noexcept {
    return static_cast<std::uint16_t>(t);
}

/// Hard upper bound on a single label per RFC 1035 §2.3.4. Labels
/// past 63 bytes are illegal; the top 2 bits of a length octet are
/// reserved for compression pointers (RFC 1035 §4.1.4).
inline constexpr std::size_t kMaxLabelLen = 63;

/// Hard upper bound on a fully-qualified name including length
/// octets and the trailing zero (RFC 1035 §2.3.4). Names larger
/// than this never fit on the wire.
inline constexpr std::size_t kMaxNameLen = 255;

/// Hard upper bound on a single TXT segment per RFC 1035 §3.3.14.
inline constexpr std::size_t kMaxTxtSegmentLen = 255;

// ── per-type typed bodies ───────────────────────────────────────────────────

struct ARecord {
    std::array<std::uint8_t, 4> octets{};
};

struct AAAARecord {
    std::array<std::uint8_t, 16> octets{};
};

struct SrvRecord {
    std::uint16_t priority = 0;
    std::uint16_t weight   = 0;
    std::uint16_t port     = 0;
    std::string   target;
};

struct MxRecord {
    std::uint16_t preference = 0;
    std::string   exchange;
};

/// CNAME / PTR / NS share the same wire shape (one name) — the
/// type byte in the store key tells the consumer which interpretation
/// applies. Helper alias kept distinct in the API so call sites
/// document intent.
using NameRecord = std::string;

/// TXT body: one or more length-prefixed UTF-8 segments. The
/// vector preserves segment boundaries (most consumers concatenate
/// them, but some — like ACME challenges — pin to a single
/// segment).
using TxtRecord = std::vector<std::string>;

// ── name encoder / decoder (RFC 1035 §3.1, no compression) ──────────────────

/// Encode a UTF-8 / ASCII DNS name into the label sequence form.
/// Empty input encodes to just the root terminator (`{0}`).
/// Returns `nullopt` when any label exceeds `kMaxLabelLen` or the
/// total encoded length would exceed `kMaxNameLen`.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_name(std::string_view name);

/// Decode a label sequence into a dotted name. Returns `nullopt`
/// when the input is truncated, a label length-octet has its top
/// bits set (compression pointer disallowed here), a label exceeds
/// `kMaxLabelLen`, or the cumulative name exceeds `kMaxNameLen`.
[[nodiscard]] std::optional<NameRecord>
decode_name(std::span<const std::uint8_t> src);

// ── per-type encoders ───────────────────────────────────────────────────────

[[nodiscard]] std::vector<std::uint8_t> encode_a(const ARecord& r);
[[nodiscard]] std::vector<std::uint8_t> encode_aaaa(const AAAARecord& r);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_srv(const SrvRecord& r);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_mx(const MxRecord& r);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_cname(std::string_view target);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_ptr(std::string_view target);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_ns(std::string_view target);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode_txt(std::span<const std::string> segments);

// ── per-type parsers ────────────────────────────────────────────────────────

[[nodiscard]] std::optional<ARecord>
parse_a(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<AAAARecord>
parse_aaaa(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<SrvRecord>
parse_srv(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<MxRecord>
parse_mx(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<NameRecord>
parse_cname(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<NameRecord>
parse_ptr(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<NameRecord>
parse_ns(std::span<const std::uint8_t> rdata);

[[nodiscard]] std::optional<TxtRecord>
parse_txt(std::span<const std::uint8_t> rdata);

// ── store-key encoding `<type-byte-MSB><type-byte-LSB>/<name>` ──────────────

/// Build the store key for a typed record. The two-byte big-endian
/// type prefix means the `name` part can contain any byte (DNS is
/// case-insensitive ASCII in practice, but we don't strip / mangle).
/// The slash separator is illegal inside DNS labels so it never
/// appears in the suffix.
[[nodiscard]] std::string make_store_key(RrType type, std::string_view name);

/// Inverse of `make_store_key`. Returns `nullopt` on a malformed
/// key (too short, missing slash, unknown type byte).
[[nodiscard]] std::optional<std::pair<RrType, std::string>>
parse_store_key(std::string_view key);

/// Validate that `n` denotes one of the RR types this slice
/// understands. Useful when decoding a key from an unknown peer.
[[nodiscard]] bool is_known_rrtype(std::uint16_t n) noexcept;

}  // namespace gn::handler::dns
