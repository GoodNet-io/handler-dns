// SPDX-License-Identifier: GPL-2.0-only
#include "dns_records.hpp"

#include <algorithm>
#include <cstring>

namespace gn::handler::dns {

namespace {

/// Big-endian 16-bit writer. Used for SRV/MX prefix integers and
/// the store-key type prefix.
void write_be16(std::vector<std::uint8_t>& dst, std::uint16_t v) {
    dst.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    dst.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

std::uint16_t read_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

}  // namespace

// ── name encoder / decoder ──────────────────────────────────────────────────

std::optional<std::vector<std::uint8_t>>
encode_name(std::string_view name) {
    std::vector<std::uint8_t> out;
    out.reserve(name.size() + 2);

    /// Empty / root-only ("." or "") encodes to a single zero
    /// terminator. The decoder reads it back as the empty string
    /// since the canonical form drops the trailing dot.
    if (name.empty() || name == ".") {
        out.push_back(0);
        return out;
    }

    std::size_t start = 0;
    while (start < name.size()) {
        const auto dot = name.find('.', start);
        const auto end = (dot == std::string_view::npos)
                            ? name.size() : dot;
        const auto label_len = end - start;

        if (label_len == 0) {
            /// Two adjacent dots, leading dot, or trailing dot on a
            /// non-canonical name. RFC 1035 §3.1 forbids zero-length
            /// labels in the middle; the trailing-dot case is
            /// canonical-FQDN syntax and we accept it by breaking
            /// out — the terminator gets appended after the loop.
            if (start == name.size()) break;          // trailing dot
            return std::nullopt;                       // empty middle label
        }
        if (label_len > kMaxLabelLen) return std::nullopt;

        out.push_back(static_cast<std::uint8_t>(label_len));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                   name.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    out.push_back(0);
    if (out.size() > kMaxNameLen) return std::nullopt;
    return out;
}

std::optional<NameRecord>
decode_name(std::span<const std::uint8_t> src) {
    std::string out;
    out.reserve(src.size());

    std::size_t cursor = 0;
    while (cursor < src.size()) {
        const std::uint8_t len_byte = src[cursor++];
        /// Top 2 bits set ⇒ compression pointer. Disallowed in
        /// rdata blobs stored by this plugin per the §header
        /// comment; let the message-layer decoder handle pointers
        /// in D-DNS.6 with full message context.
        if ((len_byte & 0xC0) != 0) return std::nullopt;
        if (len_byte == 0) {
            /// Root terminator — stop. We DO NOT append a trailing
            /// dot so the decoded form matches what callers passed
            /// in to `encode_name` (which strips trailing dots
            /// canonically).
            if (out.size() > kMaxNameLen) return std::nullopt;
            return out;
        }
        if (len_byte > kMaxLabelLen)            return std::nullopt;
        if (cursor + len_byte > src.size())     return std::nullopt;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(src.data() + cursor),
                   len_byte);
        cursor += len_byte;
    }
    /// Ran past end-of-input without finding the terminator.
    return std::nullopt;
}

// ── per-type encoders ───────────────────────────────────────────────────────

std::vector<std::uint8_t> encode_a(const ARecord& r) {
    return {r.octets.begin(), r.octets.end()};
}

std::vector<std::uint8_t> encode_aaaa(const AAAARecord& r) {
    return {r.octets.begin(), r.octets.end()};
}

std::optional<std::vector<std::uint8_t>>
encode_srv(const SrvRecord& r) {
    auto target_wire = encode_name(r.target);
    if (!target_wire) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(6 + target_wire->size());
    write_be16(out, r.priority);
    write_be16(out, r.weight);
    write_be16(out, r.port);
    out.insert(out.end(), target_wire->begin(), target_wire->end());
    return out;
}

std::optional<std::vector<std::uint8_t>>
encode_mx(const MxRecord& r) {
    auto exchange_wire = encode_name(r.exchange);
    if (!exchange_wire) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(2 + exchange_wire->size());
    write_be16(out, r.preference);
    out.insert(out.end(), exchange_wire->begin(), exchange_wire->end());
    return out;
}

std::optional<std::vector<std::uint8_t>>
encode_cname(std::string_view target) {
    return encode_name(target);
}

std::optional<std::vector<std::uint8_t>>
encode_ptr(std::string_view target) {
    return encode_name(target);
}

std::optional<std::vector<std::uint8_t>>
encode_ns(std::string_view target) {
    return encode_name(target);
}

std::optional<std::vector<std::uint8_t>>
encode_txt(std::span<const std::string> segments) {
    if (segments.empty()) return std::nullopt;
    std::vector<std::uint8_t> out;
    /// Reserve an envelope big enough for the common case; the
    /// loop appends precisely.
    std::size_t total = 0;
    for (const auto& s : segments) {
        if (s.size() > kMaxTxtSegmentLen) return std::nullopt;
        total += 1 + s.size();
    }
    out.reserve(total);
    for (const auto& s : segments) {
        out.push_back(static_cast<std::uint8_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

// ── per-type parsers ────────────────────────────────────────────────────────

std::optional<ARecord>
parse_a(std::span<const std::uint8_t> rdata) {
    if (rdata.size() != 4) return std::nullopt;
    ARecord r;
    std::memcpy(r.octets.data(), rdata.data(), 4);
    return r;
}

std::optional<AAAARecord>
parse_aaaa(std::span<const std::uint8_t> rdata) {
    if (rdata.size() != 16) return std::nullopt;
    AAAARecord r;
    std::memcpy(r.octets.data(), rdata.data(), 16);
    return r;
}

std::optional<SrvRecord>
parse_srv(std::span<const std::uint8_t> rdata) {
    if (rdata.size() < 7) return std::nullopt;  // 6-byte header + min 1-byte name (root)
    SrvRecord r;
    r.priority = read_be16(rdata.data() + 0);
    r.weight   = read_be16(rdata.data() + 2);
    r.port     = read_be16(rdata.data() + 4);
    auto name = decode_name(rdata.subspan(6));
    if (!name) return std::nullopt;
    r.target = std::move(*name);
    return r;
}

std::optional<MxRecord>
parse_mx(std::span<const std::uint8_t> rdata) {
    if (rdata.size() < 3) return std::nullopt;  // 2-byte preference + min 1-byte name
    MxRecord r;
    r.preference = read_be16(rdata.data() + 0);
    auto name = decode_name(rdata.subspan(2));
    if (!name) return std::nullopt;
    r.exchange = std::move(*name);
    return r;
}

std::optional<NameRecord>
parse_cname(std::span<const std::uint8_t> rdata) {
    return decode_name(rdata);
}

std::optional<NameRecord>
parse_ptr(std::span<const std::uint8_t> rdata) {
    return decode_name(rdata);
}

std::optional<NameRecord>
parse_ns(std::span<const std::uint8_t> rdata) {
    return decode_name(rdata);
}

std::optional<TxtRecord>
parse_txt(std::span<const std::uint8_t> rdata) {
    TxtRecord out;
    std::size_t cursor = 0;
    while (cursor < rdata.size()) {
        const auto seg_len = rdata[cursor++];
        if (cursor + seg_len > rdata.size()) return std::nullopt;
        out.emplace_back(
            reinterpret_cast<const char*>(rdata.data() + cursor),
            seg_len);
        cursor += seg_len;
    }
    if (out.empty()) return std::nullopt;
    return out;
}

// ── store-key codec ─────────────────────────────────────────────────────────

bool is_known_rrtype(std::uint16_t n) noexcept {
    switch (n) {
    case 1: case 2: case 5: case 12: case 15: case 16: case 28: case 33:
        return true;
    default:
        return false;
    }
}

std::string make_store_key(RrType type, std::string_view name) {
    std::string out;
    /// Two-byte big-endian type prefix + slash + name. Two bytes
    /// because RrType is a u16 and future RFC types may use the
    /// upper byte (the IANA registry already has values >255 like
    /// DS=43, RRSIG=46); locking to two bytes today avoids a
    /// migration when those land.
    out.reserve(3 + name.size());
    const auto v = rrtype_value(type);
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back('/');
    out.append(name);
    return out;
}

std::optional<std::pair<RrType, std::string>>
parse_store_key(std::string_view key) {
    if (key.size() < 3 || key[2] != '/') return std::nullopt;
    const std::uint16_t n = static_cast<std::uint16_t>(
        (static_cast<std::uint8_t>(key[0]) << 8) |
         static_cast<std::uint8_t>(key[1]));
    if (!is_known_rrtype(n)) return std::nullopt;
    return std::pair<RrType, std::string>{
        static_cast<RrType>(n),
        std::string(key.substr(3))
    };
}

}  // namespace gn::handler::dns
