// SPDX-License-Identifier: GPL-2.0-only
#include "dns_resolver.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>

#ifdef GOODNET_DNS_WITH_UPSTREAM
#  include <ares.h>
#  include <ares_nameser.h>  // ns_t_*, ns_c_in
#  include <netdb.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#endif

namespace gn::handler::dns {

// ── clock ───────────────────────────────────────────────────────────────────

std::uint64_t default_clock_us() noexcept {
    static std::atomic<std::uint64_t> last{0};
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto want = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
    std::uint64_t prev = last.load(std::memory_order_relaxed);
    while (true) {
        const std::uint64_t next = want > prev ? want : prev + 1;
        if (last.compare_exchange_weak(prev, next,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return next;
        }
    }
}

// ── cascade ────────────────────────────────────────────────────────────────

std::optional<ResolvedRecord>
Resolver::lookup_store(std::string_view name, RrType type) const {
    if (store_ == nullptr) return std::nullopt;
    const auto key = make_store_key(type, name);
    auto hit = store_->get(key);
    if (!hit) return std::nullopt;

    /// Honour the TTL stored alongside the record. ttl_s == 0
    /// means permanent (operator-curated cluster records); any
    /// other value is measured against the current wall clock.
    if (hit->ttl_s > 0) {
        const auto expiry_us = hit->timestamp_us
            + static_cast<std::uint64_t>(hit->ttl_s) * 1'000'000ULL;
        if (clock_() >= expiry_us) {
            /// Cache miss masked as a hit — return nullopt so the
            /// cascade falls through to upstream and refreshes
            /// the record.
            return std::nullopt;
        }
    }

    ResolvedRecord r;
    r.type         = type;
    r.name         = std::string(name);
    r.rdata        = std::move(hit->value);
    r.ttl_s        = static_cast<std::uint32_t>(hit->ttl_s);
    r.timestamp_us = hit->timestamp_us;
    return r;
}

std::vector<ResolvedRecord>
Resolver::resolve(std::string_view name, RrType type,
                  std::uint32_t /*max_results*/) {
    /// Tier 1 — store / cache.
    if (auto cached = lookup_store(name, type)) {
        return {std::move(*cached)};
    }

    /// Tier 2 — upstream. When the cascade has no upstream
    /// configured the chain ends here with an empty answer.
    if (upstream_ == nullptr) return {};

    auto fresh = upstream_->resolve(name, type);
    if (fresh.empty()) return {};

    /// Tier 3 — cache-back. Write every record back into the
    /// store so the next lookup hits tier 1. Permanent
    /// (ttl_s == 0) responses never get auto-evicted; we don't
    /// override that interpretation.
    if (store_ != nullptr) {
        for (const auto& r : fresh) {
            (void)put_record(r.name, r.type, r.rdata, r.ttl_s, 0);
        }
    }
    return fresh;
}

bool Resolver::put_record(std::string_view name, RrType type,
                           std::span<const std::uint8_t> rdata,
                           std::uint32_t ttl_s,
                           std::uint8_t flags) const {
    if (store_ == nullptr) return false;
    const auto key = make_store_key(type, name);
    return store_->put(key, rdata, ttl_s, flags);
}

bool Resolver::delete_record(std::string_view name, RrType type) const {
    if (store_ == nullptr) return false;
    return store_->del(make_store_key(type, name));
}

// ── c-ares wrapper ──────────────────────────────────────────────────────────

#ifdef GOODNET_DNS_WITH_UPSTREAM

namespace {

/// Process-wide refcount around `ares_library_init`. c-ares
/// requires paired init/cleanup; multiple `AresUpstreamResolver`
/// instances must share the global state without re-initialising.
struct AresLibraryGuard {
    std::mutex         mu;
    std::uint32_t      refs = 0;

    bool incref() {
        std::lock_guard lk(mu);
        if (refs == 0) {
            if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
                return false;
            }
        }
        ++refs;
        return true;
    }
    void decref() noexcept {
        std::lock_guard lk(mu);
        if (refs == 0) return;
        if (--refs == 0) ares_library_cleanup();
    }
};

AresLibraryGuard& library_guard() {
    static AresLibraryGuard g;
    return g;
}

/// Bridge between c-ares' callback API and a synchronous result.
struct QueryState {
    int                            status = ARES_SUCCESS;
    std::vector<std::uint8_t>      raw;
    RrType                         type;
    std::string                    name;
};

void on_query(void* arg, int status, int /*timeouts*/,
              unsigned char* abuf, int alen) {
    auto* st = static_cast<QueryState*>(arg);
    st->status = status;
    if (status == ARES_SUCCESS && abuf != nullptr && alen > 0) {
        st->raw.assign(abuf, abuf + alen);
    }
}

/// Map our RrType to c-ares' ns_type constants.
int ns_type_of(RrType t) noexcept {
    switch (t) {
    case RrType::A:     return ns_t_a;
    case RrType::NS:    return ns_t_ns;
    case RrType::CNAME: return ns_t_cname;
    case RrType::PTR:   return ns_t_ptr;
    case RrType::MX:    return ns_t_mx;
    case RrType::TXT:   return ns_t_txt;
    case RrType::AAAA:  return ns_t_aaaa;
    case RrType::SRV:   return ns_t_srv;
    }
    return ns_t_a;
}

/// Spin until the channel has no more pending sockets — c-ares'
/// canonical synchronous loop. Caps total wait at ~5 s so a
/// misconfigured /etc/resolv.conf doesn't hang the calling thread.
void drain_channel(ares_channel channel) {
    const auto deadline = std::chrono::steady_clock::now()
                         + std::chrono::seconds(5);
    while (true) {
        ares_socket_t socks[ARES_GETSOCK_MAXNUM];
        int bits = ares_getsock(channel, socks, ARES_GETSOCK_MAXNUM);
        if (bits == 0) return;  // channel idle

        pollfd fds[ARES_GETSOCK_MAXNUM];
        std::size_t nfds = 0;
        for (std::size_t i = 0; i < ARES_GETSOCK_MAXNUM; ++i) {
            short events = 0;
            if (ARES_GETSOCK_READABLE(bits, i)) events |= POLLIN;
            if (ARES_GETSOCK_WRITABLE(bits, i)) events |= POLLOUT;
            if (events == 0) continue;
            fds[nfds++] = pollfd{socks[i], events, 0};
        }
        if (nfds == 0) return;

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            ares_cancel(channel);
            return;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now).count();
        timeval tv_buf{};
        timeval* tv = ares_timeout(channel, nullptr, &tv_buf);
        int timeout_ms = static_cast<int>(remaining);
        if (tv != nullptr) {
            const long ares_ms =
                tv->tv_sec * 1000L + tv->tv_usec / 1000L;
            if (ares_ms < timeout_ms) timeout_ms = static_cast<int>(ares_ms);
        }
        if (timeout_ms < 0) timeout_ms = 0;

        const int rc = ::poll(fds, nfds, timeout_ms);
        if (rc < 0) {
            ares_cancel(channel);
            return;
        }
        for (std::size_t i = 0; i < nfds; ++i) {
            const auto sock = fds[i].fd;
            const bool readable = (fds[i].revents & POLLIN)  != 0;
            const bool writable = (fds[i].revents & POLLOUT) != 0;
            ares_process_fd(channel,
                readable ? sock : ARES_SOCKET_BAD,
                writable ? sock : ARES_SOCKET_BAD);
        }
        if (rc == 0) {
            /// Timeout fired — let c-ares retry / give up.
            ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        }
    }
}

/// Decode the raw c-ares response into our `ResolvedRecord`
/// vector. One parse function per type; each returns
/// re-encoded rdata that matches `dns_records.hpp` codecs.
std::vector<ResolvedRecord>
decode_a(std::string_view name, const QueryState& st) {
    std::vector<ResolvedRecord> out;
    constexpr int kMaxA = 16;
    ares_addrttl ttls[kMaxA];
    int n = kMaxA;
    if (ares_parse_a_reply(st.raw.data(),
            static_cast<int>(st.raw.size()),
            nullptr, ttls, &n) != ARES_SUCCESS) return out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        ARecord r;
        std::memcpy(r.octets.data(), &ttls[i].ipaddr, 4);
        ResolvedRecord rr;
        rr.type  = RrType::A;
        rr.name  = std::string(name);
        rr.rdata = encode_a(r);
        rr.ttl_s = static_cast<std::uint32_t>(ttls[i].ttl);
        out.push_back(std::move(rr));
    }
    return out;
}

std::vector<ResolvedRecord>
decode_aaaa(std::string_view name, const QueryState& st) {
    std::vector<ResolvedRecord> out;
    constexpr int kMaxAaaa = 16;
    ares_addr6ttl ttls[kMaxAaaa];
    int n = kMaxAaaa;
    if (ares_parse_aaaa_reply(st.raw.data(),
            static_cast<int>(st.raw.size()),
            nullptr, ttls, &n) != ARES_SUCCESS) return out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AAAARecord r;
        std::memcpy(r.octets.data(), &ttls[i].ip6addr, 16);
        ResolvedRecord rr;
        rr.type  = RrType::AAAA;
        rr.name  = std::string(name);
        rr.rdata = encode_aaaa(r);
        rr.ttl_s = static_cast<std::uint32_t>(ttls[i].ttl);
        out.push_back(std::move(rr));
    }
    return out;
}

std::vector<ResolvedRecord>
decode_srv(std::string_view name, const QueryState& st) {
    std::vector<ResolvedRecord> out;
    ares_srv_reply* reply = nullptr;
    if (ares_parse_srv_reply(st.raw.data(),
            static_cast<int>(st.raw.size()), &reply) != ARES_SUCCESS ||
        reply == nullptr) return out;
    for (ares_srv_reply* p = reply; p != nullptr; p = p->next) {
        SrvRecord r;
        r.priority = static_cast<std::uint16_t>(p->priority);
        r.weight   = static_cast<std::uint16_t>(p->weight);
        r.port     = static_cast<std::uint16_t>(p->port);
        r.target   = p->host != nullptr ? p->host : "";
        auto wire = encode_srv(r);
        if (!wire) continue;
        ResolvedRecord rr;
        rr.type  = RrType::SRV;
        rr.name  = std::string(name);
        rr.rdata = std::move(*wire);
        rr.ttl_s = 0;  // c-ares <1.20 lacks ttl on srv; fallback default
        out.push_back(std::move(rr));
    }
    ares_free_data(reply);
    return out;
}

std::vector<ResolvedRecord>
decode_mx(std::string_view name, const QueryState& st) {
    std::vector<ResolvedRecord> out;
    ares_mx_reply* reply = nullptr;
    if (ares_parse_mx_reply(st.raw.data(),
            static_cast<int>(st.raw.size()), &reply) != ARES_SUCCESS ||
        reply == nullptr) return out;
    for (ares_mx_reply* p = reply; p != nullptr; p = p->next) {
        MxRecord r;
        r.preference = static_cast<std::uint16_t>(p->priority);
        r.exchange   = p->host != nullptr ? p->host : "";
        auto wire = encode_mx(r);
        if (!wire) continue;
        ResolvedRecord rr;
        rr.type  = RrType::MX;
        rr.name  = std::string(name);
        rr.rdata = std::move(*wire);
        rr.ttl_s = 0;
        out.push_back(std::move(rr));
    }
    ares_free_data(reply);
    return out;
}

std::vector<ResolvedRecord>
decode_txt(std::string_view name, const QueryState& st) {
    std::vector<ResolvedRecord> out;
    ares_txt_reply* reply = nullptr;
    if (ares_parse_txt_reply(st.raw.data(),
            static_cast<int>(st.raw.size()), &reply) != ARES_SUCCESS ||
        reply == nullptr) return out;
    /// c-ares yields one ares_txt_reply per response record; each
    /// record can have multiple segments (chained via the same
    /// struct because of the txt_reply_ext flag in newer releases).
    /// For the simple parser we treat each ares_txt_reply node as
    /// one record's single segment — matches what most upstreams
    /// publish.
    std::vector<std::string> segs;
    for (ares_txt_reply* p = reply; p != nullptr; p = p->next) {
        segs.emplace_back(reinterpret_cast<const char*>(p->txt),
                          p->length);
    }
    ares_free_data(reply);

    if (!segs.empty()) {
        auto wire = encode_txt(segs);
        if (wire) {
            ResolvedRecord rr;
            rr.type  = RrType::TXT;
            rr.name  = std::string(name);
            rr.rdata = std::move(*wire);
            rr.ttl_s = 0;
            out.push_back(std::move(rr));
        }
    }
    return out;
}

std::vector<ResolvedRecord>
decode_name_type(std::string_view name, RrType type,
                 const QueryState& st) {
    /// PTR / NS share the parser shape — extract one name out of
    /// the answer, re-encode.
    char* parsed = nullptr;
    int rc = ARES_ENODATA;
    if (type == RrType::PTR) {
        struct hostent* host = nullptr;
        rc = ares_parse_ptr_reply(st.raw.data(),
                                  static_cast<int>(st.raw.size()),
                                  nullptr, 0, AF_INET, &host);
        if (rc == ARES_SUCCESS && host != nullptr) {
            parsed = host->h_name ? strdup(host->h_name) : nullptr;
            ares_free_hostent(host);
        }
    } else if (type == RrType::NS) {
        struct hostent* host = nullptr;
        rc = ares_parse_ns_reply(st.raw.data(),
                                 static_cast<int>(st.raw.size()),
                                 &host);
        if (rc == ARES_SUCCESS && host != nullptr) {
            parsed = host->h_name ? strdup(host->h_name) : nullptr;
            ares_free_hostent(host);
        }
    }
    std::vector<ResolvedRecord> out;
    if (parsed != nullptr) {
        auto wire = encode_name(parsed);
        free(parsed);
        if (wire) {
            ResolvedRecord rr;
            rr.type  = type;
            rr.name  = std::string(name);
            rr.rdata = std::move(*wire);
            rr.ttl_s = 0;
            out.push_back(std::move(rr));
        }
    }
    return out;
}

}  // namespace

std::unique_ptr<AresUpstreamResolver> AresUpstreamResolver::create() {
    if (!library_guard().incref()) return nullptr;
    ares_channel channel = nullptr;
    ares_options opts{};
    int optmask = 0;
    /// Reasonable defaults: 3 s timeout per query, 2 retries.
    opts.timeout = 3000;
    optmask |= ARES_OPT_TIMEOUTMS;
    opts.tries = 2;
    optmask |= ARES_OPT_TRIES;

    if (ares_init_options(&channel, &opts, optmask) != ARES_SUCCESS) {
        library_guard().decref();
        return nullptr;
    }
    return std::unique_ptr<AresUpstreamResolver>(
        new AresUpstreamResolver(channel));
}

AresUpstreamResolver::AresUpstreamResolver(void* channel) noexcept
    : channel_(channel) {}

AresUpstreamResolver::~AresUpstreamResolver() {
    if (channel_ != nullptr) {
        ares_destroy(static_cast<ares_channel>(channel_));
        channel_ = nullptr;
        library_guard().decref();
    }
}

std::vector<ResolvedRecord>
AresUpstreamResolver::resolve(std::string_view name, RrType type) {
    if (channel_ == nullptr || name.empty()) return {};
    const std::string z(name);  // c-ares wants NUL-terminated

    QueryState st;
    st.type = type;
    st.name = z;

    ares_query(static_cast<ares_channel>(channel_),
               z.c_str(), ns_c_in, ns_type_of(type),
               &on_query, &st);
    drain_channel(static_cast<ares_channel>(channel_));

    if (st.status != ARES_SUCCESS || st.raw.empty()) return {};

    switch (type) {
    case RrType::A:     return decode_a(name, st);
    case RrType::AAAA:  return decode_aaaa(name, st);
    case RrType::SRV:   return decode_srv(name, st);
    case RrType::MX:    return decode_mx(name, st);
    case RrType::TXT:   return decode_txt(name, st);
    case RrType::PTR:   return decode_name_type(name, RrType::PTR, st);
    case RrType::NS:    return decode_name_type(name, RrType::NS, st);
    case RrType::CNAME:
        /// c-ares lacks a direct CNAME parser — CNAMEs surface in
        /// A/AAAA answer chains. For CNAME-direct queries the
        /// upstream returns nothing in this slice; D-DNS.6 may
        /// add raw-message parsing for it.
        return {};
    }
    return {};
}

#endif  // GOODNET_DNS_WITH_UPSTREAM

}  // namespace gn::handler::dns
