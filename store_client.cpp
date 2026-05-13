// SPDX-License-Identifier: GPL-2.0-only
#include "store_client.hpp"

#include <cstring>

namespace gn::handler::dns {

namespace {

/// Translate one `gn_store_entry_t` view into an owned
/// `StoreRecord`. The extension's `key`/`value` pointers are
/// @borrowed for the duration of the call only.
StoreRecord clone_view(const gn_store_entry_t& view) {
    StoreRecord r;
    if (view.key != nullptr && view.key_len > 0) {
        r.key.assign(view.key, view.key_len);
    }
    if (view.value != nullptr && view.value_len > 0) {
        r.value.assign(view.value, view.value + view.value_len);
    }
    r.timestamp_us = view.timestamp_us;
    r.ttl_s        = view.ttl_s;
    r.flags        = view.flags;
    return r;
}

}  // namespace

std::optional<StoreClient> StoreClient::query(const host_api_t* api) {
    if (api == nullptr || api->query_extension_checked == nullptr) {
        return std::nullopt;
    }
    const void* raw = nullptr;
    const gn_result_t rc = api->query_extension_checked(
        api->host_ctx, GN_EXT_STORE,
        GN_EXT_STORE_VERSION, &raw);
    if (rc != GN_OK || raw == nullptr) {
        return std::nullopt;
    }
    const auto* vt = static_cast<const gn_store_api_t*>(raw);
    /// The producer marked the vtable size; if the consumer's
    /// SDK header is newer than what the store ships, fields we
    /// rely on may be missing. `query_extension_checked` already
    /// rejects mismatched majors, so this is just a sanity bound.
    if (vt->api_size < sizeof(gn_store_api_t)) {
        return std::nullopt;
    }
    if (vt->put == nullptr || vt->get == nullptr ||
        vt->query == nullptr || vt->del == nullptr) {
        return std::nullopt;
    }
    return StoreClient(api, vt);
}

bool StoreClient::put(std::string_view key,
                       std::span<const std::uint8_t> value,
                       std::uint64_t ttl_s,
                       std::uint8_t flags) const {
    if (vt_ == nullptr || vt_->put == nullptr) return false;
    return vt_->put(vt_->ctx,
                     key.data(), key.size(),
                     value.data(), value.size(),
                     ttl_s, flags) == 0;
}

std::optional<StoreRecord>
StoreClient::get(std::string_view key) const {
    if (vt_ == nullptr || vt_->get == nullptr) return std::nullopt;
    gn_store_entry_t view{};
    if (vt_->get(vt_->ctx, key.data(), key.size(), &view) != 0) {
        return std::nullopt;
    }
    return clone_view(view);
}

std::vector<StoreRecord>
StoreClient::drain_query(gn_store_query_t mode,
                          std::string_view key,
                          std::uint64_t since_us,
                          std::uint32_t max_results) const {
    if (vt_ == nullptr || vt_->query == nullptr) return {};

    std::vector<StoreRecord> out;
    out.reserve(max_results > 0 ? max_results : 16);

    /// C callback bridge: the extension's `emit` receives the
    /// caller-supplied opaque pointer (`emit_user`) and one
    /// borrowed record per match. Pass `&out` as the opaque and
    /// translate each view into an owned record.
    auto emit = [](void* user, const gn_store_entry_t* view) {
        if (user == nullptr || view == nullptr) return;
        auto* sink = static_cast<std::vector<StoreRecord>*>(user);
        sink->push_back(clone_view(*view));
    };

    (void)vt_->query(vt_->ctx, mode,
                      key.data(), key.size(),
                      since_us, max_results,
                      emit, &out);
    return out;
}

std::vector<StoreRecord>
StoreClient::get_prefix(std::string_view prefix,
                         std::uint32_t max_results) const {
    return drain_query(GN_STORE_QUERY_PREFIX, prefix, 0, max_results);
}

std::vector<StoreRecord>
StoreClient::get_since(std::uint64_t since_us,
                        std::uint32_t max_results) const {
    return drain_query(GN_STORE_QUERY_SINCE, {}, since_us, max_results);
}

bool StoreClient::del(std::string_view key) const {
    if (vt_ == nullptr || vt_->del == nullptr) return false;
    return vt_->del(vt_->ctx, key.data(), key.size()) == 0;
}

std::uint64_t StoreClient::cleanup_expired() const {
    if (vt_ == nullptr || vt_->cleanup_expired == nullptr) return 0;
    return vt_->cleanup_expired(vt_->ctx);
}

}  // namespace gn::handler::dns
