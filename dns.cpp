// SPDX-License-Identifier: GPL-2.0-only
#include "dns.hpp"

namespace gn::handler::dns {

DnsHandler::DnsHandler(const host_api_t* api) : api_(api) {}

DnsHandler::~DnsHandler() = default;

gn_propagation_t DnsHandler::handle_message(const gn_message_t* env) {
    /// Slice D-DNS.1 — no semantics yet; let the dispatch chain
    /// continue so an alternate handler (or the kernel's default
    /// reject path) takes the envelope. D-DNS.2 installs the
    /// store-consumer + PUT_RECORD case, D-DNS.4 wires RESOLVE
    /// through the cascade.
    (void)env;
    return GN_PROPAGATION_CONTINUE;
}

}  // namespace gn::handler::dns
