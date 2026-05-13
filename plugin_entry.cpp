// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/handlers/dns/plugin_entry.cpp
/// @brief  Plugin entry collapsed to `GN_HANDLER_PLUGIN`. Same shape
///         as the heartbeat handler — the macro generates the five
///         `gn_plugin_*` C entry points, builds the handler vtable
///         from `DnsHandler`'s static metadata, and registers the
///         `gn.dns` extension via the class's
///         `extension_name` / `extension_version` / `extension_vtable`
///         triplet.

#include <sdk/cpp/handler_plugin.hpp>

#include "dns.hpp"

GN_HANDLER_PLUGIN(
    ::gn::handler::dns::DnsHandler,
    "goodnet_handler_dns",
    "1.0.0-rc1")
