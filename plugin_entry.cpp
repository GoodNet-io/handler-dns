// SPDX-License-Identifier: GPL-2.0-only
/// @file   plugins/handlers/dns/plugin_entry.cpp
/// @brief  Plugin entry collapsed to `GN_HANDLER_PLUGIN`. The macro
///         generates the five `gn_plugin_*` C entry points and builds
///         the handler vtable from `DnsHandler`'s static metadata.
///         Registration covers both the handler vtable and the
///         `gn.dns` extension surface (resolve / put_record /
///         delete_record) backed by the resolver cascade.

#include <sdk/cpp/handler_plugin.hpp>

#include "dns.hpp"

GN_HANDLER_PLUGIN(
    ::gn::handler::dns::DnsHandler,
    "goodnet_handler_dns",
    "1.0.0-rc1")
