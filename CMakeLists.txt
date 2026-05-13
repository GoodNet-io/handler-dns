cmake_minimum_required(VERSION 3.22)

# DNS handler plugin — real RFC 1035 DNS service over a `gn.store`
# backing primitive. Typed records (A / AAAA / SRV / TXT / PTR /
# CNAME / MX), resolver cascade local → cache → upstream via c-ares,
# optional UDP listener for inbound queries. No KV storage code
# here — that lives in the store plugin; this plugin queries it
# through `host_api->query_extension("gn.store")`.
#
# Standalone: `find_package(GoodNet REQUIRED)` brings the SDK +
# `add_plugin()` helper from the installed kernel package.

if(NOT TARGET GoodNet::sdk)
    project(goodnet_handler_dns
        VERSION   1.0.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        goodnet_patch_rapidcheck_targets()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

## Source list grows slice by slice — D-DNS.6 adds dns_wire.cpp +
## dns_server.cpp.
set(GOODNET_DNS_SOURCES
    dns.cpp
    store_client.cpp
    dns_records.cpp
    dns_resolver.cpp)

## c-ares dependency. The resolver cascade's upstream tier uses
## ares_query + ares_process for native SRV/TXT/PTR support that
## asio's getaddrinfo-based resolver cannot offer. A deployment
## that wants local-store-only resolution can flip
## `GOODNET_DNS_WITH_UPSTREAM=OFF`; the plugin then ships only the
## mock-friendly interface and returns nullopt for any name the
## store doesn't already carry.
option(GOODNET_DNS_WITH_UPSTREAM
    "Build the c-ares upstream resolver alongside the cascade" ON)
if(GOODNET_DNS_WITH_UPSTREAM)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CARES REQUIRED libcares)
endif()

add_library(goodnet_dns_objects OBJECT ${GOODNET_DNS_SOURCES})
target_link_libraries(goodnet_dns_objects PUBLIC GoodNet::sdk)
if(GOODNET_DNS_WITH_UPSTREAM)
    target_compile_definitions(goodnet_dns_objects PUBLIC
        GOODNET_DNS_WITH_UPSTREAM=1)
    target_include_directories(goodnet_dns_objects PUBLIC
        ${CARES_INCLUDE_DIRS})
    target_link_libraries(goodnet_dns_objects PUBLIC
        ${CARES_LIBRARIES})
endif()
target_compile_features(goodnet_dns_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_dns_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_dns_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_dns_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_handler_dns
    plugin_entry.cpp
)
target_link_libraries(goodnet_handler_dns
    PRIVATE goodnet_dns_objects)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
