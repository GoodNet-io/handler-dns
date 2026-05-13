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

## Source list grows slice by slice — D-DNS.1 ships only the
## skeleton (dns.cpp), D-DNS.2 adds store_client.cpp, D-DNS.3 adds
## dns_records.cpp, D-DNS.4 adds dns_resolver.cpp (+ c-ares dep),
## D-DNS.6 adds dns_wire.cpp + dns_server.cpp.
set(GOODNET_DNS_SOURCES dns.cpp)

add_library(goodnet_dns_objects OBJECT ${GOODNET_DNS_SOURCES})
target_link_libraries(goodnet_dns_objects PUBLIC GoodNet::sdk)
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
