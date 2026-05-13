cmake_minimum_required(VERSION 3.22)

# DNS handler — Apache 2.0. Brings the legacy `apps/store` surface
# forward as a v1 handler plugin: pluggable IDnsBackend backend (memory
# reference shipped here; sqlite + DHT + Redis planned), wire
# dispatcher for the seven DNS_* envelope types, exposes the
# `gn.dns` extension for in-process callers.
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

## SQLite optional backend. The handler core (dns.cpp) doesn't
## link sqlite; only the SqliteDnsBackend TU does, so a deployment that
## ships only the memory backend can be built without sqlite at
## all by setting `-DGOODNET_DNS_WITH_SQLITE=OFF`. Default ON so
## the standalone plugin build matches what the kernel monorepo
## ships through `coreBuildInputs`.
option(GOODNET_DNS_WITH_SQLITE
    "Build the SQLite-backed IDnsBackend alongside the memory reference" ON)

set(GOODNET_DNS_SOURCES dns.cpp)
if(GOODNET_DNS_WITH_SQLITE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SQLite3 REQUIRED sqlite3)
    list(APPEND GOODNET_DNS_SOURCES sqlite_backend.cpp)
endif()

add_library(goodnet_dns_objects OBJECT ${GOODNET_DNS_SOURCES})
target_link_libraries(goodnet_dns_objects PUBLIC GoodNet::sdk)
if(GOODNET_DNS_WITH_SQLITE)
    target_compile_definitions(goodnet_dns_objects PUBLIC
        GOODNET_DNS_WITH_SQLITE=1)
    target_include_directories(goodnet_dns_objects PUBLIC
        ${SQLite3_INCLUDE_DIRS})
    target_link_libraries(goodnet_dns_objects PUBLIC
        ${SQLite3_LIBRARIES})
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
