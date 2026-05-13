# DNS handler unit tests — Apache 2.0.
include(GoogleTest)

add_executable(test_dns test_dns.cpp)
target_link_libraries(test_dns PRIVATE
    GoodNet::sdk
    goodnet_dns_objects
    spdlog::spdlog
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_dns PRIVATE cxx_std_23)
## PCH intentionally skipped — the umbrella header pulls spdlog/asio
## that aren't on this target's include path; the test is short
## enough that a clean compile per TU has no measurable cost.
gtest_discover_tests(test_dns
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)

## Per-slice test executables land here:
##   D-DNS.2 — test_dns_store_client.cpp
##   D-DNS.3 — test_dns_records.cpp
##   D-DNS.4 — test_dns_resolver.cpp
##   D-DNS.6 — test_dns_wire.cpp + test_dns_server.cpp
