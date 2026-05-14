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

add_executable(test_dns_store_client test_dns_store_client.cpp)
target_link_libraries(test_dns_store_client PRIVATE
    GoodNet::sdk
    goodnet_dns_objects
    spdlog::spdlog
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_dns_store_client PRIVATE cxx_std_23)
gtest_discover_tests(test_dns_store_client
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)

add_executable(test_dns_records test_dns_records.cpp)
target_link_libraries(test_dns_records PRIVATE
    GoodNet::sdk
    goodnet_dns_objects
    spdlog::spdlog
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_dns_records PRIVATE cxx_std_23)
gtest_discover_tests(test_dns_records
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)

add_executable(test_dns_resolver test_dns_resolver.cpp)
target_link_libraries(test_dns_resolver PRIVATE
    GoodNet::sdk
    goodnet_dns_objects
    spdlog::spdlog
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_dns_resolver PRIVATE cxx_std_23)
gtest_discover_tests(test_dns_resolver
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)

## Future test executables land here:
##   UDP nameserver listener — test_dns_wire.cpp + test_dns_server.cpp
##   mDNS / DNS-SD multicast layer — test_dns_mdns.cpp
