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

if(GOODNET_DNS_WITH_SQLITE)
    add_executable(test_dns_sqlite_backend test_dns_sqlite_backend.cpp)
    target_link_libraries(test_dns_sqlite_backend PRIVATE
        GoodNet::sdk
        goodnet_dns_objects
        spdlog::spdlog
        GTest::gtest
        GTest::gtest_main)
    target_compile_features(test_dns_sqlite_backend PRIVATE cxx_std_23)
    gtest_discover_tests(test_dns_sqlite_backend
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
endif()
