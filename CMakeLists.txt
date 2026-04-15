cmake_minimum_required(VERSION 3.14)

project(TinyPKI VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)

set(TINYPKI_CORE_SRCS
    src/ecqv/ecqv.c
    src/revoke/revoke.c
    src/revoke/revoke_sync.c
    src/revoke/revoke_bft.c
    src/revoke/merkle.c
    src/revoke/merkle_cbor.c
    src/revoke/merkle_epoch.c
    src/auth/auth.c
    src/pki/crypto.c
    src/pki/rev_bridge.c
    src/pki/service.c
    src/pki/client.c
)

add_library(tinypki STATIC ${TINYPKI_CORE_SRCS})
target_include_directories(tinypki PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tinypki PUBLIC OpenSSL::Crypto OpenSSL::SSL)
target_compile_definitions(tinypki PUBLIC _POSIX_C_SOURCE=200809L)

if (MSVC)
    target_compile_options(tinypki PRIVATE /W4)
else ()
    target_compile_options(tinypki PRIVATE -Wall -Wextra)
endif ()

add_executable(sm2_demo src/app/main.c)
target_link_libraries(sm2_demo PRIVATE tinypki)

add_executable(sm2_test_cert_flow src/app/demo_test_cert_flow.c)
target_link_libraries(sm2_test_cert_flow PRIVATE tinypki)

add_executable(sm2_test_merkle_flow src/app/demo_test_merkle_flow.c)
target_link_libraries(sm2_test_merkle_flow PRIVATE tinypki)

add_executable(sm2_bench_network_overhead src/app/bench_network_overhead.c)
target_link_libraries(sm2_bench_network_overhead PRIVATE tinypki)

add_executable(sm2_bench_capability_suite src/app/bench_capability_suite.c)
target_link_libraries(sm2_bench_capability_suite PRIVATE tinypki)
if (NOT MSVC)
    target_link_libraries(sm2_bench_capability_suite PRIVATE m)
endif ()
if (WIN32)
    target_link_libraries(sm2_bench_capability_suite PRIVATE ws2_32)
endif ()

set(TINYPKI_TEST_COMMON_SRCS
    tests/test_common.c
)

set(TINYPKI_TEST_ECQV_SRCS
    tests/test_ecqv.c
)

set(TINYPKI_TEST_REVOKE_SRCS
    tests/test_revoke.c
    tests/test_revoke_helpers.c
    tests/test_revoke_core.c
    tests/test_revoke_sync.c
    tests/test_revoke_bft.c
)

set(TINYPKI_TEST_MERKLE_SRCS
    tests/test_merkle.c
)

set(TINYPKI_TEST_AUTH_SRCS
    tests/test_auth.c
)

set(TINYPKI_TEST_PKI_SRCS
    tests/test_pki.c
)

set(TINYPKI_TEST_PKI_INTERNAL_SRCS
    tests/test_pki_internal.c
)

add_executable(test_all
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_ECQV_SRCS}
    ${TINYPKI_TEST_REVOKE_SRCS}
    ${TINYPKI_TEST_MERKLE_SRCS}
    ${TINYPKI_TEST_AUTH_SRCS}
    ${TINYPKI_TEST_PKI_SRCS}
    ${TINYPKI_TEST_PKI_INTERNAL_SRCS}
    tests/test_main.c)
target_link_libraries(test_all PRIVATE tinypki)

add_executable(test_ecqv_suite
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_ECQV_SRCS}
    tests/test_main_ecqv.c)
target_link_libraries(test_ecqv_suite PRIVATE tinypki)

add_executable(test_revoke_suite
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_REVOKE_SRCS}
    tests/test_main_revoke.c)
target_link_libraries(test_revoke_suite PRIVATE tinypki)

add_executable(test_auth_suite
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_AUTH_SRCS}
    tests/test_main_auth.c)
target_link_libraries(test_auth_suite PRIVATE tinypki)

add_executable(test_pki_suite
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_PKI_SRCS}
    tests/test_main_pki.c)
target_link_libraries(test_pki_suite PRIVATE tinypki)

add_executable(test_pki_internal_suite
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_PKI_INTERNAL_SRCS}
    tests/test_main_pki_internal.c)
target_link_libraries(test_pki_internal_suite PRIVATE tinypki)

add_executable(test_merkle_suite
    ${TINYPKI_TEST_COMMON_SRCS}
    ${TINYPKI_TEST_MERKLE_SRCS}
    tests/test_main_merkle.c)
target_link_libraries(test_merkle_suite PRIVATE tinypki)

enable_testing()
add_test(NAME suite_ecqv COMMAND test_ecqv_suite)
add_test(NAME suite_revoke COMMAND test_revoke_suite)
add_test(NAME suite_auth COMMAND test_auth_suite)
add_test(NAME suite_pki COMMAND test_pki_suite)
add_test(NAME suite_pki_internal COMMAND test_pki_internal_suite)
add_test(NAME suite_merkle COMMAND test_merkle_suite)
