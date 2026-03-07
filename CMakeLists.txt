cmake_minimum_required(VERSION 3.14)

project(TinyPKI VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)

set(SM2ECQV_CORE_SRCS
    src/ecqv/ecqv.c
    src/revoke/revoke.c
    src/revoke/merkle.c
    src/revoke/merkle_cbor.c
    src/revoke/merkle_epoch.c
    src/revoke/merkle_k_anon.c
    src/auth/auth.c
    src/pki/crypto.c
    src/pki/service.c
    src/pki/client.c
)

add_library(sm2ecqv STATIC ${SM2ECQV_CORE_SRCS})
target_include_directories(sm2ecqv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(sm2ecqv PUBLIC OpenSSL::Crypto OpenSSL::SSL)
target_compile_definitions(sm2ecqv PUBLIC _POSIX_C_SOURCE=200809L)

if (MSVC)
    target_compile_options(sm2ecqv PRIVATE /W4)
else ()
    target_compile_options(sm2ecqv PRIVATE -Wall -Wextra)
endif ()

add_executable(sm2_demo src/app/main.c)
target_link_libraries(sm2_demo PRIVATE sm2ecqv)

add_executable(sm2_test_cert_flow src/app/demo_test_cert_flow.c)
target_link_libraries(sm2_test_cert_flow PRIVATE sm2ecqv)

add_executable(sm2_test_merkle_flow src/app/demo_test_merkle_flow.c)
target_link_libraries(sm2_test_merkle_flow PRIVATE sm2ecqv)

set(SM2ECQV_TEST_SRCS
    tests/test_common.c
    tests/test_ecqv.c
    tests/test_revoke.c
    tests/test_merkle.c
    tests/test_auth.c
    tests/test_pki.c
    tests/test_main.c
)

add_executable(test_all ${SM2ECQV_TEST_SRCS})
target_link_libraries(test_all PRIVATE sm2ecqv)

enable_testing()
add_test(NAME unit_tests COMMAND test_all)
