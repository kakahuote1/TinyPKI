/* SPDX-License-Identifier: Apache-2.0 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/evp.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include "sm2_implicit_cert.h"
#include "sm2_revocation.h"
#include "sm2_auth.h"
#include "sm2_pki_types.h"
#include "sm2_pki_service.h"
#include "sm2_pki_client.h"
#include "../src/pki/pki_internal.h"

extern int g_tests_run;
extern int g_tests_passed;
extern int g_tests_failed;

extern sm2_private_key_t g_ca_priv;
extern sm2_ec_point_t g_ca_pub;
extern int g_ca_initialized;

#define TEST_ASSERT(condition, msg)                                            \
    do                                                                         \
    {                                                                          \
        if (!(condition))                                                      \
        {                                                                      \
            printf("\033[31m[FAIL] %s: %s\033[0m\n", __func__, msg);           \
            g_tests_failed++;                                                  \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TEST_PASS()                                                            \
    do                                                                         \
    {                                                                          \
        printf("\033[32m[PASS] %s\033[0m\n", __func__);                        \
        g_tests_passed++;                                                      \
    } while (0)

#define RUN_TEST(test_func)                                                    \
    do                                                                         \
    {                                                                          \
        g_tests_run++;                                                         \
        test_func();                                                           \
    } while (0)

double now_ms_highres(void);
double calc_p95_ms(double *samples, size_t count);
double calc_median_value(double *samples, size_t count);
uint64_t test_now_unix(void);
uint64_t test_cert_now(const sm2_implicit_cert_t *cert);
uint64_t test_cert_pair_now(
    const sm2_implicit_cert_t *cert_a, const sm2_implicit_cert_t *cert_b);
int test_benchmarks_enabled(void);
int test_generate_sm2_keypair(
    sm2_private_key_t *private_key, sm2_ec_point_t *public_key);

static inline sm2_ic_error_t test_issue_cert(sm2_ic_cert_result_t *result,
    const sm2_ic_cert_request_t *request, const uint8_t *issuer_id,
    size_t issuer_id_len, const sm2_private_key_t *ca_private_key,
    const sm2_ec_point_t *ca_public_key)
{
    return sm2_ic_ca_generate_cert(result, request, issuer_id, issuer_id_len,
        ca_private_key, ca_public_key, test_now_unix());
}

static inline sm2_ic_error_t test_issue_cert_with_ctx(
    sm2_ic_cert_result_t *result, const sm2_ic_cert_request_t *request,
    const uint8_t *issuer_id, size_t issuer_id_len,
    const sm2_private_key_t *ca_private_key,
    const sm2_ec_point_t *ca_public_key, const sm2_ic_issue_ctx_t *issue_ctx)
{
    return sm2_ic_ca_generate_cert_with_ctx(result, request, issuer_id,
        issuer_id_len, ca_private_key, ca_public_key, issue_ctx,
        test_now_unix());
}

static inline sm2_pki_error_t test_pki_issue_cert(sm2_pki_service_ctx_t *ctx,
    const sm2_ic_cert_request_t *request, sm2_ic_cert_result_t *result)
{
    return sm2_pki_cert_issue(ctx, request, test_now_unix(), result);
}

static inline int test_openssl_cipher_available(const char *name)
{
#if OPENSSL_VERSION_MAJOR >= 3
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, NULL);
    if (!cipher)
        return 0;
    EVP_CIPHER_free(cipher);
    return 1;
#else
    return EVP_get_cipherbyname(name) != NULL;
#endif
}

void test_setup_ca(void);
int run_named_test_suite(const char *title, void (*run_suite)(void));

void run_test_ecqv_suite(void);
void run_test_revoke_suite(void);
void run_test_auth_suite(void);
void run_test_pki_suite(void);
void run_test_pki_internal_suite(void);
void run_test_merkle_suite(void);

#endif
