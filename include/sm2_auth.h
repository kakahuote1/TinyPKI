/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_auth.h
 * @brief High-throughput unified authentication based on SM2 implicit
 * certificates.
 */

#ifndef SM2_AUTH_H
#define SM2_AUTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_AUTH_MAX_SIG_DER_LEN 96
#define SM2_AUTH_AEAD_IV_LEN 12
#define SM2_AUTH_AEAD_TAG_LEN 16
#define SM2_AUTH_AEAD_TAG_MAX_LEN 16

    typedef struct
    {
        uint8_t der[SM2_AUTH_MAX_SIG_DER_LEN];
        size_t der_len;
    } sm2_auth_signature_t;

    typedef enum
    {
        SM2_AUTH_AEAD_MODE_SM4_GCM = 1,
        SM2_AUTH_AEAD_MODE_SM4_CCM = 2
    } sm2_auth_aead_mode_t;

#ifdef __cplusplus
}
#endif

#endif /* SM2_AUTH_H */
