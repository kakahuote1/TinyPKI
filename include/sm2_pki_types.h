/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_types.h
 * @brief Shared public TinyPKI error and AEAD types.
 */

#ifndef SM2_PKI_TYPES_H
#define SM2_PKI_TYPES_H

#include "sm2_auth.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        SM2_PKI_SUCCESS = 0,
        SM2_PKI_ERR_PARAM = -100,
        SM2_PKI_ERR_MEMORY = -101,
        SM2_PKI_ERR_CRYPTO = -102,
        SM2_PKI_ERR_VERIFY = -103,
        SM2_PKI_ERR_STATE = -104,
        SM2_PKI_ERR_NOT_FOUND = -105,
        SM2_PKI_ERR_CONFLICT = -106
    } sm2_pki_error_t;

    typedef sm2_auth_aead_mode_t sm2_pki_aead_mode_t;

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_TYPES_H */
