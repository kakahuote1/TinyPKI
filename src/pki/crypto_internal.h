/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2_PKI_CRYPTO_INTERNAL_H
#define SM2_PKI_CRYPTO_INTERNAL_H

#include "sm2_pki_types.h"
#include "sm2_implicit_cert.h"

sm2_pki_error_t sm2_pki_error_from_ic(sm2_ic_error_t err);

sm2_pki_error_t sm2_pki_random(uint8_t *buf, size_t len);
sm2_pki_error_t sm2_pki_sm3_hash(
    const uint8_t *input, size_t input_len, uint8_t output[SM3_DIGEST_LENGTH]);

sm2_pki_error_t sm2_crypto_sign(const sm2_private_key_t *private_key,
    const uint8_t *message, size_t message_len,
    sm2_auth_signature_t *signature);

sm2_pki_error_t sm2_crypto_verify(const sm2_ec_point_t *public_key,
    const uint8_t *message, size_t message_len,
    const sm2_auth_signature_t *signature);

sm2_pki_error_t sm2_pki_aead_encrypt(sm2_pki_aead_mode_t mode,
    const uint8_t key[16], const uint8_t *iv, size_t iv_len, const uint8_t *aad,
    size_t aad_len, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len, uint8_t *tag, size_t *tag_len);

sm2_pki_error_t sm2_pki_aead_decrypt(sm2_pki_aead_mode_t mode,
    const uint8_t key[16], const uint8_t *iv, size_t iv_len, const uint8_t *aad,
    size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag, size_t tag_len, uint8_t *plaintext,
    size_t *plaintext_len);

#endif /* SM2_PKI_CRYPTO_INTERNAL_H */
