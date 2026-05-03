/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_transparency.h
 * @brief Issuance transparency evidence and witness policy types.
 */

#ifndef SM2_PKI_TRANSPARENCY_H
#define SM2_PKI_TRANSPARENCY_H

#include <stddef.h>
#include <stdint.h>
#include "sm2_crypto.h"
#include "sm2_revocation.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_PKI_TRANSPARENCY_MAX_WITNESSES 8
#define SM2_PKI_TRANSPARENCY_WITNESS_ID_MAX_LEN 32
#define SM2_PKI_ISSUANCE_COMMITMENT_LEN SM2_REV_MERKLE_HASH_LEN
#define SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH SM2_REV_MERKLE_MAX_DEPTH

    typedef struct
    {
        uint8_t witness_id[SM2_PKI_TRANSPARENCY_WITNESS_ID_MAX_LEN];
        size_t witness_id_len;
        sm2_ec_point_t public_key;
    } sm2_pki_transparency_witness_t;

    typedef struct
    {
        uint8_t witness_id[SM2_PKI_TRANSPARENCY_WITNESS_ID_MAX_LEN];
        size_t witness_id_len;
        uint8_t signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t signature_len;
    } sm2_pki_transparency_witness_signature_t;

    typedef struct
    {
        const sm2_pki_transparency_witness_t *witnesses;
        size_t witness_count;
        size_t threshold;
    } sm2_pki_transparency_policy_t;

    typedef struct
    {
        uint8_t cert_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
        size_t leaf_index;
        size_t leaf_count;
        size_t sibling_count;
        uint8_t sibling_hashes[SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH]
                              [SM2_REV_MERKLE_HASH_LEN];
        uint8_t sibling_on_left[SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH];
    } sm2_pki_issuance_member_proof_t;

    typedef struct
    {
        sm2_rev_root_record_t root_record;
        sm2_pki_issuance_member_proof_t member_proof;
        sm2_pki_transparency_witness_signature_t
            witness_signatures[SM2_PKI_TRANSPARENCY_MAX_WITNESSES];
        size_t witness_signature_count;
    } sm2_pki_issuance_evidence_t;

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_TRANSPARENCY_H */
