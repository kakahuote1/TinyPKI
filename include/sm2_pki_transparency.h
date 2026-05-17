/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_transparency.h
 * @brief Issuance transparency evidence and witness policy types.
 */

#ifndef SM2_PKI_TRANSPARENCY_H
#define SM2_PKI_TRANSPARENCY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sm2_implicit_cert.h"
#include "sm2_pki_types.h"
#include "sm2_revocation.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_PKI_TRANSPARENCY_MAX_WITNESSES 8
#define SM2_PKI_TRANSPARENCY_WITNESS_ID_MAX_LEN 32
#define SM2_PKI_ISSUANCE_COMMITMENT_LEN SM2_REV_MERKLE_HASH_LEN
#define SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH 64
#define SM2_PKI_ISSUANCE_MAX_PEAKS 64
#define SM2_PKI_EPOCH_ROOT_DIGEST_LEN SM2_REV_MERKLE_HASH_LEN
#define SM2_PKI_POLICY_DIGEST_LEN SM2_PKI_EPOCH_ROOT_DIGEST_LEN
#define SM2_PKI_DEFAULT_WITNESS_POLICY_VERSION 1U
#define SM2_PKI_DEFAULT_SYNC_POLICY_VERSION 1U
#define SM2_PKI_WITNESS_KEY_DEFAULT_VERSION 1U
#define SM2_PKI_WITNESS_KEY_VALID_UNTIL_OPEN UINT64_MAX

    typedef uint8_t
        sm2_pki_issuance_commitment_t[SM2_PKI_ISSUANCE_COMMITMENT_LEN];

    /* Unified system-state root for roots and policy digests. */
    typedef struct
    {
        uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
        size_t authority_id_len;
        uint64_t epoch_version;
        uint64_t revocation_root_version;
        uint8_t revocation_root_hash[SM2_REV_MERKLE_HASH_LEN];
        uint64_t issuance_root_version;
        uint8_t issuance_root_hash[SM2_REV_MERKLE_HASH_LEN];
        uint64_t witness_policy_version;
        uint8_t witness_policy_hash[SM2_PKI_POLICY_DIGEST_LEN];
        uint64_t sync_policy_version;
        uint8_t sync_policy_hash[SM2_PKI_POLICY_DIGEST_LEN];
        uint64_t valid_from;
        uint64_t valid_until;
        uint8_t signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t signature_len;
    } sm2_pki_epoch_root_record_t;

    typedef struct
    {
        uint8_t witness_id[SM2_PKI_TRANSPARENCY_WITNESS_ID_MAX_LEN];
        size_t witness_id_len;
        uint64_t key_version;
        uint64_t valid_from;
        uint64_t valid_until;
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
        size_t peak_index;
        size_t peak_count;
        uint8_t peak_hashes[SM2_PKI_ISSUANCE_MAX_PEAKS]
                           [SM2_REV_MERKLE_HASH_LEN];
    } sm2_pki_issuance_member_proof_t;

    typedef struct
    {
        size_t leaf_count;
        size_t peak_count;
        uint8_t peak_heights[SM2_PKI_ISSUANCE_MAX_PEAKS];
        uint8_t peak_hashes[SM2_PKI_ISSUANCE_MAX_PEAKS]
                           [SM2_REV_MERKLE_HASH_LEN];
    } sm2_pki_issuance_frontier_t;

    typedef struct
    {
        bool initialized;
        bool has_authority;
        uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
        size_t authority_id_len;
        uint64_t latest_epoch_version;
        uint8_t latest_epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
        uint64_t latest_revocation_root_version;
        uint8_t latest_revocation_root_hash[SM2_REV_MERKLE_HASH_LEN];
        uint64_t latest_issuance_root_version;
        uint8_t latest_issuance_root_hash[SM2_REV_MERKLE_HASH_LEN];
        sm2_pki_issuance_frontier_t issuance_frontier;
    } sm2_pki_epoch_witness_state_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t epoch_version;
        uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
        bool proof_valid;
    } sm2_pki_epoch_root_vote_t;

    typedef struct
    {
        uint64_t selected_epoch_version;
        uint8_t selected_epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
        size_t unique_node_count;
        size_t valid_vote_count;
        size_t stale_vote_count;
        size_t conflict_vote_count;
        size_t threshold;
        bool quorum_met;
        bool fork_detected;
    } sm2_pki_epoch_quorum_result_t;

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_TRANSPARENCY_H */
