/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle_internal.h
 * @brief Internal shared declarations for Merkle accumulator sub-modules.
 *
 * This header is included by merkle.c, merkle_cbor.c and merkle_epoch.c.
 * It is NOT part of the public API.
 */

#ifndef SM2_MERKLE_INTERNAL_H
#define SM2_MERKLE_INTERNAL_H

#include "revoke_internal.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef SM2_REVOKE_INTERNAL_TYPEDEFS
#define SM2_REVOKE_INTERNAL_TYPEDEFS
    typedef struct sm2_rev_tree_st sm2_rev_tree_t;
    typedef struct sm2_rev_multi_proof_st sm2_rev_multi_proof_t;
    typedef struct sm2_rev_epoch_dir_st sm2_rev_epoch_dir_t;
#endif

#ifndef SM2_REVOKE_LOOKUP_CTX_TYPEDEF
#define SM2_REVOKE_LOOKUP_CTX_TYPEDEF
    typedef struct
    {
        const sm2_rev_epoch_dir_t *directory;
        sm2_ic_error_t (*verify_fn)(void *user_ctx, const uint8_t *data,
            size_t data_len, const uint8_t *signature, size_t signature_len);
        void *verify_user_ctx;
    } sm2_rev_lookup_ctx_t;
#endif

    struct sm2_rev_tree_st
    {
        uint64_t root_version;
        size_t leaf_count;
        struct sm2_rev_sparse_node_st *root;
        struct sm2_rev_sparse_node_st *free_nodes;
        struct sm2_rev_sparse_pool_block_st *node_pool_blocks;
        size_t node_pool_live_count;
        size_t node_pool_peak_live_count;
        uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    };

    struct sm2_rev_multi_proof_st
    {
        size_t query_count;
        sm2_rev_multi_item_t *items;
        size_t unique_hash_count;
        uint8_t (*unique_hashes)[SM2_REV_MERKLE_HASH_LEN];
    };

    struct sm2_rev_epoch_dir_st
    {
        uint64_t epoch_id;
        sm2_rev_root_record_t root_record;
        size_t tree_level_count;
        uint64_t patch_version;
        sm2_rev_delta_item_t *patch_items;
        size_t patch_item_count;
        uint8_t directory_signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t directory_signature_len;
    };

    typedef struct
    {
        size_t node_alloc_count;
        size_t node_free_count;
        size_t node_pool_block_alloc_count;
        size_t root_refresh_count;
        size_t root_refresh_node_visit_count;
    } sm2_rev_tree_debug_stats_t;

    /* ---- hash primitives (domain-separated SM3) ---- */
    void merkle_u64_to_be(uint64_t v, uint8_t out[8]);

    sm2_ic_error_t merkle_serial_key(
        uint64_t serial_number, uint8_t out_key[SM2_REV_MERKLE_HASH_LEN]);

    sm2_ic_error_t merkle_hash_leaf(uint64_t serial_number,
        const uint8_t key[SM2_REV_MERKLE_HASH_LEN],
        uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN]);

    sm2_ic_error_t merkle_tree_update_serial(
        sm2_rev_tree_t *tree, uint64_t serial, bool revoked);
    void merkle_tree_set_root_version(sm2_rev_tree_t *tree, uint64_t version);
    sm2_ic_error_t merkle_tree_clone(
        const sm2_rev_tree_t *src, sm2_rev_tree_t **dst);
    void merkle_tree_debug_stats_reset(void);
    void merkle_tree_debug_stats_get(sm2_rev_tree_debug_stats_t *stats);

    /* ---- sort comparators ---- */
    int merkle_cmp_u64(const void *a, const void *b);
    int merkle_cmp_delta_item(const void *a, const void *b);

    /* ---- CBOR primitives ---- */
    sm2_ic_error_t cbor_put_type_value(uint8_t major, uint64_t value,
        uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_type_value(const uint8_t *in, size_t in_len,
        size_t *offset, uint8_t *major, uint64_t *value);

    sm2_ic_error_t cbor_put_bytes(const uint8_t *data, size_t data_len,
        uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_bytes(const uint8_t *in, size_t in_len,
        size_t *offset, uint8_t *out, size_t out_len, size_t *actual_len);

    sm2_ic_error_t cbor_put_bool(
        bool value, uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_bool(
        const uint8_t *in, size_t in_len, size_t *offset, bool *value);

    sm2_ic_error_t cbor_put_null(uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_null(
        const uint8_t *in, size_t in_len, size_t *offset);

    sm2_ic_error_t cbor_get_bytes_alloc(const uint8_t *in, size_t in_len,
        size_t *offset, uint8_t **out, size_t *out_len);

    /* ---- CBOR member proof inner encode/decode ---- */
    sm2_ic_error_t cbor_encode_member_proof_inner(
        const sm2_rev_member_proof_t *proof, uint8_t *output, size_t output_cap,
        size_t *offset);

    sm2_ic_error_t cbor_decode_member_proof_inner(sm2_rev_member_proof_t *proof,
        const uint8_t *input, size_t input_len, size_t *offset);

    /* ---- multiproof helpers ---- */
    sm2_ic_error_t multiproof_reserve_unique_hashes(
        sm2_rev_multi_proof_t *proof, size_t *capacity, size_t required,
        size_t hard_limit);

    sm2_ic_error_t multiproof_find_or_add_hash(sm2_rev_multi_proof_t *proof,
        const uint8_t hash[SM2_REV_MERKLE_HASH_LEN], size_t *capacity,
        size_t hard_limit, uint16_t *out_ref);

    sm2_ic_error_t multiproof_expand_member(const sm2_rev_multi_proof_t *proof,
        const sm2_rev_multi_item_t *item, sm2_rev_member_proof_t *member);

    size_t multiproof_next_pow2(size_t v);

    /* ---- epoch directory auth ---- */
    sm2_ic_error_t merkle_serialize_root_for_auth(
        const sm2_rev_root_record_t *root_record, uint8_t *output,
        size_t output_cap, size_t *output_len);

    sm2_ic_error_t merkle_epoch_serialize_for_auth(
        const sm2_rev_epoch_dir_t *directory, uint8_t *output,
        size_t output_cap, size_t *output_len);

    sm2_ic_error_t merkle_calc_patch_digest(const sm2_rev_delta_item_t *items,
        size_t item_count, uint8_t out_digest[SM2_REV_MERKLE_HASH_LEN]);

    bool merkle_epoch_patch_lookup(
        const sm2_rev_epoch_dir_t *directory, uint64_t serial, bool *revoked);

    sm2_ic_error_t merkle_epoch_directory_clone(
        sm2_rev_epoch_dir_t *dst, const sm2_rev_epoch_dir_t *src);

#ifdef __cplusplus
}
#endif

#endif /* SM2_MERKLE_INTERNAL_H */
