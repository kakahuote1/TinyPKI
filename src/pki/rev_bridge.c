/* SPDX-License-Identifier: Apache-2.0 */

#include "pki_internal.h"
#include "../revoke/revoke_internal.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define SM2_PKI_ISSUANCE_CERT_ENCODE_MAX 1024U

static void pki_issuance_u64_to_be(uint64_t v, uint8_t out[8]);

sm2_ic_error_t sm2_pki_rev_snapshot_create(
    const sm2_rev_ctx_t *src, sm2_rev_ctx_t **snapshot)
{
    if (!snapshot)
        return SM2_IC_ERR_PARAM;

    *snapshot = NULL;
    sm2_rev_ctx_t *state = (sm2_rev_ctx_t *)calloc(1, sizeof(*state));
    if (!state)
        return SM2_IC_ERR_MEMORY;

    sm2_ic_error_t ret = sm2_rev_internal_snapshot_create(src, state);
    if (ret != SM2_IC_SUCCESS)
    {
        free(state);
        return ret;
    }

    *snapshot = state;
    return SM2_IC_SUCCESS;
}

void sm2_pki_rev_snapshot_release(sm2_rev_ctx_t **snapshot)
{
    if (!snapshot || !*snapshot)
        return;
    sm2_rev_internal_snapshot_release(*snapshot);
    free(*snapshot);
    *snapshot = NULL;
}

void sm2_pki_rev_snapshot_restore(sm2_rev_ctx_t *dst, sm2_rev_ctx_t **snapshot)
{
    if (!snapshot || !*snapshot)
        return;
    sm2_rev_internal_snapshot_restore(dst, *snapshot);
    free(*snapshot);
    *snapshot = NULL;
}

sm2_ic_error_t sm2_pki_rev_prepare_root_publication(const sm2_rev_ctx_t *ctx,
    uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    const uint8_t *authority_id, size_t authority_id_len, sm2_rev_tree_t **tree,
    sm2_rev_root_record_t *root_record, uint64_t *root_valid_until)
{
    return sm2_rev_internal_prepare_root_publication(ctx, now_ts, sign_fn,
        sign_user_ctx, authority_id, authority_id_len, tree, root_record,
        root_valid_until);
}

void sm2_pki_rev_set_root_valid_until(
    sm2_rev_ctx_t *ctx, uint64_t root_valid_until)
{
    sm2_rev_internal_set_root_valid_until(ctx, root_valid_until);
}

static sm2_ic_error_t pki_issuance_serialize_root_for_auth(
    const sm2_rev_root_record_t *root_record, uint8_t *output,
    size_t output_cap, size_t *output_len)
{
    static const uint8_t tag[] = "SM2PKI_ISSUANCE_ROOT_V1";
    size_t need = (sizeof(tag) - 1U) + 8U + SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN
        + 8U + SM2_REV_MERKLE_HASH_LEN + 8U + 8U;

    if (!root_record || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (root_record->authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
        return SM2_IC_ERR_PARAM;
    if (output_cap < need)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    memcpy(output + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;

    pki_issuance_u64_to_be(
        (uint64_t)root_record->authority_id_len, output + off);
    off += 8U;
    memcpy(
        output + off, root_record->authority_id, root_record->authority_id_len);
    off += root_record->authority_id_len;

    pki_issuance_u64_to_be(root_record->root_version, output + off);
    off += 8U;

    memcpy(output + off, root_record->root_hash, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;

    pki_issuance_u64_to_be(root_record->valid_from, output + off);
    off += 8U;

    pki_issuance_u64_to_be(root_record->valid_until, output + off);
    off += 8U;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_root_record_sign_hash(const uint8_t *authority_id,
    size_t authority_id_len, uint64_t root_version,
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN], uint64_t valid_from,
    uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_root_record_t *root_record)
{
    if (!root_hash || !sign_fn || !root_record)
        return SM2_IC_ERR_PARAM;
    if ((!authority_id && authority_id_len > 0)
        || authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (valid_until < valid_from)
        return SM2_IC_ERR_PARAM;

    memset(root_record, 0, sizeof(*root_record));
    if (authority_id_len > 0)
    {
        memcpy(root_record->authority_id, authority_id, authority_id_len);
        root_record->authority_id_len = authority_id_len;
    }
    root_record->root_version = root_version;
    memcpy(root_record->root_hash, root_hash, SM2_REV_MERKLE_HASH_LEN);
    root_record->valid_from = valid_from;
    root_record->valid_until = valid_until;

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = pki_issuance_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t sig_len = sizeof(root_record->signature);
    ret = sign_fn(
        sign_user_ctx, auth_buf, auth_len, root_record->signature, &sig_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (sig_len == 0 || sig_len > sizeof(root_record->signature))
        return SM2_IC_ERR_VERIFY;

    root_record->signature_len = sig_len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_issuance_root_verify(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!root_record || !verify_fn)
        return SM2_IC_ERR_PARAM;
    if (root_record->authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
        return SM2_IC_ERR_VERIFY;
    if (root_record->signature_len == 0
        || root_record->signature_len > sizeof(root_record->signature))
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (root_record->valid_until < root_record->valid_from)
        return SM2_IC_ERR_VERIFY;
    if (now_ts < root_record->valid_from || now_ts > root_record->valid_until)
        return SM2_IC_ERR_VERIFY;

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = pki_issuance_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = verify_fn(verify_user_ctx, auth_buf, auth_len, root_record->signature,
        root_record->signature_len);
    return ret == SM2_IC_SUCCESS ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_pki_issuance_cert_commitment(
    const sm2_implicit_cert_t *cert,
    uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN])
{
    uint8_t cert_buf[SM2_PKI_ISSUANCE_CERT_ENCODE_MAX];
    size_t cert_len = sizeof(cert_buf);

    if (!cert || !commitment)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_ic_cbor_encode_cert(cert_buf, &cert_len, cert);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = sm2_ic_sm3_hash(cert_buf, cert_len, commitment);
    memset(cert_buf, 0, sizeof(cert_buf));
    return ret;
}

sm2_ic_error_t sm2_pki_issuance_leaf_key(
    const sm2_implicit_cert_t *cert, uint64_t *leaf_key)
{
    uint8_t digest[SM2_PKI_ISSUANCE_COMMITMENT_LEN];

    if (!cert || !leaf_key)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_pki_issuance_cert_commitment(cert, digest);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *leaf_key = ((uint64_t)digest[0] << 56) | ((uint64_t)digest[1] << 48)
        | ((uint64_t)digest[2] << 40) | ((uint64_t)digest[3] << 32)
        | ((uint64_t)digest[4] << 24) | ((uint64_t)digest[5] << 16)
        | ((uint64_t)digest[6] << 8) | (uint64_t)digest[7];
    memset(digest, 0, sizeof(digest));
    return SM2_IC_SUCCESS;
}

struct sm2_pki_issuance_tree_st
{
    uint64_t root_version;
    size_t leaf_count;
    uint8_t (*commitments)[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    size_t level_count;
    size_t level_offsets[SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH];
    size_t level_sizes[SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH];
    uint8_t *node_hashes;
    size_t node_hashes_len;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
};

static void pki_issuance_u64_to_be(uint64_t v, uint8_t out[8])
{
    for (int i = 0; i < 8; i++)
        out[7 - i] = (uint8_t)((v >> (i * 8)) & 0xFFU);
}

static void pki_issuance_tree_reset(sm2_pki_issuance_tree_t *tree)
{
    if (!tree)
        return;
    free(tree->commitments);
    free(tree->node_hashes);
    memset(tree, 0, sizeof(*tree));
}

void sm2_pki_issuance_tree_cleanup(sm2_pki_issuance_tree_t **tree)
{
    if (!tree || !*tree)
        return;
    pki_issuance_tree_reset(*tree);
    free(*tree);
    *tree = NULL;
}

static sm2_ic_error_t pki_issuance_hash_empty(
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    static const uint8_t marker[] = "SM2PKI_ISSUANCE_EMPTY_V1";
    return sm2_ic_sm3_hash(marker, sizeof(marker) - 1U, out_hash);
}

static sm2_ic_error_t pki_issuance_hash_leaf(
    const uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    size_t leaf_index, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    uint8_t buf[1U + 8U + SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    if (!commitment || !out_hash)
        return SM2_IC_ERR_PARAM;
    buf[0] = 0x40U;
    pki_issuance_u64_to_be((uint64_t)leaf_index, buf + 1);
    memcpy(buf + 9, commitment, SM2_PKI_ISSUANCE_COMMITMENT_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

static sm2_ic_error_t pki_issuance_hash_parent(
    const uint8_t left[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t right[SM2_REV_MERKLE_HASH_LEN],
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    uint8_t buf[1U + SM2_REV_MERKLE_HASH_LEN * 2U];
    if (!left || !right || !out_hash)
        return SM2_IC_ERR_PARAM;
    buf[0] = 0x41U;
    memcpy(buf + 1, left, SM2_REV_MERKLE_HASH_LEN);
    memcpy(buf + 1 + SM2_REV_MERKLE_HASH_LEN, right,
        SM2_REV_MERKLE_HASH_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

static sm2_ic_error_t pki_issuance_calc_layout(
    sm2_pki_issuance_tree_t *tree, size_t leaf_count, size_t *out_total_nodes)
{
    size_t level = 0;
    size_t n = leaf_count;
    size_t total_nodes = 0;

    if (!tree || !out_total_nodes || leaf_count == 0)
        return SM2_IC_ERR_PARAM;

    while (true)
    {
        if (level >= SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH)
            return SM2_IC_ERR_PARAM;

        tree->level_sizes[level] = n;
        tree->level_offsets[level] = total_nodes;
        if (total_nodes > SIZE_MAX - n)
            return SM2_IC_ERR_MEMORY;
        total_nodes += n;

        level++;
        if (n == 1)
            break;
        n = (n + 1U) / 2U;
    }

    tree->level_count = level;
    *out_total_nodes = total_nodes;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_issuance_tree_build(sm2_pki_issuance_tree_t **tree,
    const uint8_t (*commitments)[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    size_t commitment_count, uint64_t root_version)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    if (commitment_count > 0 && !commitments)
        return SM2_IC_ERR_PARAM;
    if (!*tree)
    {
        *tree = (sm2_pki_issuance_tree_t *)calloc(1, sizeof(**tree));
        if (!*tree)
            return SM2_IC_ERR_MEMORY;
    }

    sm2_pki_issuance_tree_t *state = *tree;
    pki_issuance_tree_reset(state);
    state->root_version = root_version;

    if (commitment_count == 0)
    {
        state->leaf_count = 0;
        state->level_count = 1;
        state->level_sizes[0] = 1;
        state->level_offsets[0] = 0;
        state->node_hashes_len = SM2_REV_MERKLE_HASH_LEN;
        state->node_hashes = (uint8_t *)calloc(1, state->node_hashes_len);
        if (!state->node_hashes)
            return SM2_IC_ERR_MEMORY;
        sm2_ic_error_t ret = pki_issuance_hash_empty(state->node_hashes);
        if (ret != SM2_IC_SUCCESS)
        {
            pki_issuance_tree_reset(state);
            return ret;
        }
        memcpy(state->root_hash, state->node_hashes, SM2_REV_MERKLE_HASH_LEN);
        return SM2_IC_SUCCESS;
    }

    if (commitment_count > SIZE_MAX / sizeof(*state->commitments))
        return SM2_IC_ERR_MEMORY;
    state->commitments
        = (uint8_t (*)[SM2_PKI_ISSUANCE_COMMITMENT_LEN])malloc(
            commitment_count * sizeof(*state->commitments));
    if (!state->commitments)
        return SM2_IC_ERR_MEMORY;
    memcpy(state->commitments, commitments,
        commitment_count * sizeof(*state->commitments));
    state->leaf_count = commitment_count;

    size_t total_nodes = 0;
    sm2_ic_error_t ret
        = pki_issuance_calc_layout(state, commitment_count, &total_nodes);
    if (ret != SM2_IC_SUCCESS)
    {
        pki_issuance_tree_reset(state);
        return ret;
    }
    if (total_nodes > SIZE_MAX / SM2_REV_MERKLE_HASH_LEN)
    {
        pki_issuance_tree_reset(state);
        return SM2_IC_ERR_MEMORY;
    }

    state->node_hashes_len = total_nodes * SM2_REV_MERKLE_HASH_LEN;
    state->node_hashes = (uint8_t *)calloc(1, state->node_hashes_len);
    if (!state->node_hashes)
    {
        pki_issuance_tree_reset(state);
        return SM2_IC_ERR_MEMORY;
    }

    size_t leaf_off = state->level_offsets[0];
    for (size_t i = 0; i < state->leaf_count; i++)
    {
        uint8_t *dst
            = state->node_hashes + (leaf_off + i) * SM2_REV_MERKLE_HASH_LEN;
        ret = pki_issuance_hash_leaf(state->commitments[i], i, dst);
        if (ret != SM2_IC_SUCCESS)
        {
            pki_issuance_tree_reset(state);
            return ret;
        }
    }

    for (size_t level = 0; level + 1 < state->level_count; level++)
    {
        size_t curr_count = state->level_sizes[level];
        size_t next_count = state->level_sizes[level + 1];
        size_t curr_off = state->level_offsets[level];
        size_t next_off = state->level_offsets[level + 1];

        for (size_t i = 0; i < next_count; i++)
        {
            size_t left_idx = i * 2U;
            size_t right_idx = left_idx + 1U;
            if (right_idx >= curr_count)
                right_idx = left_idx;

            const uint8_t *left = state->node_hashes
                + (curr_off + left_idx) * SM2_REV_MERKLE_HASH_LEN;
            const uint8_t *right = state->node_hashes
                + (curr_off + right_idx) * SM2_REV_MERKLE_HASH_LEN;
            uint8_t *dst
                = state->node_hashes + (next_off + i) * SM2_REV_MERKLE_HASH_LEN;

            ret = pki_issuance_hash_parent(left, right, dst);
            if (ret != SM2_IC_SUCCESS)
            {
                pki_issuance_tree_reset(state);
                return ret;
            }
        }
    }

    size_t root_off = state->level_offsets[state->level_count - 1];
    memcpy(state->root_hash,
        state->node_hashes + root_off * SM2_REV_MERKLE_HASH_LEN,
        SM2_REV_MERKLE_HASH_LEN);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_issuance_tree_get_root_hash(
    const sm2_pki_issuance_tree_t *tree,
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN])
{
    if (!tree || !root_hash || !tree->node_hashes)
        return SM2_IC_ERR_PARAM;
    memcpy(root_hash, tree->root_hash, SM2_REV_MERKLE_HASH_LEN);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_issuance_tree_prove_member(
    const sm2_pki_issuance_tree_t *tree,
    const uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    sm2_pki_issuance_member_proof_t *proof)
{
    if (!tree || !commitment || !proof || !tree->node_hashes
        || tree->level_count == 0)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (tree->leaf_count == 0)
        return SM2_IC_ERR_VERIFY;

    size_t index = SIZE_MAX;
    for (size_t i = 0; i < tree->leaf_count; i++)
    {
        if (memcmp(tree->commitments[i], commitment,
                SM2_PKI_ISSUANCE_COMMITMENT_LEN)
            == 0)
        {
            index = i;
            break;
        }
    }
    if (index == SIZE_MAX)
        return SM2_IC_ERR_VERIFY;

    memset(proof, 0, sizeof(*proof));
    memcpy(proof->cert_commitment, commitment,
        SM2_PKI_ISSUANCE_COMMITMENT_LEN);
    proof->leaf_index = index;
    proof->leaf_count = tree->leaf_count;
    proof->sibling_count = tree->level_count - 1;

    size_t cur = index;
    for (size_t level = 0; level + 1 < tree->level_count; level++)
    {
        size_t level_count = tree->level_sizes[level];
        size_t level_off = tree->level_offsets[level];
        size_t sibling = (cur % 2U == 0) ? (cur + 1U) : (cur - 1U);
        if (sibling >= level_count)
            sibling = cur;

        const uint8_t *src = tree->node_hashes
            + (level_off + sibling) * SM2_REV_MERKLE_HASH_LEN;
        memcpy(proof->sibling_hashes[level], src, SM2_REV_MERKLE_HASH_LEN);
        proof->sibling_on_left[level] = sibling < cur ? 1U : 0U;
        cur /= 2U;
    }
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t pki_issuance_validate_member_shape(
    const sm2_pki_issuance_member_proof_t *proof)
{
    if (!proof || proof->leaf_count == 0
        || proof->leaf_index >= proof->leaf_count)
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (proof->sibling_count >= SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH)
        return SM2_IC_ERR_VERIFY;

    size_t expected = 0;
    size_t n = proof->leaf_count;
    while (n > 1)
    {
        if (expected >= SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH)
            return SM2_IC_ERR_VERIFY;
        expected++;
        n = (n + 1U) / 2U;
    }
    return proof->sibling_count == expected ? SM2_IC_SUCCESS
                                            : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_pki_issuance_tree_verify_member(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_pki_issuance_member_proof_t *proof)
{
    if (!root_hash || !proof)
        return SM2_IC_ERR_PARAM;
    sm2_ic_error_t ret = pki_issuance_validate_member_shape(proof);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint8_t cur[SM2_REV_MERKLE_HASH_LEN];
    uint8_t next[SM2_REV_MERKLE_HASH_LEN];
    ret = pki_issuance_hash_leaf(
        proof->cert_commitment, proof->leaf_index, cur);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t path_index = proof->leaf_index;
    size_t level_count = proof->leaf_count;
    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        size_t sibling
            = (path_index % 2U == 0) ? (path_index + 1U) : (path_index - 1U);
        if (sibling >= level_count)
            sibling = path_index;
        uint8_t expected_on_left = sibling < path_index ? 1U : 0U;
        if ((proof->sibling_on_left[i] ? 1U : 0U) != expected_on_left)
            return SM2_IC_ERR_VERIFY;

        if (proof->sibling_on_left[i])
            ret = pki_issuance_hash_parent(
                proof->sibling_hashes[i], cur, next);
        else
            ret = pki_issuance_hash_parent(
                cur, proof->sibling_hashes[i], next);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        memcpy(cur, next, SM2_REV_MERKLE_HASH_LEN);
        path_index /= 2U;
        level_count = (level_count + 1U) / 2U;
    }

    return memcmp(cur, root_hash, SM2_REV_MERKLE_HASH_LEN) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}
