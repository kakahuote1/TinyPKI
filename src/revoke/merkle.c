/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle.c
 * @brief Core Merkle hash tree: build, prove, verify (member & absence).
 */

#include "merkle_internal.h"

static void rev_tree_reset(sm2_rev_tree_t *tree)
{
    if (!tree)
        return;

    free(tree->serials);
    free(tree->node_hashes);
    memset(tree, 0, sizeof(*tree));
}

int merkle_cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb)
        return -1;
    if (va > vb)
        return 1;
    return 0;
}

void merkle_u64_to_be(uint64_t v, uint8_t out[8])
{
    for (int i = 0; i < 8; i++)
        out[7 - i] = (uint8_t)((v >> (i * 8)) & 0xFFU);
}

sm2_ic_error_t merkle_hash_leaf(
    uint64_t serial_number, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    uint8_t buf[9];
    buf[0] = 0x00;
    merkle_u64_to_be(serial_number, buf + 1);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

sm2_ic_error_t merkle_hash_parent(const uint8_t left[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t right[SM2_REV_MERKLE_HASH_LEN],
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    uint8_t buf[1 + SM2_REV_MERKLE_HASH_LEN * 2];
    buf[0] = 0x01;
    memcpy(buf + 1, left, SM2_REV_MERKLE_HASH_LEN);
    memcpy(buf + 1 + SM2_REV_MERKLE_HASH_LEN, right, SM2_REV_MERKLE_HASH_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

sm2_ic_error_t merkle_hash_empty(uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    const uint8_t marker = 0xEE;
    return sm2_ic_sm3_hash(&marker, 1, out_hash);
}

void sm2_rev_tree_cleanup(sm2_rev_tree_t **tree)
{
    if (!tree || !*tree)
        return;
    rev_tree_reset(*tree);
    free(*tree);
    *tree = NULL;
}

sm2_ic_error_t merkle_calc_layout(
    sm2_rev_tree_t *tree, size_t leaf_count, size_t *out_total_nodes)
{
    size_t level = 0;
    size_t n = leaf_count;
    size_t total_nodes = 0;

    while (true)
    {
        if (level >= SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_PARAM;

        tree->level_sizes[level] = n;
        tree->level_offsets[level] = total_nodes;

        if (total_nodes > SIZE_MAX - n)
            return SM2_IC_ERR_MEMORY;
        total_nodes += n;

        level++;
        if (n == 1)
            break;
        n = (n + 1) / 2;
    }

    tree->level_count = level;
    *out_total_nodes = total_nodes;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_tree_build(sm2_rev_tree_t **tree,
    const uint64_t *revoked_serials, size_t revoked_count,
    uint64_t root_version)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    if (!*tree)
    {
        *tree = (sm2_rev_tree_t *)calloc(1, sizeof(**tree));
        if (!*tree)
            return SM2_IC_ERR_MEMORY;
    }
    sm2_rev_tree_t *state = *tree;
    if (revoked_count > 0 && !revoked_serials)
        return SM2_IC_ERR_PARAM;

    rev_tree_reset(state);

    state->root_version = root_version;

    if (revoked_count == 0)
    {
        state->leaf_count = 0;
        state->level_count = 1;
        state->level_sizes[0] = 1;
        state->level_offsets[0] = 0;
        state->node_hashes_len = SM2_REV_MERKLE_HASH_LEN;
        state->node_hashes = (uint8_t *)calloc(1, state->node_hashes_len);
        if (!state->node_hashes)
            return SM2_IC_ERR_MEMORY;

        sm2_ic_error_t ret = merkle_hash_empty(state->node_hashes);
        if (ret != SM2_IC_SUCCESS)
        {
            rev_tree_reset(state);
            return ret;
        }
        memcpy(state->root_hash, state->node_hashes, SM2_REV_MERKLE_HASH_LEN);
        return SM2_IC_SUCCESS;
    }

    uint64_t *tmp = (uint64_t *)malloc(revoked_count * sizeof(uint64_t));
    if (!tmp)
        return SM2_IC_ERR_MEMORY;
    memcpy(tmp, revoked_serials, revoked_count * sizeof(uint64_t));
    qsort(tmp, revoked_count, sizeof(uint64_t), merkle_cmp_u64);

    size_t uniq_count = 0;
    for (size_t i = 0; i < revoked_count; i++)
    {
        if (uniq_count == 0 || tmp[i] != tmp[uniq_count - 1])
            tmp[uniq_count++] = tmp[i];
    }

    state->serials = (uint64_t *)malloc(uniq_count * sizeof(uint64_t));
    if (!state->serials)
    {
        free(tmp);
        return SM2_IC_ERR_MEMORY;
    }
    memcpy(state->serials, tmp, uniq_count * sizeof(uint64_t));
    free(tmp);
    state->leaf_count = uniq_count;

    size_t total_nodes = 0;
    sm2_ic_error_t ret = merkle_calc_layout(state, uniq_count, &total_nodes);
    if (ret != SM2_IC_SUCCESS)
    {
        rev_tree_reset(state);
        return ret;
    }

    if (total_nodes > SIZE_MAX / SM2_REV_MERKLE_HASH_LEN)
    {
        rev_tree_reset(state);
        return SM2_IC_ERR_MEMORY;
    }

    state->node_hashes_len = total_nodes * SM2_REV_MERKLE_HASH_LEN;
    state->node_hashes = (uint8_t *)calloc(1, state->node_hashes_len);
    if (!state->node_hashes)
    {
        rev_tree_reset(state);
        return SM2_IC_ERR_MEMORY;
    }

    size_t leaf_off = state->level_offsets[0];
    for (size_t i = 0; i < state->leaf_count; i++)
    {
        uint8_t *dst
            = state->node_hashes + (leaf_off + i) * SM2_REV_MERKLE_HASH_LEN;
        ret = merkle_hash_leaf(state->serials[i], dst);
        if (ret != SM2_IC_SUCCESS)
        {
            rev_tree_reset(state);
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
            size_t left_idx = i * 2;
            size_t right_idx = left_idx + 1;
            if (right_idx >= curr_count)
                right_idx = left_idx;

            const uint8_t *left = state->node_hashes
                + (curr_off + left_idx) * SM2_REV_MERKLE_HASH_LEN;
            const uint8_t *right = state->node_hashes
                + (curr_off + right_idx) * SM2_REV_MERKLE_HASH_LEN;
            uint8_t *dst
                = state->node_hashes + (next_off + i) * SM2_REV_MERKLE_HASH_LEN;

            ret = merkle_hash_parent(left, right, dst);
            if (ret != SM2_IC_SUCCESS)
            {
                rev_tree_reset(state);
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

size_t sm2_rev_tree_leaf_count(const sm2_rev_tree_t *tree)
{
    return tree ? tree->leaf_count : 0;
}

uint64_t sm2_rev_tree_root_version(const sm2_rev_tree_t *tree)
{
    return tree ? tree->root_version : 0;
}

sm2_ic_error_t sm2_rev_tree_get_root_hash(
    const sm2_rev_tree_t *tree, uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN])
{
    if (!tree || !root_hash || !tree->node_hashes)
        return SM2_IC_ERR_PARAM;
    memcpy(root_hash, tree->root_hash, SM2_REV_MERKLE_HASH_LEN);
    return SM2_IC_SUCCESS;
}

bool merkle_find_serial(
    const sm2_rev_tree_t *tree, uint64_t serial, size_t *pos)
{
    size_t left = 0;
    size_t right = tree->leaf_count;

    while (left < right)
    {
        size_t mid = left + (right - left) / 2;
        uint64_t v = tree->serials[mid];
        if (v < serial)
            left = mid + 1;
        else
            right = mid;
    }

    *pos = left;
    return left < tree->leaf_count && tree->serials[left] == serial;
}

sm2_ic_error_t sm2_rev_tree_prove_member(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_member_proof_t *proof)
{
    if (!tree || !proof || !tree->node_hashes || tree->level_count == 0)
        return SM2_IC_ERR_PARAM;
    if (tree->leaf_count == 0)
        return SM2_IC_ERR_VERIFY;

    size_t index = 0;
    if (!merkle_find_serial(tree, serial_number, &index))
        return SM2_IC_ERR_VERIFY;

    memset(proof, 0, sizeof(*proof));
    proof->serial_number = serial_number;
    proof->leaf_index = index;
    proof->leaf_count = tree->leaf_count;
    proof->sibling_count = tree->level_count - 1;

    size_t cur = index;
    for (size_t level = 0; level + 1 < tree->level_count; level++)
    {
        size_t level_count = tree->level_sizes[level];
        size_t level_off = tree->level_offsets[level];

        size_t sibling = (cur % 2 == 0) ? (cur + 1) : (cur - 1);
        if (sibling >= level_count)
            sibling = cur;

        const uint8_t *src = tree->node_hashes
            + (level_off + sibling) * SM2_REV_MERKLE_HASH_LEN;
        memcpy(proof->sibling_hashes[level], src, SM2_REV_MERKLE_HASH_LEN);
        proof->sibling_on_left[level] = sibling < cur ? 1U : 0U;
        cur /= 2;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_tree_verify_member(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_member_proof_t *proof)
{
    if (!root_hash || !proof)
        return SM2_IC_ERR_PARAM;
    if (proof->leaf_count == 0 || proof->leaf_index >= proof->leaf_count)
        return SM2_IC_ERR_VERIFY;
    if (proof->sibling_count >= SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_VERIFY;

    uint8_t cur[SM2_REV_MERKLE_HASH_LEN];
    uint8_t next[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = merkle_hash_leaf(proof->serial_number, cur);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        if (proof->sibling_on_left[i])
            ret = merkle_hash_parent(proof->sibling_hashes[i], cur, next);
        else
            ret = merkle_hash_parent(cur, proof->sibling_hashes[i], next);

        if (ret != SM2_IC_SUCCESS)
            return ret;
        memcpy(cur, next, SM2_REV_MERKLE_HASH_LEN);
    }

    return memcmp(cur, root_hash, SM2_REV_MERKLE_HASH_LEN) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_rev_tree_prove_absence(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_absence_proof_t *proof)
{
    if (!tree || !proof || !tree->node_hashes || tree->level_count == 0)
        return SM2_IC_ERR_PARAM;

    memset(proof, 0, sizeof(*proof));
    proof->target_serial = serial_number;
    proof->leaf_count = tree->leaf_count;

    if (tree->leaf_count == 0)
        return SM2_IC_SUCCESS;

    size_t pos = 0;
    if (merkle_find_serial(tree, serial_number, &pos))
        return SM2_IC_ERR_VERIFY;

    if (pos > 0)
    {
        proof->has_left_neighbor = true;
        sm2_ic_error_t ret = sm2_rev_tree_prove_member(
            tree, tree->serials[pos - 1], &proof->left_proof);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    if (pos < tree->leaf_count)
    {
        proof->has_right_neighbor = true;
        sm2_ic_error_t ret = sm2_rev_tree_prove_member(
            tree, tree->serials[pos], &proof->right_proof);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_tree_verify_absence(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_absence_proof_t *proof)
{
    if (!root_hash || !proof)
        return SM2_IC_ERR_PARAM;

    if (!proof->has_left_neighbor && !proof->has_right_neighbor)
    {
        if (proof->leaf_count != 0)
            return SM2_IC_ERR_VERIFY;

        uint8_t empty_hash[SM2_REV_MERKLE_HASH_LEN];
        sm2_ic_error_t ret = merkle_hash_empty(empty_hash);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        return memcmp(root_hash, empty_hash, SM2_REV_MERKLE_HASH_LEN) == 0
            ? SM2_IC_SUCCESS
            : SM2_IC_ERR_VERIFY;
    }

    if (proof->leaf_count == 0)
        return SM2_IC_ERR_VERIFY;

    if (proof->has_left_neighbor)
    {
        if (proof->left_proof.leaf_count == 0
            || proof->left_proof.leaf_count != proof->leaf_count)
        {
            return SM2_IC_ERR_VERIFY;
        }
        sm2_ic_error_t ret
            = sm2_rev_tree_verify_member(root_hash, &proof->left_proof);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        if (proof->left_proof.serial_number >= proof->target_serial)
            return SM2_IC_ERR_VERIFY;
    }

    if (proof->has_right_neighbor)
    {
        if (proof->right_proof.leaf_count == 0
            || proof->right_proof.leaf_count != proof->leaf_count)
        {
            return SM2_IC_ERR_VERIFY;
        }
        sm2_ic_error_t ret
            = sm2_rev_tree_verify_member(root_hash, &proof->right_proof);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        if (proof->target_serial >= proof->right_proof.serial_number)
            return SM2_IC_ERR_VERIFY;
    }

    if (proof->has_left_neighbor && proof->has_right_neighbor)
    {
        if (proof->left_proof.leaf_count != proof->right_proof.leaf_count)
            return SM2_IC_ERR_VERIFY;
        if (proof->left_proof.leaf_index + 1 != proof->right_proof.leaf_index)
            return SM2_IC_ERR_VERIFY;
    }
    else if (proof->has_left_neighbor)
    {
        if (proof->left_proof.leaf_index + 1 != proof->leaf_count)
            return SM2_IC_ERR_VERIFY;
    }
    else
    {
        if (proof->right_proof.leaf_index != 0)
            return SM2_IC_ERR_VERIFY;
    }

    return SM2_IC_SUCCESS;
}
sm2_ic_error_t merkle_serialize_root_for_auth(
    const sm2_rev_root_record_t *root_record, uint8_t *output,
    size_t output_cap, size_t *output_len)
{
    static const uint8_t tag[] = "SM2REV_MERKLE_ROOT_V1";
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
    off += (sizeof(tag) - 1U);

    merkle_u64_to_be((uint64_t)root_record->authority_id_len, output + off);
    off += 8U;
    memcpy(
        output + off, root_record->authority_id, root_record->authority_id_len);
    off += root_record->authority_id_len;

    merkle_u64_to_be(root_record->root_version, output + off);
    off += 8U;

    memcpy(output + off, root_record->root_hash, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;

    merkle_u64_to_be(root_record->valid_from, output + off);
    off += 8U;

    merkle_u64_to_be(root_record->valid_until, output + off);
    off += 8U;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_root_sign_with_authority(const sm2_rev_tree_t *tree,
    const uint8_t *authority_id, size_t authority_id_len, uint64_t valid_from,
    uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_root_record_t *root_record)
{
    if (!tree || !root_record || !sign_fn)
        return SM2_IC_ERR_PARAM;
    if (!tree->node_hashes || tree->level_count == 0)
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
    root_record->root_version = tree->root_version;
    root_record->valid_from = valid_from;
    root_record->valid_until = valid_until;
    memcpy(root_record->root_hash, tree->root_hash, SM2_REV_MERKLE_HASH_LEN);

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = merkle_serialize_root_for_auth(
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

sm2_ic_error_t sm2_rev_root_sign(const sm2_rev_tree_t *tree,
    uint64_t valid_from, uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, sm2_rev_root_record_t *root_record)
{
    return sm2_rev_root_sign_with_authority(tree, NULL, 0, valid_from,
        valid_until, sign_fn, sign_user_ctx, root_record);
}

sm2_ic_error_t sm2_rev_root_verify(const sm2_rev_root_record_t *root_record,
    uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
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
    sm2_ic_error_t ret = merkle_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = verify_fn(verify_user_ctx, auth_buf, auth_len, root_record->signature,
        root_record->signature_len);
    return ret == SM2_IC_SUCCESS ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_rev_member_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_member_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx)
{
    sm2_ic_error_t ret
        = sm2_rev_root_verify(root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    return sm2_rev_tree_verify_member(root_record->root_hash, proof);
}

sm2_ic_error_t sm2_rev_absence_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_absence_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx)
{
    sm2_ic_error_t ret
        = sm2_rev_root_verify(root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    return sm2_rev_tree_verify_absence(root_record->root_hash, proof);
}
