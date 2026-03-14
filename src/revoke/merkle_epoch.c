/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle_epoch.c
 * @brief Epoch directory, hot-patch, cached proofs and epoch switch logic.
 */

#include "merkle_internal.h"
size_t merkle_expected_sibling_count(size_t leaf_count)
{
    size_t n = leaf_count;
    size_t depth = 0;

    if (n == 0)
        return 0;

    while (n > 1)
    {
        n = (n + 1) / 2;
        depth++;
    }

    return depth;
}

int merkle_cmp_delta_item(const void *a, const void *b)
{
    const sm2_crl_delta_item_t *ia = (const sm2_crl_delta_item_t *)a;
    const sm2_crl_delta_item_t *ib = (const sm2_crl_delta_item_t *)b;
    if (ia->serial_number < ib->serial_number)
        return -1;
    if (ia->serial_number > ib->serial_number)
        return 1;
    return 0;
}

sm2_ic_error_t merkle_calc_patch_digest(const sm2_crl_delta_item_t *items,
    size_t item_count, uint8_t out_digest[SM2_REV_MERKLE_HASH_LEN])
{
    if (!out_digest)
        return SM2_IC_ERR_PARAM;
    if (item_count > 0 && !items)
        return SM2_IC_ERR_PARAM;
    if (item_count > ((SIZE_MAX - 8U) / 9U))
        return SM2_IC_ERR_PARAM;

    size_t buf_len = 8 + item_count * 9;
    uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;

    merkle_u64_to_be((uint64_t)item_count, buf);
    size_t off = 8;

    for (size_t i = 0; i < item_count; i++)
    {
        merkle_u64_to_be(items[i].serial_number, buf + off);
        off += 8;
        buf[off++] = items[i].revoked ? 1U : 0U;
    }

    sm2_ic_error_t ret = sm2_ic_sm3_hash(buf, buf_len, out_digest);
    free(buf);
    return ret;
}

sm2_ic_error_t merkle_epoch_serialize_for_auth(
    const sm2_rev_epoch_dir_t *directory, uint8_t *output, size_t output_cap,
    size_t *output_len)
{
    static const uint8_t tag[] = "SM2REV_MERKLE_EPOCH_DIR_V1";
    uint8_t patch_digest[SM2_REV_MERKLE_HASH_LEN];

    if (!directory || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (directory->root_record.authority_id_len
        > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_ic_error_t ret = merkle_calc_patch_digest(
        directory->patch_items, directory->patch_item_count, patch_digest);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t need = (sizeof(tag) - 1U) + 8U + SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN
        + 8U + 8U + SM2_REV_MERKLE_HASH_LEN + 8U + 8U + 8U + 8U + 8U
        + SM2_REV_MERKLE_HASH_LEN;
    if (output_cap < need)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    memcpy(output + off, tag, sizeof(tag) - 1U);
    off += (sizeof(tag) - 1U);

    merkle_u64_to_be(directory->epoch_id, output + off);
    off += 8U;

    merkle_u64_to_be(
        (uint64_t)directory->root_record.authority_id_len, output + off);
    off += 8U;
    memcpy(output + off, directory->root_record.authority_id,
        directory->root_record.authority_id_len);
    off += directory->root_record.authority_id_len;

    merkle_u64_to_be(directory->root_record.root_version, output + off);
    off += 8U;

    memcpy(output + off, directory->root_record.root_hash,
        SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;

    merkle_u64_to_be(directory->root_record.valid_from, output + off);
    off += 8U;

    merkle_u64_to_be(directory->root_record.valid_until, output + off);
    off += 8U;

    merkle_u64_to_be((uint64_t)directory->tree_level_count, output + off);
    off += 8U;

    merkle_u64_to_be((uint64_t)directory->cache_level_count, output + off);
    off += 8U;

    merkle_u64_to_be(directory->patch_version, output + off);
    off += 8U;

    memcpy(output + off, patch_digest, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

bool merkle_epoch_patch_lookup(
    const sm2_rev_epoch_dir_t *directory, uint64_t serial, bool *revoked)
{
    if (!directory || !revoked || !directory->patch_items)
        return false;

    size_t left = 0;
    size_t right = directory->patch_item_count;
    while (left < right)
    {
        size_t mid = left + (right - left) / 2;
        uint64_t v = directory->patch_items[mid].serial_number;
        if (v < serial)
            left = mid + 1;
        else
            right = mid;
    }

    if (left < directory->patch_item_count
        && directory->patch_items[left].serial_number == serial)
    {
        *revoked = directory->patch_items[left].revoked;
        return true;
    }

    return false;
}

bool merkle_epoch_get_cached_hash(const sm2_rev_epoch_dir_t *directory,
    size_t level_index, size_t node_index,
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    if (!directory || !out_hash || !directory->cached_hashes)
        return false;

    for (size_t i = 0; i < directory->cache_level_count; i++)
    {
        if (directory->cached_level_indices[i] != level_index)
            continue;

        if (node_index >= directory->cached_level_sizes[i])
            return false;

        size_t idx = directory->cached_level_offsets[i] + node_index;
        if (idx >= directory->cached_hash_count)
            return false;

        memcpy(
            out_hash, directory->cached_hashes[idx], SM2_REV_MERKLE_HASH_LEN);
        return true;
    }

    return false;
}

static void epoch_dir_reset(sm2_rev_epoch_dir_t *directory)
{
    if (!directory)
        return;

    free(directory->cached_hashes);
    free(directory->patch_items);
    memset(directory, 0, sizeof(*directory));
}

static sm2_ic_error_t epoch_dir_ensure(sm2_rev_epoch_dir_t **directory)
{
    if (!directory)
        return SM2_IC_ERR_PARAM;
    if (!*directory)
    {
        *directory = (sm2_rev_epoch_dir_t *)calloc(1, sizeof(**directory));
        if (!*directory)
            return SM2_IC_ERR_MEMORY;
    }
    return SM2_IC_SUCCESS;
}

void sm2_rev_epoch_dir_cleanup(sm2_rev_epoch_dir_t **directory)
{
    if (!directory || !*directory)
        return;

    epoch_dir_reset(*directory);
    free(*directory);
    *directory = NULL;
}

sm2_ic_error_t merkle_epoch_directory_clone(
    sm2_rev_epoch_dir_t *dst, const sm2_rev_epoch_dir_t *src)
{
    if (!dst || !src)
        return SM2_IC_ERR_PARAM;

    sm2_rev_epoch_dir_t tmp = *src;
    tmp.cached_hashes = NULL;
    tmp.patch_items = NULL;

    if (src->cached_hash_count > 0)
    {
        if (src->cached_hash_count > SIZE_MAX / SM2_REV_MERKLE_HASH_LEN)
            return SM2_IC_ERR_MEMORY;

        tmp.cached_hashes
            = calloc(src->cached_hash_count, sizeof(*tmp.cached_hashes));
        if (!tmp.cached_hashes)
            return SM2_IC_ERR_MEMORY;

        memcpy(tmp.cached_hashes, src->cached_hashes,
            src->cached_hash_count * SM2_REV_MERKLE_HASH_LEN);
    }

    if (src->patch_item_count > 0)
    {
        if (src->patch_item_count > SIZE_MAX / sizeof(sm2_crl_delta_item_t))
        {
            free(tmp.cached_hashes);
            return SM2_IC_ERR_MEMORY;
        }

        tmp.patch_items = (sm2_crl_delta_item_t *)calloc(
            src->patch_item_count, sizeof(sm2_crl_delta_item_t));
        if (!tmp.patch_items)
        {
            free(tmp.cached_hashes);
            return SM2_IC_ERR_MEMORY;
        }

        memcpy(tmp.patch_items, src->patch_items,
            src->patch_item_count * sizeof(sm2_crl_delta_item_t));
    }

    epoch_dir_reset(dst);
    *dst = tmp;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_epoch_dir_build_with_authority(
    const sm2_rev_tree_t *tree, uint64_t epoch_id,
    const uint8_t *authority_id, size_t authority_id_len,
    size_t cache_top_levels, uint64_t valid_from, uint64_t valid_until,
    sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_epoch_dir_t **directory)
{
    if (!tree || !directory || !sign_fn)
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
    if (cache_top_levels == 0
        || cache_top_levels > SM2_REV_MERKLE_EPOCH_MAX_CACHE_LEVELS)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_ic_error_t ret = epoch_dir_ensure(directory);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    sm2_rev_epoch_dir_t *state = *directory;
    epoch_dir_reset(state);

    state->epoch_id = epoch_id;
    state->tree_level_count = tree->level_count;

    ret = sm2_rev_root_sign_with_authority(tree, authority_id,
        authority_id_len, valid_from, valid_until, sign_fn, sign_user_ctx,
        &state->root_record);
    if (ret != SM2_IC_SUCCESS)
    {
        epoch_dir_reset(state);
        return ret;
    }

    size_t sibling_levels = tree->level_count - 1;
    state->cache_level_count = cache_top_levels;
    if (state->cache_level_count > sibling_levels)
        state->cache_level_count = sibling_levels;
    if (state->cache_level_count == 0)
    {
        epoch_dir_reset(state);
        return SM2_IC_ERR_PARAM;
    }

    size_t start_level = sibling_levels - state->cache_level_count;
    size_t total_hashes = 0;

    for (size_t i = 0; i < state->cache_level_count; i++)
    {
        size_t level_idx = start_level + i;
        size_t level_size = tree->level_sizes[level_idx];

        state->cached_level_indices[i] = level_idx;
        state->cached_level_sizes[i] = level_size;
        state->cached_level_offsets[i] = total_hashes;

        if (total_hashes > SIZE_MAX - level_size)
        {
            epoch_dir_reset(state);
            return SM2_IC_ERR_MEMORY;
        }
        total_hashes += level_size;
    }

    state->cached_hash_count = total_hashes;
    if (total_hashes > 0)
    {
        if (total_hashes > SIZE_MAX / SM2_REV_MERKLE_HASH_LEN)
        {
            epoch_dir_reset(state);
            return SM2_IC_ERR_MEMORY;
        }

        state->cached_hashes
            = calloc(total_hashes, sizeof(*state->cached_hashes));
        if (!state->cached_hashes)
        {
            epoch_dir_reset(state);
            return SM2_IC_ERR_MEMORY;
        }

        for (size_t i = 0; i < state->cache_level_count; i++)
        {
            size_t level_idx = state->cached_level_indices[i];
            size_t level_size = state->cached_level_sizes[i];
            size_t level_off = state->cached_level_offsets[i];
            size_t src_off = tree->level_offsets[level_idx];
            memcpy(state->cached_hashes + level_off,
                tree->node_hashes + src_off * SM2_REV_MERKLE_HASH_LEN,
                level_size * SM2_REV_MERKLE_HASH_LEN);
        }
    }

    state->patch_version = 0;
    state->patch_items = NULL;
    state->patch_item_count = 0;

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    ret = merkle_epoch_serialize_for_auth(
        state, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
    {
        epoch_dir_reset(state);
        return ret;
    }

    size_t sig_len = sizeof(state->directory_signature);
    ret = sign_fn(sign_user_ctx, auth_buf, auth_len, state->directory_signature,
        &sig_len);
    if (ret != SM2_IC_SUCCESS || sig_len == 0
        || sig_len > sizeof(state->directory_signature))
    {
        epoch_dir_reset(state);
        return SM2_IC_ERR_VERIFY;
    }

    state->directory_signature_len = sig_len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_epoch_dir_build(const sm2_rev_tree_t *tree,
    uint64_t epoch_id, size_t cache_top_levels, uint64_t valid_from,
    uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_epoch_dir_t **directory)
{
    return sm2_rev_epoch_dir_build_with_authority(tree, epoch_id, NULL, 0,
        cache_top_levels, valid_from, valid_until, sign_fn, sign_user_ctx,
        directory);
}

sm2_ic_error_t sm2_rev_epoch_dir_verify(const sm2_rev_epoch_dir_t *directory,
    uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!directory || !verify_fn)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_rev_root_verify(
        &directory->root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (directory->tree_level_count <= 1 || directory->cache_level_count == 0
        || directory->cache_level_count > SM2_REV_MERKLE_EPOCH_MAX_CACHE_LEVELS
        || directory->cache_level_count >= directory->tree_level_count)
    {
        return SM2_IC_ERR_VERIFY;
    }

    size_t expected_hash_count = 0;
    for (size_t i = 0; i < directory->cache_level_count; i++)
    {
        if (directory->cached_level_indices[i] >= directory->tree_level_count)
            return SM2_IC_ERR_VERIFY;
        if (directory->cached_level_sizes[i] == 0)
            return SM2_IC_ERR_VERIFY;
        if (directory->cached_level_offsets[i] != expected_hash_count)
            return SM2_IC_ERR_VERIFY;

        if (expected_hash_count > SIZE_MAX - directory->cached_level_sizes[i])
            return SM2_IC_ERR_VERIFY;
        expected_hash_count += directory->cached_level_sizes[i];
    }

    if (!directory->cached_hashes
        || directory->cached_hash_count != expected_hash_count)
    {
        return SM2_IC_ERR_VERIFY;
    }

    if (directory->directory_signature_len == 0
        || directory->directory_signature_len
            > sizeof(directory->directory_signature))
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    ret = merkle_epoch_serialize_for_auth(
        directory, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = verify_fn(verify_user_ctx, auth_buf, auth_len,
        directory->directory_signature, directory->directory_signature_len);
    return ret == SM2_IC_SUCCESS ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_rev_epoch_apply_patch(sm2_rev_epoch_dir_t *directory,
    uint64_t patch_version, const sm2_crl_delta_item_t *items,
    size_t item_count, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx)
{
    if (!directory || !sign_fn)
        return SM2_IC_ERR_PARAM;
    if (item_count > 0 && !items)
        return SM2_IC_ERR_PARAM;
    if (patch_version <= directory->patch_version)
        return SM2_IC_ERR_VERIFY;

    sm2_crl_delta_item_t *new_items = NULL;
    size_t new_count = 0;

    if (item_count > 0)
    {
        if (item_count > SIZE_MAX / sizeof(sm2_crl_delta_item_t))
            return SM2_IC_ERR_MEMORY;

        sm2_crl_delta_item_t *tmp = (sm2_crl_delta_item_t *)calloc(
            item_count, sizeof(sm2_crl_delta_item_t));
        if (!tmp)
            return SM2_IC_ERR_MEMORY;
        memcpy(tmp, items, item_count * sizeof(sm2_crl_delta_item_t));
        qsort(tmp, item_count, sizeof(sm2_crl_delta_item_t),
            merkle_cmp_delta_item);

        new_items = (sm2_crl_delta_item_t *)calloc(
            item_count, sizeof(sm2_crl_delta_item_t));
        if (!new_items)
        {
            free(tmp);
            return SM2_IC_ERR_MEMORY;
        }

        for (size_t i = 0; i < item_count; i++)
        {
            if (new_count == 0
                || new_items[new_count - 1].serial_number
                    != tmp[i].serial_number)
            {
                new_items[new_count++] = tmp[i];
            }
            else
            {
                new_items[new_count - 1].revoked
                    = new_items[new_count - 1].revoked || tmp[i].revoked;
            }
        }

        free(tmp);
    }

    sm2_crl_delta_item_t *old_items = directory->patch_items;
    size_t old_count = directory->patch_item_count;
    uint64_t old_version = directory->patch_version;
    uint8_t old_sig[SM2_REV_SYNC_MAX_SIG_LEN];
    size_t old_sig_len = directory->directory_signature_len;
    memcpy(old_sig, directory->directory_signature, sizeof(old_sig));

    directory->patch_items = new_items;
    directory->patch_item_count = new_count;
    directory->patch_version = patch_version;

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = merkle_epoch_serialize_for_auth(
        directory, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
    {
        directory->patch_items = old_items;
        directory->patch_item_count = old_count;
        directory->patch_version = old_version;
        directory->directory_signature_len = old_sig_len;
        memcpy(directory->directory_signature, old_sig, sizeof(old_sig));
        free(new_items);
        return ret;
    }

    size_t sig_len = sizeof(directory->directory_signature);
    ret = sign_fn(sign_user_ctx, auth_buf, auth_len,
        directory->directory_signature, &sig_len);
    if (ret != SM2_IC_SUCCESS || sig_len == 0
        || sig_len > sizeof(directory->directory_signature))
    {
        directory->patch_items = old_items;
        directory->patch_item_count = old_count;
        directory->patch_version = old_version;
        directory->directory_signature_len = old_sig_len;
        memcpy(directory->directory_signature, old_sig, sizeof(old_sig));
        free(new_items);
        return SM2_IC_ERR_VERIFY;
    }

    directory->directory_signature_len = sig_len;
    free(old_items);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_epoch_prove_member_cached(const sm2_rev_tree_t *tree,
    uint64_t serial_number, size_t cache_top_levels,
    sm2_rev_cached_member_proof_t *proof)
{
    if (!tree || !proof)
        return SM2_IC_ERR_PARAM;

    memset(proof, 0, sizeof(*proof));

    sm2_ic_error_t ret
        = sm2_rev_tree_prove_member(tree, serial_number, &proof->proof);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t omit = cache_top_levels;
    if (omit > proof->proof.sibling_count)
        omit = proof->proof.sibling_count;

    proof->omitted_top_levels = omit;
    proof->proof.sibling_count -= omit;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_epoch_verify_member_cached(
    const sm2_rev_epoch_dir_t *directory, uint64_t now_ts,
    const sm2_rev_cached_member_proof_t *proof,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!directory || !proof || !verify_fn)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_rev_epoch_dir_verify(
        directory, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    bool patch_revoked = false;
    if (merkle_epoch_patch_lookup(
            directory, proof->proof.serial_number, &patch_revoked))
    {
        return patch_revoked ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
    }

    size_t expected_depth
        = merkle_expected_sibling_count(proof->proof.leaf_count);
    if (expected_depth == 0)
        return SM2_IC_ERR_VERIFY;
    if (proof->proof.sibling_count > expected_depth
        || proof->omitted_top_levels > expected_depth
        || proof->omitted_top_levels > directory->cache_level_count
        || proof->proof.sibling_count + proof->omitted_top_levels
            != expected_depth)
    {
        return SM2_IC_ERR_VERIFY;
    }

    sm2_rev_member_proof_t full = proof->proof;
    size_t present_count = full.sibling_count;
    full.sibling_count = expected_depth;

    size_t cur = full.leaf_index;
    size_t level_size = full.leaf_count;

    for (size_t level = 0; level < expected_depth; level++)
    {
        size_t sibling = (cur % 2 == 0) ? (cur + 1) : (cur - 1);
        if (sibling >= level_size)
            sibling = cur;

        if (level >= present_count)
        {
            uint8_t sibling_hash[SM2_REV_MERKLE_HASH_LEN];
            if (!merkle_epoch_get_cached_hash(
                    directory, level, sibling, sibling_hash))
            {
                return SM2_IC_ERR_VERIFY;
            }

            memcpy(full.sibling_hashes[level], sibling_hash,
                SM2_REV_MERKLE_HASH_LEN);
            full.sibling_on_left[level] = sibling < cur ? 1U : 0U;
        }

        cur /= 2;
        level_size = (level_size + 1) / 2;
    }

    return sm2_rev_tree_verify_member(directory->root_record.root_hash, &full);
}

sm2_ic_error_t sm2_rev_epoch_lookup(const sm2_rev_epoch_dir_t *directory,
    uint64_t now_ts, uint64_t serial_number, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx, sm2_rev_status_t *status)
{
    if (!directory || !verify_fn || !status)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_rev_epoch_dir_verify(
        directory, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    bool revoked = false;
    if (merkle_epoch_patch_lookup(directory, serial_number, &revoked))
    {
        *status = revoked ? SM2_REV_STATUS_REVOKED : SM2_REV_STATUS_GOOD;
        return SM2_IC_SUCCESS;
    }

    *status = SM2_REV_STATUS_UNKNOWN;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_epoch_lookup_cb(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    if (!cert || !status || !user_ctx)
        return SM2_IC_ERR_PARAM;

    sm2_rev_lookup_ctx_t *ctx = (sm2_rev_lookup_ctx_t *)user_ctx;
    if (!ctx->directory || !ctx->verify_fn)
        return SM2_IC_ERR_PARAM;

    return sm2_rev_epoch_lookup(ctx->directory, now_ts, cert->serial_number,
        ctx->verify_fn, ctx->verify_user_ctx, status);
}

sm2_ic_error_t sm2_rev_epoch_switch(sm2_rev_epoch_dir_t **local_directory,
    const sm2_rev_epoch_dir_t *incoming_directory, uint64_t now_ts,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!local_directory || !incoming_directory || !verify_fn)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_rev_epoch_dir_verify(
        incoming_directory, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    sm2_rev_epoch_dir_t *state = *local_directory;
    if (state && state->directory_signature_len > 0)
    {
        if (incoming_directory->epoch_id < state->epoch_id)
            return SM2_IC_ERR_VERIFY;
        if (incoming_directory->epoch_id == state->epoch_id
            && incoming_directory->root_record.root_version
                < state->root_record.root_version)
        {
            return SM2_IC_ERR_VERIFY;
        }
        if (incoming_directory->epoch_id == state->epoch_id
            && incoming_directory->patch_version < state->patch_version)
        {
            return SM2_IC_ERR_VERIFY;
        }
    }

    if (!state)
    {
        ret = epoch_dir_ensure(local_directory);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        state = *local_directory;
    }

    return merkle_epoch_directory_clone(state, incoming_directory);
}

size_t sm2_rev_epoch_dir_tree_level_count(const sm2_rev_epoch_dir_t *directory)
{
    return directory ? directory->tree_level_count : 0;
}

size_t sm2_rev_epoch_dir_cache_level_count(const sm2_rev_epoch_dir_t *directory)
{
    return directory ? directory->cache_level_count : 0;
}

uint64_t sm2_rev_epoch_dir_patch_version(const sm2_rev_epoch_dir_t *directory)
{
    return directory ? directory->patch_version : 0;
}

sm2_ic_error_t sm2_rev_epoch_dir_get_root_record(
    const sm2_rev_epoch_dir_t *directory, sm2_rev_root_record_t *root_record)
{
    if (!directory || !root_record)
        return SM2_IC_ERR_PARAM;

    *root_record = directory->root_record;
    return SM2_IC_SUCCESS;
}
