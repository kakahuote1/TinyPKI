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

static sm2_ic_error_t pki_epoch_serialize_root_for_auth(
    const sm2_pki_epoch_root_record_t *root_record, uint8_t *output,
    size_t output_cap, size_t *output_len)
{
    static const uint8_t tag[] = "SM2PKI_EPOCH_ROOT_V1";
    size_t need = (sizeof(tag) - 1U) + 8U + SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN
        + 8U + 8U + SM2_REV_MERKLE_HASH_LEN + 8U + SM2_REV_MERKLE_HASH_LEN + 8U
        + 8U;

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

    pki_issuance_u64_to_be(root_record->epoch_version, output + off);
    off += 8U;

    pki_issuance_u64_to_be(root_record->revocation_root_version, output + off);
    off += 8U;
    memcpy(output + off, root_record->revocation_root_hash,
        SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;

    pki_issuance_u64_to_be(root_record->issuance_root_version, output + off);
    off += 8U;
    memcpy(
        output + off, root_record->issuance_root_hash, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;

    pki_issuance_u64_to_be(root_record->valid_from, output + off);
    off += 8U;

    pki_issuance_u64_to_be(root_record->valid_until, output + off);
    off += 8U;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_epoch_root_sign(const uint8_t *authority_id,
    size_t authority_id_len, uint64_t epoch_version,
    uint64_t revocation_root_version,
    const uint8_t revocation_root_hash[SM2_REV_MERKLE_HASH_LEN],
    uint64_t issuance_root_version,
    const uint8_t issuance_root_hash[SM2_REV_MERKLE_HASH_LEN],
    uint64_t valid_from, uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, sm2_pki_epoch_root_record_t *root_record)
{
    if (!authority_id || authority_id_len == 0
        || authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN
        || !revocation_root_hash || !issuance_root_hash || !sign_fn
        || !root_record)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (epoch_version == 0 || valid_until < valid_from)
        return SM2_IC_ERR_PARAM;

    memset(root_record, 0, sizeof(*root_record));
    memcpy(root_record->authority_id, authority_id, authority_id_len);
    root_record->authority_id_len = authority_id_len;
    root_record->epoch_version = epoch_version;
    root_record->revocation_root_version = revocation_root_version;
    memcpy(root_record->revocation_root_hash, revocation_root_hash,
        SM2_REV_MERKLE_HASH_LEN);
    root_record->issuance_root_version = issuance_root_version;
    memcpy(root_record->issuance_root_hash, issuance_root_hash,
        SM2_REV_MERKLE_HASH_LEN);
    root_record->valid_from = valid_from;
    root_record->valid_until = valid_until;

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = pki_epoch_serialize_root_for_auth(
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

sm2_ic_error_t sm2_pki_epoch_root_verify(
    const sm2_pki_epoch_root_record_t *root_record, uint64_t now_ts,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!root_record || !verify_fn)
        return SM2_IC_ERR_PARAM;
    if (root_record->authority_id_len == 0
        || root_record->authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (root_record->epoch_version == 0
        || root_record->valid_until < root_record->valid_from
        || now_ts < root_record->valid_from || now_ts > root_record->valid_until
        || root_record->signature_len == 0
        || root_record->signature_len > sizeof(root_record->signature))
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = pki_epoch_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = verify_fn(verify_user_ctx, auth_buf, auth_len, root_record->signature,
        root_record->signature_len);
    return ret == SM2_IC_SUCCESS ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_pki_epoch_root_digest(
    const sm2_pki_epoch_root_record_t *root_record,
    uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN])
{
    uint8_t auth_buf[256];
    size_t auth_len = 0;
    if (!root_record || !digest)
        return SM2_IC_ERR_PARAM;
    sm2_ic_error_t ret = pki_epoch_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return sm2_ic_sm3_hash(auth_buf, auth_len, digest);
}

sm2_ic_error_t sm2_pki_epoch_root_encode_witness_payload(
    const sm2_pki_epoch_root_record_t *root_record, uint8_t *output,
    size_t output_cap, size_t *output_len)
{
    static const uint8_t tag[] = "SM2PKI_EPOCH_WITNESS_V1";
    uint8_t auth_buf[256];
    size_t auth_len = 0;
    if (!root_record || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (root_record->signature_len == 0
        || root_record->signature_len > sizeof(root_record->signature))
    {
        return SM2_IC_ERR_VERIFY;
    }

    sm2_ic_error_t ret = pki_epoch_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t need
        = (sizeof(tag) - 1U) + 8U + auth_len + 8U + root_record->signature_len;
    if (output_cap < need)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    memcpy(output + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    pki_issuance_u64_to_be((uint64_t)auth_len, output + off);
    off += 8U;
    memcpy(output + off, auth_buf, auth_len);
    off += auth_len;
    pki_issuance_u64_to_be((uint64_t)root_record->signature_len, output + off);
    off += 8U;
    memcpy(output + off, root_record->signature, root_record->signature_len);
    off += root_record->signature_len;
    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_issuance_cert_commitment(const sm2_implicit_cert_t *cert,
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
    size_t commitment_capacity;
    struct sm2_pki_issuance_node_st *nodes;
    size_t node_count;
    size_t node_capacity;
    size_t peaks[SM2_PKI_ISSUANCE_MAX_PEAKS];
    size_t peak_count;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
};

typedef struct sm2_pki_issuance_node_st
{
    uint8_t hash[SM2_REV_MERKLE_HASH_LEN];
    size_t left;
    size_t right;
    size_t parent;
    size_t leaf_index;
    size_t leaf_count;
    size_t height;
    bool is_leaf;
} sm2_pki_issuance_node_t;

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
    free(tree->nodes);
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
    memcpy(buf + 1 + SM2_REV_MERKLE_HASH_LEN, right, SM2_REV_MERKLE_HASH_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

static sm2_ic_error_t pki_issuance_hash_root(size_t leaf_count,
    size_t peak_count,
    const uint8_t peak_hashes[SM2_PKI_ISSUANCE_MAX_PEAKS]
                             [SM2_REV_MERKLE_HASH_LEN],
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    static const uint8_t tag[] = "SM2PKI_ISSUANCE_MMR_ROOT_V1";
    uint8_t buf[(sizeof(tag) - 1U) + 16U
        + SM2_PKI_ISSUANCE_MAX_PEAKS * SM2_REV_MERKLE_HASH_LEN];

    if (!out_hash || peak_count > SM2_PKI_ISSUANCE_MAX_PEAKS)
        return SM2_IC_ERR_PARAM;
    if (leaf_count == 0)
        return pki_issuance_hash_empty(out_hash);
    if (!peak_hashes || peak_count == 0)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    memcpy(buf + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    pki_issuance_u64_to_be((uint64_t)leaf_count, buf + off);
    off += 8U;
    pki_issuance_u64_to_be((uint64_t)peak_count, buf + off);
    off += 8U;
    for (size_t i = 0; i < peak_count; i++)
    {
        memcpy(buf + off, peak_hashes[i], SM2_REV_MERKLE_HASH_LEN);
        off += SM2_REV_MERKLE_HASH_LEN;
    }
    return sm2_ic_sm3_hash(buf, off, out_hash);
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
    state->root_version = 0;
    sm2_ic_error_t ret = pki_issuance_hash_empty(state->root_hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < commitment_count; i++)
    {
        ret = sm2_pki_issuance_tree_append(tree, commitments[i], i + 1U);
        if (ret != SM2_IC_SUCCESS)
        {
            pki_issuance_tree_reset(state);
            return ret;
        }
    }

    state->root_version = root_version;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t pki_issuance_ensure_commitment_capacity(
    sm2_pki_issuance_tree_t *tree, size_t required)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    if (required <= tree->commitment_capacity)
        return SM2_IC_SUCCESS;

    size_t new_capacity
        = tree->commitment_capacity == 0 ? 16U : tree->commitment_capacity;
    while (new_capacity < required)
    {
        if (new_capacity > SIZE_MAX / 2U)
            return SM2_IC_ERR_MEMORY;
        new_capacity *= 2U;
    }
    if (new_capacity > SIZE_MAX / sizeof(*tree->commitments))
        return SM2_IC_ERR_MEMORY;

    void *new_mem
        = realloc(tree->commitments, new_capacity * sizeof(*tree->commitments));
    if (!new_mem)
        return SM2_IC_ERR_MEMORY;
    tree->commitments = new_mem;
    tree->commitment_capacity = new_capacity;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t pki_issuance_ensure_node_capacity(
    sm2_pki_issuance_tree_t *tree, size_t required)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    if (required <= tree->node_capacity)
        return SM2_IC_SUCCESS;

    size_t new_capacity = tree->node_capacity == 0 ? 32U : tree->node_capacity;
    while (new_capacity < required)
    {
        if (new_capacity > SIZE_MAX / 2U)
            return SM2_IC_ERR_MEMORY;
        new_capacity *= 2U;
    }
    if (new_capacity > SIZE_MAX / sizeof(*tree->nodes))
        return SM2_IC_ERR_MEMORY;

    void *new_mem = realloc(tree->nodes, new_capacity * sizeof(*tree->nodes));
    if (!new_mem)
        return SM2_IC_ERR_MEMORY;
    tree->nodes = new_mem;
    tree->node_capacity = new_capacity;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t pki_issuance_refresh_root(sm2_pki_issuance_tree_t *tree)
{
    uint8_t peak_hashes[SM2_PKI_ISSUANCE_MAX_PEAKS][SM2_REV_MERKLE_HASH_LEN];
    if (!tree)
        return SM2_IC_ERR_PARAM;
    for (size_t i = 0; i < tree->peak_count; i++)
    {
        if (tree->peaks[i] >= tree->node_count)
            return SM2_IC_ERR_VERIFY;
        memcpy(peak_hashes[i], tree->nodes[tree->peaks[i]].hash,
            SM2_REV_MERKLE_HASH_LEN);
    }
    return pki_issuance_hash_root(
        tree->leaf_count, tree->peak_count, peak_hashes, tree->root_hash);
}

sm2_ic_error_t sm2_pki_issuance_tree_append(sm2_pki_issuance_tree_t **tree,
    const uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    uint64_t root_version)
{
    if (!tree || !commitment)
        return SM2_IC_ERR_PARAM;
    if (!*tree)
    {
        *tree = (sm2_pki_issuance_tree_t *)calloc(1, sizeof(**tree));
        if (!*tree)
            return SM2_IC_ERR_MEMORY;
        sm2_ic_error_t ret = pki_issuance_hash_empty((*tree)->root_hash);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    sm2_pki_issuance_tree_t *state = *tree;
    if (state->leaf_count >= SIZE_MAX - 1U)
        return SM2_IC_ERR_MEMORY;
    if (state->peak_count >= SM2_PKI_ISSUANCE_MAX_PEAKS)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = pki_issuance_ensure_commitment_capacity(
        state, state->leaf_count + 1U);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = pki_issuance_ensure_node_capacity(state, state->node_count + 1U);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t leaf_index = state->leaf_count;
    size_t node_index = state->node_count++;
    sm2_pki_issuance_node_t *node = &state->nodes[node_index];
    memset(node, 0, sizeof(*node));
    node->left = SIZE_MAX;
    node->right = SIZE_MAX;
    node->parent = SIZE_MAX;
    node->leaf_index = leaf_index;
    node->leaf_count = 1U;
    node->height = 0;
    node->is_leaf = true;
    ret = pki_issuance_hash_leaf(commitment, leaf_index, node->hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    memcpy(state->commitments[leaf_index], commitment,
        SM2_PKI_ISSUANCE_COMMITMENT_LEN);
    state->leaf_count++;
    state->peaks[state->peak_count++] = node_index;

    while (state->peak_count >= 2U)
    {
        size_t right_peak = state->peaks[state->peak_count - 1U];
        size_t left_peak = state->peaks[state->peak_count - 2U];
        if (state->nodes[left_peak].height != state->nodes[right_peak].height)
            break;

        ret = pki_issuance_ensure_node_capacity(state, state->node_count + 1U);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        size_t parent_index = state->node_count++;
        sm2_pki_issuance_node_t *parent = &state->nodes[parent_index];
        memset(parent, 0, sizeof(*parent));
        parent->left = left_peak;
        parent->right = right_peak;
        parent->parent = SIZE_MAX;
        parent->leaf_index = state->nodes[left_peak].leaf_index;
        parent->leaf_count = state->nodes[left_peak].leaf_count
            + state->nodes[right_peak].leaf_count;
        parent->height = state->nodes[left_peak].height + 1U;
        parent->is_leaf = false;
        ret = pki_issuance_hash_parent(state->nodes[left_peak].hash,
            state->nodes[right_peak].hash, parent->hash);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        state->nodes[left_peak].parent = parent_index;
        state->nodes[right_peak].parent = parent_index;
        state->peaks[state->peak_count - 2U] = parent_index;
        state->peak_count--;
    }

    state->root_version = root_version;
    return pki_issuance_refresh_root(state);
}

sm2_ic_error_t sm2_pki_issuance_tree_get_root_hash(
    const sm2_pki_issuance_tree_t *tree,
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN])
{
    if (!tree || !root_hash)
        return SM2_IC_ERR_PARAM;
    memcpy(root_hash, tree->root_hash, SM2_REV_MERKLE_HASH_LEN);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_issuance_tree_prove_member(
    const sm2_pki_issuance_tree_t *tree,
    const uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    sm2_pki_issuance_member_proof_t *proof)
{
    if (!tree || !commitment || !proof)
        return SM2_IC_ERR_PARAM;
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
    memcpy(proof->cert_commitment, commitment, SM2_PKI_ISSUANCE_COMMITMENT_LEN);
    proof->leaf_index = index;
    proof->leaf_count = tree->leaf_count;

    size_t node_index = SIZE_MAX;
    for (size_t i = 0; i < tree->node_count; i++)
    {
        if (tree->nodes[i].is_leaf && tree->nodes[i].leaf_index == index)
        {
            node_index = i;
            break;
        }
    }
    if (node_index == SIZE_MAX)
        return SM2_IC_ERR_VERIFY;

    while (tree->nodes[node_index].parent != SIZE_MAX)
    {
        if (proof->sibling_count >= SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH)
            return SM2_IC_ERR_PARAM;

        size_t parent = tree->nodes[node_index].parent;
        size_t sibling = tree->nodes[parent].left == node_index
            ? tree->nodes[parent].right
            : tree->nodes[parent].left;
        if (sibling >= tree->node_count)
            return SM2_IC_ERR_VERIFY;

        memcpy(proof->sibling_hashes[proof->sibling_count],
            tree->nodes[sibling].hash, SM2_REV_MERKLE_HASH_LEN);
        proof->sibling_on_left[proof->sibling_count]
            = tree->nodes[parent].left == sibling ? 1U : 0U;
        proof->sibling_count++;
        node_index = parent;
    }

    proof->peak_index = SIZE_MAX;
    for (size_t i = 0; i < tree->peak_count; i++)
    {
        if (tree->peaks[i] == node_index)
            proof->peak_index = i;
        memcpy(proof->peak_hashes[i], tree->nodes[tree->peaks[i]].hash,
            SM2_REV_MERKLE_HASH_LEN);
    }
    if (proof->peak_index == SIZE_MAX)
        return SM2_IC_ERR_VERIFY;
    proof->peak_count = tree->peak_count;
    return SM2_IC_SUCCESS;
}

static size_t pki_issuance_floor_log2_size(size_t v)
{
    size_t bit = 0;
    while (v > 1U)
    {
        v >>= 1U;
        bit++;
    }
    return bit;
}

static sm2_ic_error_t pki_issuance_expected_peak(size_t leaf_count,
    size_t leaf_index, size_t *peak_index, size_t *peak_count,
    size_t *peak_height)
{
    if (!peak_index || !peak_count || !peak_height || leaf_count == 0
        || leaf_index >= leaf_count)
    {
        return SM2_IC_ERR_VERIFY;
    }

    size_t start = 0;
    size_t remaining = leaf_count;
    size_t idx = 0;
    while (remaining > 0)
    {
        size_t height = pki_issuance_floor_log2_size(remaining);
        size_t count = ((size_t)1U) << height;
        if (leaf_index >= start && leaf_index < start + count)
        {
            *peak_index = idx;
            *peak_height = height;
        }
        start += count;
        remaining -= count;
        idx++;
        if (idx > SM2_PKI_ISSUANCE_MAX_PEAKS)
            return SM2_IC_ERR_VERIFY;
    }
    *peak_count = idx;
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
    if (proof->sibling_count > SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH
        || proof->peak_count == 0
        || proof->peak_count > SM2_PKI_ISSUANCE_MAX_PEAKS
        || proof->peak_index >= proof->peak_count)
    {
        return SM2_IC_ERR_VERIFY;
    }

    size_t expected_peak = 0;
    size_t expected_peak_count = 0;
    size_t expected_height = 0;
    sm2_ic_error_t ret
        = pki_issuance_expected_peak(proof->leaf_count, proof->leaf_index,
            &expected_peak, &expected_peak_count, &expected_height);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (proof->peak_index != expected_peak
        || proof->peak_count != expected_peak_count
        || proof->sibling_count != expected_height)
    {
        return SM2_IC_ERR_VERIFY;
    }
    return SM2_IC_SUCCESS;
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

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        if (proof->sibling_on_left[i])
            ret = pki_issuance_hash_parent(proof->sibling_hashes[i], cur, next);
        else
            ret = pki_issuance_hash_parent(cur, proof->sibling_hashes[i], next);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        memcpy(cur, next, SM2_REV_MERKLE_HASH_LEN);
    }

    if (memcmp(
            cur, proof->peak_hashes[proof->peak_index], SM2_REV_MERKLE_HASH_LEN)
        != 0)
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint8_t expected_root[SM2_REV_MERKLE_HASH_LEN];
    ret = pki_issuance_hash_root(proof->leaf_count, proof->peak_count,
        proof->peak_hashes, expected_root);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    return memcmp(expected_root, root_hash, SM2_REV_MERKLE_HASH_LEN) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}
