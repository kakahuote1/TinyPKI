/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_client.c
 * @brief PKI client library implementation.
 */

#include "pki_internal.h"
#include "sm2_secure_mem.h"
#include <stdlib.h>
#include <string.h>

static sm2_pki_client_state_t *pki_client_state(sm2_pki_client_ctx_t *ctx)
{
    return ctx;
}

static const sm2_pki_client_state_t *pki_client_state_const(
    const sm2_pki_client_ctx_t *ctx)
{
    return ctx;
}

typedef struct
{
    const sm2_auth_trust_store_t *store;
    bool require_specific_index;
    size_t required_index;
} pki_client_root_verify_ctx_t;

#define SM2_PKI_WITNESS_PAYLOAD_MAX 1024U
#define SM2_PKI_SM3_BLOCK_LEN 64U

static sm2_ic_error_t pki_client_root_record_verify_cb(void *user_ctx,
    const uint8_t *data, size_t data_len, const uint8_t *signature,
    size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;
    if (signature_len == 0 || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return SM2_IC_ERR_VERIFY;

    const pki_client_root_verify_ctx_t *ctx
        = (const pki_client_root_verify_ctx_t *)user_ctx;
    if (!ctx->store || ctx->store->count == 0)
        return SM2_IC_ERR_PARAM;
    if (ctx->require_specific_index && ctx->required_index >= ctx->store->count)
        return SM2_IC_ERR_VERIFY;

    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    if (ctx->require_specific_index)
    {
        return sm2_auth_verify_signature(
            &ctx->store->ca_pub_keys[ctx->required_index], data, data_len,
            &sig);
    }

    for (size_t i = 0; i < ctx->store->count; i++)
    {
        if (sm2_auth_verify_signature(
                &ctx->store->ca_pub_keys[i], data, data_len, &sig)
            == SM2_IC_SUCCESS)
        {
            return SM2_IC_SUCCESS;
        }
    }

    return SM2_IC_ERR_VERIFY;
}

static bool pki_client_authority_id_valid(
    const uint8_t *authority_id, size_t authority_id_len)
{
    return authority_id && authority_id_len > 0
        && authority_id_len <= SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN;
}

static bool pki_client_bound_service_live(const sm2_pki_client_state_t *state)
{
    return state && sm2_pki_service_binding_live(state->revocation_service);
}

static sm2_pki_epoch_cache_entry_t *pki_client_find_epoch_root_cache_entry(
    sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len)
{
    if (!state
        || !pki_client_authority_id_valid(authority_id, authority_id_len))
        return NULL;

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        sm2_pki_epoch_cache_entry_t *entry = &state->epoch_root_cache[i];
        if (!entry->used || entry->authority_id_len != authority_id_len)
            continue;
        if (memcmp(entry->authority_id, authority_id, authority_id_len) == 0)
            return entry;
    }

    return NULL;
}

static const sm2_pki_epoch_cache_entry_t *
pki_client_find_epoch_root_cache_entry_const(
    const sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len)
{
    if (!state
        || !pki_client_authority_id_valid(authority_id, authority_id_len))
        return NULL;

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        const sm2_pki_epoch_cache_entry_t *entry = &state->epoch_root_cache[i];
        if (!entry->used || entry->authority_id_len != authority_id_len)
            continue;
        if (memcmp(entry->authority_id, authority_id, authority_id_len) == 0)
            return entry;
    }

    return NULL;
}

static sm2_pki_epoch_cache_entry_t *pki_client_ensure_epoch_root_cache_entry(
    sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len)
{
    sm2_pki_epoch_cache_entry_t *entry = pki_client_find_epoch_root_cache_entry(
        state, authority_id, authority_id_len);
    if (entry)
        return entry;

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        entry = &state->epoch_root_cache[i];
        if (entry->used)
            continue;

        memset(entry, 0, sizeof(*entry));
        memcpy(entry->authority_id, authority_id, authority_id_len);
        entry->authority_id_len = authority_id_len;
        return entry;
    }

    return NULL;
}

static sm2_pki_error_t pki_client_check_epoch_root_freshness(
    const sm2_pki_epoch_cache_entry_t *entry,
    const sm2_pki_epoch_root_record_t *root_record,
    const uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN],
    size_t matched_ca_index)
{
    if (!entry || !root_record || !epoch_digest)
        return SM2_PKI_ERR_PARAM;

    if (root_record->epoch_version < entry->highest_seen_epoch_version)
        return SM2_PKI_ERR_VERIFY;
    if (entry->has_epoch_digest
        && root_record->epoch_version == entry->highest_seen_epoch_version
        && memcmp(
               epoch_digest, entry->epoch_digest, SM2_PKI_EPOCH_ROOT_DIGEST_LEN)
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (entry->has_pinned_ca_index
        && entry->pinned_ca_index != matched_ca_index)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (entry->has_revocation_root)
    {
        if (root_record->revocation_root_version
            < entry->highest_seen_revocation_root_version)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (root_record->revocation_root_version
                == entry->highest_seen_revocation_root_version
            && memcmp(root_record->revocation_root_hash,
                   entry->latest_revocation_root_hash,
                   sizeof(root_record->revocation_root_hash))
                != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
    }
    if (entry->has_issuance_root)
    {
        if (root_record->issuance_root_version
            < entry->highest_seen_issuance_root_version)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (root_record->issuance_root_version
                == entry->highest_seen_issuance_root_version
            && memcmp(root_record->issuance_root_hash,
                   entry->latest_issuance_root_hash,
                   sizeof(root_record->issuance_root_hash))
                != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
    }

    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_expected_authority_from_cert(
    const sm2_implicit_cert_t *cert, const uint8_t **authority_id,
    size_t *authority_id_len)
{
    if (!cert || !authority_id || !authority_id_len)
        return SM2_PKI_ERR_PARAM;
    if ((cert->field_mask & SM2_IC_FIELD_ISSUER_ID) == 0)
        return SM2_PKI_ERR_VERIFY;
    if (!pki_client_authority_id_valid(cert->issuer_id, cert->issuer_id_len))
        return SM2_PKI_ERR_VERIFY;

    *authority_id = cert->issuer_id;
    *authority_id_len = cert->issuer_id_len;
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_accept_epoch_root_record(
    sm2_pki_client_state_t *state,
    const sm2_pki_epoch_root_record_t *root_record, uint64_t now_ts,
    size_t matched_ca_index,
    const sm2_pki_transparency_witness_signature_t *witness_signatures,
    size_t witness_signature_count)
{
    if (!state || !root_record)
        return SM2_PKI_ERR_PARAM;
    if ((!witness_signatures && witness_signature_count > 0)
        || witness_signature_count > SM2_PKI_TRANSPARENCY_MAX_WITNESSES)
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (!pki_client_authority_id_valid(
            root_record->authority_id, root_record->authority_id_len))
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (matched_ca_index >= state->trust_store.count)
        return SM2_PKI_ERR_VERIFY;

    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = true,
        .required_index = matched_ca_index };
    sm2_ic_error_t ic_ret = sm2_pki_epoch_root_verify(
        root_record, now_ts, pki_client_root_record_verify_cb, &verify_ctx);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    ic_ret = sm2_pki_epoch_root_digest(root_record, epoch_digest);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    sm2_pki_epoch_cache_entry_t *entry
        = pki_client_ensure_epoch_root_cache_entry(
            state, root_record->authority_id, root_record->authority_id_len);
    if (!entry)
        return SM2_PKI_ERR_MEMORY;

    sm2_pki_error_t ret = pki_client_check_epoch_root_freshness(
        entry, root_record, epoch_digest, matched_ca_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    entry->epoch_record = *root_record;
    memset(entry->witness_signatures, 0, sizeof(entry->witness_signatures));
    if (witness_signature_count > 0)
    {
        memcpy(entry->witness_signatures, witness_signatures,
            witness_signature_count * sizeof(entry->witness_signatures[0]));
    }
    entry->witness_signature_count = witness_signature_count;
    memcpy(entry->epoch_digest, epoch_digest, sizeof(entry->epoch_digest));
    entry->used = true;
    entry->has_epoch_record = true;
    entry->has_epoch_digest = true;
    entry->has_pinned_ca_index = true;
    entry->pinned_ca_index = matched_ca_index;
    if (root_record->epoch_version > entry->highest_seen_epoch_version)
        entry->highest_seen_epoch_version = root_record->epoch_version;
    entry->highest_seen_revocation_root_version
        = root_record->revocation_root_version;
    memcpy(entry->latest_revocation_root_hash,
        root_record->revocation_root_hash,
        sizeof(entry->latest_revocation_root_hash));
    entry->has_revocation_root = true;
    entry->highest_seen_issuance_root_version
        = root_record->issuance_root_version;
    memcpy(entry->latest_issuance_root_hash, root_record->issuance_root_hash,
        sizeof(entry->latest_issuance_root_hash));
    entry->has_issuance_root = true;
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_match_epoch_root_ca(
    sm2_pki_client_state_t *state,
    const sm2_pki_epoch_root_record_t *root_record, uint64_t now_ts,
    size_t *matched_ca_index)
{
    if (!state || !root_record || !matched_ca_index)
        return SM2_PKI_ERR_PARAM;
    if (state->trust_store.count == 0)
        return SM2_PKI_ERR_VERIFY;

    for (size_t i = 0; i < state->trust_store.count; i++)
    {
        pki_client_root_verify_ctx_t verify_ctx
            = { .store = &state->trust_store,
                  .require_specific_index = true,
                  .required_index = i };
        sm2_ic_error_t ic_ret = sm2_pki_epoch_root_verify(
            root_record, now_ts, pki_client_root_record_verify_cb, &verify_ctx);
        if (ic_ret == SM2_IC_SUCCESS)
        {
            *matched_ca_index = i;
            return SM2_PKI_SUCCESS;
        }
    }

    return SM2_PKI_ERR_VERIFY;
}

static sm2_pki_error_t pki_client_epoch_root_digest_matches(
    const sm2_pki_epoch_root_record_t *root_record,
    const uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN])
{
    uint8_t actual_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    if (!root_record || !digest)
        return SM2_PKI_ERR_PARAM;

    sm2_ic_error_t ic_ret
        = sm2_pki_epoch_root_digest(root_record, actual_digest);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    return memcmp(actual_digest, digest, sizeof(actual_digest)) == 0
        ? SM2_PKI_SUCCESS
        : SM2_PKI_ERR_VERIFY;
}

static void pki_client_cache_reset(sm2_pki_client_state_t *state)
{
    if (!state)
        return;
    memset(state->evidence_cache, 0, sizeof(state->evidence_cache));
    state->evidence_cache_counter = 0;
}

static void pki_client_epoch_cache_drop_checkpoints(
    sm2_pki_client_state_t *state)
{
    if (!state)
        return;
    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        state->epoch_root_cache[i].has_epoch_record = false;
        state->epoch_root_cache[i].witness_signature_count = 0;
    }
}

static void pki_client_cache_u64_to_be(uint64_t v, uint8_t out[8])
{
    for (size_t i = 0; i < 8U; i++)
        out[7U - i] = (uint8_t)(v >> (i * 8U));
}

static void pki_client_cache_u32_to_be(uint32_t v, uint8_t out[4])
{
    for (size_t i = 0; i < 4U; i++)
        out[3U - i] = (uint8_t)(v >> (i * 8U));
}

static sm2_pki_error_t pki_client_cache_mix(
    uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN], const void *data,
    size_t data_len)
{
    if (!digest || (!data && data_len > 0U)
        || data_len > SM2_REV_MERKLE_HASH_LEN)
        return SM2_PKI_ERR_PARAM;

    uint8_t buf[SM2_PKI_EPOCH_ROOT_DIGEST_LEN + 8U + SM2_REV_MERKLE_HASH_LEN];
    uint8_t len_be[8];
    pki_client_cache_u64_to_be((uint64_t)data_len, len_be);
    memcpy(buf, digest, SM2_PKI_EPOCH_ROOT_DIGEST_LEN);
    memcpy(buf + SM2_PKI_EPOCH_ROOT_DIGEST_LEN, len_be, sizeof(len_be));
    if (data_len > 0U)
        memcpy(buf + SM2_PKI_EPOCH_ROOT_DIGEST_LEN + sizeof(len_be), data,
            data_len);
    return sm2_pki_sm3_hash(
        buf, SM2_PKI_EPOCH_ROOT_DIGEST_LEN + sizeof(len_be) + data_len, digest);
}

static sm2_pki_error_t pki_client_cache_mix_u64(
    uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN], uint64_t v)
{
    uint8_t tmp[8];
    pki_client_cache_u64_to_be(v, tmp);
    return pki_client_cache_mix(digest, tmp, sizeof(tmp));
}

static sm2_pki_error_t pki_client_cache_mix_byte(
    uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN], uint8_t v)
{
    return pki_client_cache_mix(digest, &v, sizeof(v));
}

static bool pki_client_bytes_equal_ct(
    const uint8_t *a, const uint8_t *b, size_t len)
{
    if (!a || !b)
        return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static sm2_pki_error_t pki_client_hmac_sm3(const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out[SM2_PKI_EPOCH_ROOT_DIGEST_LEN])
{
    if (!key || key_len == 0 || (!data && data_len > 0U) || !out)
        return SM2_PKI_ERR_PARAM;
    if (data_len > SIZE_MAX - SM2_PKI_SM3_BLOCK_LEN)
        return SM2_PKI_ERR_MEMORY;

    uint8_t key_block[SM2_PKI_SM3_BLOCK_LEN];
    uint8_t key_hash[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    uint8_t inner_hash[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    uint8_t outer[SM2_PKI_SM3_BLOCK_LEN + SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    memset(key_block, 0, sizeof(key_block));
    memset(key_hash, 0, sizeof(key_hash));
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(outer, 0, sizeof(outer));

    sm2_pki_error_t ret = SM2_PKI_SUCCESS;
    if (key_len > SM2_PKI_SM3_BLOCK_LEN)
    {
        ret = sm2_pki_sm3_hash(key, key_len, key_hash);
        if (ret != SM2_PKI_SUCCESS)
            goto cleanup_stack;
        memcpy(key_block, key_hash, sizeof(key_hash));
    }
    else
    {
        memcpy(key_block, key, key_len);
    }

    size_t inner_len = SM2_PKI_SM3_BLOCK_LEN + data_len;
    uint8_t *inner = (uint8_t *)malloc(inner_len);
    if (!inner)
    {
        ret = SM2_PKI_ERR_MEMORY;
        goto cleanup_stack;
    }

    for (size_t i = 0; i < SM2_PKI_SM3_BLOCK_LEN; i++)
        inner[i] = (uint8_t)(key_block[i] ^ 0x36U);
    if (data_len > 0U)
        memcpy(inner + SM2_PKI_SM3_BLOCK_LEN, data, data_len);
    ret = sm2_pki_sm3_hash(inner, inner_len, inner_hash);
    sm2_secure_memzero(inner, inner_len);
    free(inner);
    if (ret != SM2_PKI_SUCCESS)
        goto cleanup_stack;

    for (size_t i = 0; i < SM2_PKI_SM3_BLOCK_LEN; i++)
        outer[i] = (uint8_t)(key_block[i] ^ 0x5CU);
    memcpy(outer + SM2_PKI_SM3_BLOCK_LEN, inner_hash, sizeof(inner_hash));
    ret = sm2_pki_sm3_hash(outer, sizeof(outer), out);

cleanup_stack:
    sm2_secure_memzero(key_block, sizeof(key_block));
    sm2_secure_memzero(key_hash, sizeof(key_hash));
    sm2_secure_memzero(inner_hash, sizeof(inner_hash));
    sm2_secure_memzero(outer, sizeof(outer));
    return ret;
}

static sm2_pki_error_t pki_client_persisted_state_shape_valid(
    const sm2_pki_client_persisted_state_t *state)
{
    if (!state)
        return SM2_PKI_ERR_PARAM;
    if (state->format_version != SM2_PKI_CLIENT_PERSISTED_STATE_VERSION
        || state->record_count > SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    for (size_t i = 0; i < state->record_count; i++)
    {
        const sm2_pki_client_persisted_authority_state_t *record
            = &state->records[i];
        if (!pki_client_authority_id_valid(
                record->authority_id, record->authority_id_len))
        {
            return SM2_PKI_ERR_VERIFY;
        }
    }
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_persisted_storage_slot_tag(
    const sm2_pki_client_persisted_storage_slot_t *slot,
    const uint8_t *device_secret, size_t device_secret_len,
    uint8_t tag[SM2_PKI_CLIENT_PERSISTED_STORAGE_TAG_LEN])
{
    static const uint8_t domain[] = "TinyPKI persisted storage slot v1";
    if (!slot || !tag)
        return SM2_PKI_ERR_PARAM;

    size_t auth_len = sizeof(domain) - 1U + 4U + 4U + 8U + sizeof(slot->state);
    uint8_t *auth = (uint8_t *)malloc(auth_len);
    if (!auth)
        return SM2_PKI_ERR_MEMORY;

    size_t off = 0;
    memcpy(auth + off, domain, sizeof(domain) - 1U);
    off += sizeof(domain) - 1U;
    pki_client_cache_u32_to_be(slot->magic, auth + off);
    off += 4U;
    pki_client_cache_u32_to_be(slot->format_version, auth + off);
    off += 4U;
    pki_client_cache_u64_to_be(slot->sequence, auth + off);
    off += 8U;
    memcpy(auth + off, &slot->state, sizeof(slot->state));
    off += sizeof(slot->state);

    sm2_pki_error_t ret = off == auth_len
        ? pki_client_hmac_sm3(
              device_secret, device_secret_len, auth, auth_len, tag)
        : SM2_PKI_ERR_STATE;
    sm2_secure_memzero(auth, auth_len);
    free(auth);
    return ret;
}

static bool pki_client_persisted_storage_slot_valid(
    const sm2_pki_client_persisted_storage_slot_t *slot,
    const uint8_t *device_secret, size_t device_secret_len)
{
    if (!slot || !device_secret || device_secret_len == 0)
        return false;
    if (slot->magic != SM2_PKI_CLIENT_PERSISTED_STORAGE_MAGIC
        || slot->format_version != SM2_PKI_CLIENT_PERSISTED_STORAGE_VERSION
        || slot->sequence == 0)
    {
        return false;
    }
    if (pki_client_persisted_state_shape_valid(&slot->state) != SM2_PKI_SUCCESS)
    {
        return false;
    }

    uint8_t expected[SM2_PKI_CLIENT_PERSISTED_STORAGE_TAG_LEN];
    memset(expected, 0, sizeof(expected));
    sm2_pki_error_t ret = pki_client_persisted_storage_slot_tag(
        slot, device_secret, device_secret_len, expected);
    if (ret != SM2_PKI_SUCCESS)
    {
        sm2_secure_memzero(expected, sizeof(expected));
        return false;
    }
    bool ok = pki_client_bytes_equal_ct(expected, slot->tag, sizeof(expected));
    sm2_secure_memzero(expected, sizeof(expected));
    return ok;
}

static sm2_pki_error_t pki_client_evidence_proof_digest(
    const sm2_pki_evidence_bundle_t *evidence,
    uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN])
{
    if (!evidence || !digest)
        return SM2_PKI_ERR_PARAM;

    const sm2_rev_absence_proof_t *rev
        = &evidence->revocation_proof.absence_proof;
    const sm2_pki_issuance_member_proof_t *iss
        = &evidence->issuance_proof.member_proof;
    if (rev->sibling_count > SM2_REV_MERKLE_MAX_DEPTH
        || iss->sibling_count > SM2_PKI_ISSUANCE_MAX_PROOF_DEPTH
        || iss->peak_count > SM2_PKI_ISSUANCE_MAX_PEAKS)
    {
        return SM2_PKI_ERR_VERIFY;
    }

    static const uint8_t tag[] = "SM2PKI_EVIDENCE_CACHE_V1";
    sm2_pki_error_t ret = sm2_pki_sm3_hash(tag, sizeof(tag) - 1U, digest);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix(
        digest, evidence->epoch_digest, sizeof(evidence->epoch_digest));
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    ret = pki_client_cache_mix_u64(digest, rev->target_serial);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix(
        digest, rev->target_key, sizeof(rev->target_key));
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_byte(digest, rev->tree_empty ? 1U : 0U);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_u64(digest, (uint64_t)rev->terminal_depth);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix(
        digest, rev->terminal_key, sizeof(rev->terminal_key));
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix(
        digest, rev->terminal_hash, sizeof(rev->terminal_hash));
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_u64(digest, (uint64_t)rev->sibling_count);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    for (size_t i = 0; i < rev->sibling_count; i++)
    {
        ret = pki_client_cache_mix_u64(
            digest, (uint64_t)rev->sibling_depths[i]);
        if (ret != SM2_PKI_SUCCESS)
            return ret;
        ret = pki_client_cache_mix(
            digest, rev->sibling_hashes[i], sizeof(rev->sibling_hashes[i]));
        if (ret != SM2_PKI_SUCCESS)
            return ret;
        ret = pki_client_cache_mix_byte(
            digest, rev->sibling_on_left[i] ? 1U : 0U);
        if (ret != SM2_PKI_SUCCESS)
            return ret;
    }

    ret = pki_client_cache_mix(
        digest, iss->cert_commitment, sizeof(iss->cert_commitment));
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_u64(digest, (uint64_t)iss->leaf_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_u64(digest, (uint64_t)iss->leaf_count);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_u64(digest, (uint64_t)iss->sibling_count);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    for (size_t i = 0; i < iss->sibling_count; i++)
    {
        ret = pki_client_cache_mix(
            digest, iss->sibling_hashes[i], sizeof(iss->sibling_hashes[i]));
        if (ret != SM2_PKI_SUCCESS)
            return ret;
        ret = pki_client_cache_mix_byte(
            digest, iss->sibling_on_left[i] ? 1U : 0U);
        if (ret != SM2_PKI_SUCCESS)
            return ret;
    }
    ret = pki_client_cache_mix_u64(digest, (uint64_t)iss->peak_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_cache_mix_u64(digest, (uint64_t)iss->peak_count);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    for (size_t i = 0; i < iss->peak_count; i++)
    {
        ret = pki_client_cache_mix(
            digest, iss->peak_hashes[i], sizeof(iss->peak_hashes[i]));
        if (ret != SM2_PKI_SUCCESS)
            return ret;
    }

    return SM2_PKI_SUCCESS;
}

static uint64_t pki_client_cert_valid_until(const sm2_implicit_cert_t *cert)
{
    if (!cert || (cert->field_mask & SM2_IC_FIELD_VALID_FROM) == 0
        || (cert->field_mask & SM2_IC_FIELD_VALID_DURATION) == 0)
    {
        return 0;
    }
    if (cert->valid_duration > UINT64_MAX - cert->valid_from)
        return UINT64_MAX;
    return cert->valid_from + cert->valid_duration;
}

static bool pki_client_evidence_cache_hit(sm2_pki_client_state_t *state,
    const sm2_implicit_cert_t *cert, const sm2_pki_epoch_root_record_t *epoch,
    const uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN],
    const uint8_t cert_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    const uint8_t proof_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN], uint64_t now_ts,
    size_t matched_ca_index)
{
    if (!state || !cert || !epoch || !epoch_digest || !cert_commitment
        || !proof_digest)
    {
        return false;
    }

    for (size_t i = 0; i < SM2_PKI_VERIFIED_EVIDENCE_CACHE_CAPACITY; i++)
    {
        sm2_pki_verified_evidence_cache_entry_t *entry
            = &state->evidence_cache[i];
        if (!entry->used || entry->valid_until < now_ts)
            continue;
        if (entry->serial_number != cert->serial_number
            || entry->pinned_ca_index != matched_ca_index
            || entry->authority_id_len != epoch->authority_id_len
            || memcmp(entry->authority_id, epoch->authority_id,
                   epoch->authority_id_len)
                != 0
            || memcmp(entry->cert_commitment, cert_commitment,
                   SM2_PKI_ISSUANCE_COMMITMENT_LEN)
                != 0
            || memcmp(entry->epoch_digest, epoch_digest,
                   SM2_PKI_EPOCH_ROOT_DIGEST_LEN)
                != 0
            || memcmp(entry->proof_digest, proof_digest,
                   SM2_PKI_EPOCH_ROOT_DIGEST_LEN)
                != 0
            || entry->epoch_version != epoch->epoch_version
            || entry->revocation_root_version != epoch->revocation_root_version
            || memcmp(entry->revocation_root_hash, epoch->revocation_root_hash,
                   SM2_REV_MERKLE_HASH_LEN)
                != 0
            || entry->issuance_root_version != epoch->issuance_root_version
            || memcmp(entry->issuance_root_hash, epoch->issuance_root_hash,
                   SM2_REV_MERKLE_HASH_LEN)
                != 0)
        {
            continue;
        }

        if (state->evidence_cache_counter == UINT64_MAX)
        {
            pki_client_cache_reset(state);
            return false;
        }
        state->evidence_cache_counter++;
        entry->last_used_counter = state->evidence_cache_counter;
        return true;
    }
    return false;
}

static void pki_client_evidence_cache_store(sm2_pki_client_state_t *state,
    const sm2_implicit_cert_t *cert, const sm2_pki_epoch_root_record_t *epoch,
    const uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN],
    const uint8_t cert_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    const uint8_t proof_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN],
    size_t matched_ca_index)
{
    if (!state || !cert || !epoch || !epoch_digest || !cert_commitment
        || !proof_digest)
    {
        return;
    }

    uint64_t cert_until = pki_client_cert_valid_until(cert);
    uint64_t valid_until = cert_until != 0 && cert_until < epoch->valid_until
        ? cert_until
        : epoch->valid_until;
    if (valid_until == 0)
        return;
    if (state->evidence_cache_counter == UINT64_MAX)
        pki_client_cache_reset(state);

    sm2_pki_verified_evidence_cache_entry_t *slot = NULL;
    for (size_t i = 0; i < SM2_PKI_VERIFIED_EVIDENCE_CACHE_CAPACITY; i++)
    {
        if (!state->evidence_cache[i].used)
        {
            slot = &state->evidence_cache[i];
            break;
        }
        if (!slot
            || state->evidence_cache[i].last_used_counter
                < slot->last_used_counter)
        {
            slot = &state->evidence_cache[i];
        }
    }
    if (!slot)
        return;

    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->authority_id, epoch->authority_id, epoch->authority_id_len);
    slot->authority_id_len = epoch->authority_id_len;
    slot->pinned_ca_index = matched_ca_index;
    slot->serial_number = cert->serial_number;
    memcpy(slot->cert_commitment, cert_commitment,
        SM2_PKI_ISSUANCE_COMMITMENT_LEN);
    memcpy(slot->epoch_digest, epoch_digest, SM2_PKI_EPOCH_ROOT_DIGEST_LEN);
    memcpy(slot->proof_digest, proof_digest, SM2_PKI_EPOCH_ROOT_DIGEST_LEN);
    slot->epoch_version = epoch->epoch_version;
    slot->revocation_root_version = epoch->revocation_root_version;
    memcpy(slot->revocation_root_hash, epoch->revocation_root_hash,
        SM2_REV_MERKLE_HASH_LEN);
    slot->issuance_root_version = epoch->issuance_root_version;
    memcpy(slot->issuance_root_hash, epoch->issuance_root_hash,
        SM2_REV_MERKLE_HASH_LEN);
    slot->valid_until = valid_until;
    state->evidence_cache_counter++;
    slot->last_used_counter = state->evidence_cache_counter;
}

static sm2_pki_error_t pki_client_get_cached_epoch_root(
    sm2_pki_client_state_t *state, const sm2_implicit_cert_t *cert,
    uint64_t now_ts, size_t matched_ca_index,
    const sm2_pki_epoch_root_record_t **epoch)
{
    if (!state || !cert || !epoch)
        return SM2_PKI_ERR_PARAM;

    const uint8_t *authority_id = NULL;
    size_t authority_id_len = 0;
    sm2_pki_error_t ret = pki_client_expected_authority_from_cert(
        cert, &authority_id, &authority_id_len);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    sm2_pki_epoch_cache_entry_t *entry = pki_client_find_epoch_root_cache_entry(
        state, authority_id, authority_id_len);
    if (!entry || !entry->has_epoch_record || !entry->has_pinned_ca_index)
        return SM2_PKI_ERR_VERIFY;
    if (entry->pinned_ca_index != matched_ca_index)
        return SM2_PKI_ERR_VERIFY;

    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = true,
        .required_index = matched_ca_index };
    sm2_ic_error_t ic_ret = sm2_pki_epoch_root_verify(&entry->epoch_record,
        now_ts, pki_client_root_record_verify_cb, &verify_ctx);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    *epoch = &entry->epoch_record;
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_map_service_failure_closed(
    sm2_pki_error_t ret)
{
    if (ret == SM2_PKI_SUCCESS)
        return SM2_PKI_SUCCESS;
    if (ret == SM2_PKI_ERR_MEMORY)
        return ret;
    return SM2_PKI_ERR_VERIFY;
}

static sm2_pki_error_t pki_client_verify_without_revocation(
    const sm2_pki_client_state_t *state,
    const sm2_pki_verify_request_t *request, uint64_t now_ts,
    size_t *matched_ca_index)
{
    if (!state || !request)
        return SM2_PKI_ERR_PARAM;

    sm2_auth_request_t req;
    sm2_auth_request_init(&req);
    req.cert = request->cert;
    req.public_key = request->public_key;
    req.message = request->message;
    req.message_len = request->message_len;
    req.signature = request->signature;
    req.allow_missing_revocation_check = true;

    return sm2_pki_error_from_ic(sm2_auth_authenticate_request(
        &req, &state->trust_store, NULL, now_ts, matched_ca_index));
}

static bool pki_client_witness_id_valid(
    const uint8_t *witness_id, size_t witness_id_len)
{
    return witness_id && witness_id_len > 0
        && witness_id_len <= SM2_PKI_TRANSPARENCY_WITNESS_ID_MAX_LEN;
}

static bool pki_client_public_keys_equal(
    const sm2_ec_point_t *a, const sm2_ec_point_t *b)
{
    return a && b && memcmp(a->x, b->x, sizeof(a->x)) == 0
        && memcmp(a->y, b->y, sizeof(a->y)) == 0;
}

static bool pki_client_find_trusted_ca_index(
    const sm2_pki_client_state_t *state, const sm2_ec_point_t *ca_public_key,
    size_t *matched_ca_index)
{
    if (!state || !ca_public_key || state->trust_store.count == 0)
        return false;

    for (size_t i = 0; i < state->trust_store.count; i++)
    {
        if (pki_client_public_keys_equal(
                &state->trust_store.ca_pub_keys[i], ca_public_key))
        {
            if (matched_ca_index)
                *matched_ca_index = i;
            return true;
        }
    }
    return false;
}

static bool pki_client_trust_store_contains_ca(
    const sm2_pki_client_state_t *state, const sm2_ec_point_t *ca_public_key)
{
    return pki_client_find_trusted_ca_index(state, ca_public_key, NULL);
}

static sm2_pki_error_t pki_client_validate_transparency_policy(
    const sm2_pki_transparency_policy_t *policy)
{
    if (!policy || policy->threshold == 0)
        return SM2_PKI_ERR_PARAM;
    if (!policy->witnesses || policy->witness_count == 0
        || policy->witness_count > SM2_PKI_TRANSPARENCY_MAX_WITNESSES
        || policy->threshold > policy->witness_count)
    {
        return SM2_PKI_ERR_PARAM;
    }
    for (size_t i = 0; i < policy->witness_count; i++)
    {
        const sm2_pki_transparency_witness_t *witness = &policy->witnesses[i];
        if (!pki_client_witness_id_valid(
                witness->witness_id, witness->witness_id_len))
        {
            return SM2_PKI_ERR_PARAM;
        }
        for (size_t j = i + 1; j < policy->witness_count; j++)
        {
            if (witness->witness_id_len == policy->witnesses[j].witness_id_len
                && memcmp(witness->witness_id, policy->witnesses[j].witness_id,
                       witness->witness_id_len)
                    == 0)
            {
                return SM2_PKI_ERR_PARAM;
            }
            if (pki_client_public_keys_equal(
                    &witness->public_key, &policy->witnesses[j].public_key))
            {
                return SM2_PKI_ERR_PARAM;
            }
        }
    }
    return SM2_PKI_SUCCESS;
}

sm2_ic_error_t sm2_pki_transparency_policy_digest(
    const sm2_pki_transparency_policy_t *policy,
    uint8_t digest[SM2_PKI_POLICY_DIGEST_LEN])
{
    static const uint8_t tag[] = "SM2PKI_WITNESS_POLICY_V1";
    if (!digest)
        return SM2_IC_ERR_PARAM;
    if (pki_client_validate_transparency_policy(policy) != SM2_PKI_SUCCESS)
        return SM2_IC_ERR_PARAM;

    size_t need = sizeof(tag) - 1U + 8U + 8U;
    for (size_t i = 0; i < policy->witness_count; i++)
        need += 8U + policy->witnesses[i].witness_id_len + SM2_KEY_LEN * 2U;

    uint8_t *auth = (uint8_t *)malloc(need);
    if (!auth)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    memcpy(auth + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    pki_client_cache_u64_to_be((uint64_t)policy->threshold, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be((uint64_t)policy->witness_count, auth + off);
    off += 8U;
    for (size_t i = 0; i < policy->witness_count; i++)
    {
        const sm2_pki_transparency_witness_t *witness = &policy->witnesses[i];
        pki_client_cache_u64_to_be(
            (uint64_t)witness->witness_id_len, auth + off);
        off += 8U;
        memcpy(auth + off, witness->witness_id, witness->witness_id_len);
        off += witness->witness_id_len;
        memcpy(auth + off, witness->public_key.x, SM2_KEY_LEN);
        off += SM2_KEY_LEN;
        memcpy(auth + off, witness->public_key.y, SM2_KEY_LEN);
        off += SM2_KEY_LEN;
    }

    sm2_ic_error_t ret
        = off == need ? sm2_ic_sm3_hash(auth, off, digest) : SM2_IC_ERR_PARAM;
    sm2_secure_memzero(auth, need);
    free(auth);
    return ret;
}

sm2_ic_error_t sm2_pki_default_sync_policy_digest(
    uint8_t digest[SM2_PKI_POLICY_DIGEST_LEN])
{
    static const uint8_t tag[] = "SM2PKI_SYNC_POLICY_V1";
    if (!digest)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sync_policy_t policy;
    sm2_ic_error_t ret = sm2_rev_sync_policy_init(&policy);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint8_t auth[(sizeof(tag) - 1U) + 8U * 7U];
    size_t off = 0;
    memcpy(auth + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    pki_client_cache_u64_to_be(policy.t_base_sec, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be(policy.fast_poll_sec, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be(policy.max_backoff_sec, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be(policy.propagation_delay_sec, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be(policy.full_checkpoint_interval_sec, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be(
        (uint64_t)policy.max_delta_chain_len, auth + off);
    off += 8U;
    pki_client_cache_u64_to_be(policy.urgent_delta_grace_sec, auth + off);
    off += 8U;

    return off == sizeof(auth) ? sm2_ic_sm3_hash(auth, off, digest)
                               : SM2_IC_ERR_PARAM;
}

static sm2_pki_error_t pki_client_check_epoch_policy_binding(
    const sm2_pki_client_state_t *state,
    const sm2_pki_epoch_root_record_t *root_record)
{
    if (!state || !root_record || !state->has_transparency_policy)
        return SM2_PKI_ERR_VERIFY;
    if (root_record->witness_policy_version
            != SM2_PKI_DEFAULT_WITNESS_POLICY_VERSION
        || root_record->sync_policy_version
            != SM2_PKI_DEFAULT_SYNC_POLICY_VERSION)
    {
        return SM2_PKI_ERR_VERIFY;
    }

    uint8_t witness_digest[SM2_PKI_POLICY_DIGEST_LEN];
    uint8_t sync_digest[SM2_PKI_POLICY_DIGEST_LEN];
    sm2_ic_error_t ic_ret = sm2_pki_transparency_policy_digest(
        &state->transparency_policy, witness_digest);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    ic_ret = sm2_pki_default_sync_policy_digest(sync_digest);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    bool ok = pki_client_bytes_equal_ct(root_record->witness_policy_hash,
                  witness_digest, sizeof(witness_digest))
        && pki_client_bytes_equal_ct(
            root_record->sync_policy_hash, sync_digest, sizeof(sync_digest));
    sm2_secure_memzero(witness_digest, sizeof(witness_digest));
    sm2_secure_memzero(sync_digest, sizeof(sync_digest));
    return ok ? SM2_PKI_SUCCESS : SM2_PKI_ERR_VERIFY;
}
static sm2_pki_error_t pki_client_verify_witness_signature_set(
    const uint8_t *payload, size_t payload_len,
    const sm2_pki_transparency_witness_signature_t *signatures,
    size_t signature_count, const sm2_pki_transparency_policy_t *policy);

static sm2_pki_error_t pki_client_verify_witness_signature_set(
    const uint8_t *payload, size_t payload_len,
    const sm2_pki_transparency_witness_signature_t *signatures,
    size_t signature_count, const sm2_pki_transparency_policy_t *policy)
{
    bool used[SM2_PKI_TRANSPARENCY_MAX_WITNESSES];
    size_t valid_count = 0;

    if (!policy || policy->threshold == 0)
        return SM2_PKI_ERR_VERIFY;
    if (!payload || payload_len == 0 || (!signatures && signature_count > 0))
        return SM2_PKI_ERR_VERIFY;
    if (!policy->witnesses || policy->witness_count == 0
        || policy->witness_count > SM2_PKI_TRANSPARENCY_MAX_WITNESSES
        || policy->threshold > policy->witness_count
        || signature_count > SM2_PKI_TRANSPARENCY_MAX_WITNESSES)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (pki_client_validate_transparency_policy(policy) != SM2_PKI_SUCCESS)
        return SM2_PKI_ERR_VERIFY;

    memset(used, 0, sizeof(used));

    for (size_t i = 0; i < signature_count; i++)
    {
        const sm2_pki_transparency_witness_signature_t *sig_entry
            = &signatures[i];
        if (!pki_client_witness_id_valid(
                sig_entry->witness_id, sig_entry->witness_id_len)
            || sig_entry->signature_len == 0
            || sig_entry->signature_len > sizeof(sig_entry->signature))
        {
            return SM2_PKI_ERR_VERIFY;
        }

        for (size_t j = 0; j < policy->witness_count; j++)
        {
            const sm2_pki_transparency_witness_t *witness
                = &policy->witnesses[j];
            if (used[j] || witness->witness_id_len != sig_entry->witness_id_len
                || memcmp(witness->witness_id, sig_entry->witness_id,
                       sig_entry->witness_id_len)
                    != 0)
            {
                continue;
            }

            sm2_auth_signature_t sig;
            memset(&sig, 0, sizeof(sig));
            memcpy(sig.der, sig_entry->signature, sig_entry->signature_len);
            sig.der_len = sig_entry->signature_len;
            if (sm2_auth_verify_signature(
                    &witness->public_key, payload, payload_len, &sig)
                == SM2_IC_SUCCESS)
            {
                used[j] = true;
                valid_count++;
            }
            break;
        }
    }

    return valid_count >= policy->threshold ? SM2_PKI_SUCCESS
                                            : SM2_PKI_ERR_VERIFY;
}

static sm2_pki_error_t pki_client_verify_epoch_witness_threshold(
    const sm2_pki_epoch_root_record_t *root_record,
    const sm2_pki_transparency_witness_signature_t *signatures,
    size_t signature_count, const sm2_pki_transparency_policy_t *policy)
{
    uint8_t payload[SM2_PKI_WITNESS_PAYLOAD_MAX];
    size_t payload_len = 0;
    if (!root_record)
        return SM2_PKI_ERR_PARAM;
    sm2_ic_error_t ic_ret = sm2_pki_epoch_root_encode_witness_payload(
        root_record, payload, sizeof(payload), &payload_len);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    return pki_client_verify_witness_signature_set(
        payload, payload_len, signatures, signature_count, policy);
}

static sm2_pki_error_t pki_client_verify_revocation_proof_with_epoch(
    const sm2_implicit_cert_t *cert, const sm2_pki_epoch_root_record_t *epoch,
    const sm2_pki_epoch_revocation_proof_t *proof)
{
    if (!cert || !epoch || !proof)
        return SM2_PKI_ERR_PARAM;
    if (proof->absence_proof.target_serial != cert->serial_number)
        return SM2_PKI_ERR_VERIFY;

    sm2_ic_error_t ic_ret = sm2_rev_tree_verify_absence(
        epoch->revocation_root_hash, &proof->absence_proof);
    return sm2_pki_error_from_ic(ic_ret);
}

static sm2_pki_error_t pki_client_verify_issuance_proof_with_epoch(
    const sm2_implicit_cert_t *cert, const sm2_pki_epoch_root_record_t *epoch,
    const sm2_pki_epoch_issuance_proof_t *proof)
{
    if (!cert || !epoch || !proof)
        return SM2_PKI_ERR_PARAM;
    if (proof->member_proof.leaf_count != epoch->issuance_root_version)
        return SM2_PKI_ERR_VERIFY;

    uint8_t expected_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    sm2_ic_error_t ic_ret
        = sm2_pki_issuance_cert_commitment(cert, expected_commitment);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    if (memcmp(proof->member_proof.cert_commitment, expected_commitment,
            sizeof(expected_commitment))
        != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }

    ic_ret = sm2_pki_issuance_tree_verify_member(
        epoch->issuance_root_hash, &proof->member_proof);
    return sm2_pki_error_from_ic(ic_ret);
}

static sm2_pki_error_t pki_client_verify_epoch_evidence_bundle(
    sm2_pki_client_state_t *state, const sm2_implicit_cert_t *cert,
    const sm2_pki_evidence_bundle_t *evidence, uint64_t now_ts,
    size_t matched_ca_index)
{
    if (!state || !cert || !evidence)
        return SM2_PKI_ERR_PARAM;

    const sm2_pki_epoch_root_record_t *cached_epoch = NULL;

    sm2_pki_error_t ret = pki_client_get_cached_epoch_root(
        state, cert, now_ts, matched_ca_index, &cached_epoch);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_epoch_root_digest_matches(
        cached_epoch, evidence->epoch_digest);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    uint8_t cert_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    sm2_ic_error_t ic_ret
        = sm2_pki_issuance_cert_commitment(cert, cert_commitment);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    uint8_t proof_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    ret = pki_client_evidence_proof_digest(evidence, proof_digest);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    if (pki_client_evidence_cache_hit(state, cert, cached_epoch,
            evidence->epoch_digest, cert_commitment, proof_digest, now_ts,
            matched_ca_index))
    {
        return SM2_PKI_SUCCESS;
    }

    ret = pki_client_verify_revocation_proof_with_epoch(
        cert, cached_epoch, &evidence->revocation_proof);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_verify_issuance_proof_with_epoch(
        cert, cached_epoch, &evidence->issuance_proof);
    if (ret == SM2_PKI_SUCCESS)
    {
        pki_client_evidence_cache_store(state, cert, cached_epoch,
            evidence->epoch_digest, cert_commitment, proof_digest,
            matched_ca_index);
    }
    return ret;
}

static void pki_client_release_bound_service(sm2_pki_client_state_t *state)
{
    if (!state || !state->revocation_service)
        return;

    sm2_pki_service_release_revocation_binding(state->revocation_service);
    state->revocation_service = NULL;
}

static sm2_pki_error_t pki_client_require_cert_key_agreement(
    const sm2_implicit_cert_t *cert)
{
    if (!cert)
        return SM2_PKI_ERR_PARAM;
    if ((cert->field_mask & SM2_IC_FIELD_KEY_USAGE) == 0
        || (cert->key_usage & SM2_KU_KEY_AGREEMENT) == 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_validate_keypair(
    const sm2_private_key_t *private_key, const sm2_ec_point_t *public_key)
{
    sm2_ec_point_t derived_public_key;
    if (!private_key || !public_key)
        return SM2_PKI_ERR_PARAM;

    memset(&derived_public_key, 0, sizeof(derived_public_key));
    sm2_ic_error_t ret = sm2_ic_sm2_point_mult(
        &derived_public_key, private_key->d, SM2_KEY_LEN, NULL);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    return memcmp(&derived_public_key, public_key, sizeof(derived_public_key))
            == 0
        ? SM2_PKI_SUCCESS
        : SM2_PKI_ERR_VERIFY;
}

static sm2_pki_error_t pki_client_require_handshake_binding(
    const sm2_pki_verify_request_t *peer_request,
    const sm2_ec_point_t *peer_ephemeral_public_key,
    const sm2_ec_point_t *local_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len)
{
    uint8_t *expected = NULL;
    size_t expected_len = 0;
    if (!peer_request || !peer_request->message || !peer_ephemeral_public_key
        || !local_ephemeral_public_key)
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_pki_error_t ret = sm2_pki_secure_session_build_binding(
        peer_ephemeral_public_key, local_ephemeral_public_key, transcript,
        transcript_len, NULL, &expected_len);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    if (peer_request->message_len != expected_len)
        return SM2_PKI_ERR_VERIFY;

    expected = (uint8_t *)malloc(expected_len);
    if (!expected)
        return SM2_PKI_ERR_MEMORY;

    size_t out_len = expected_len;
    ret = sm2_pki_secure_session_build_binding(peer_ephemeral_public_key,
        local_ephemeral_public_key, transcript, transcript_len, expected,
        &out_len);
    if (ret != SM2_PKI_SUCCESS)
    {
        free(expected);
        return ret;
    }

    ret = memcmp(peer_request->message, expected, expected_len) == 0
        ? SM2_PKI_SUCCESS
        : SM2_PKI_ERR_VERIFY;
    free(expected);
    return ret;
}

static sm2_pki_error_t pki_client_require_local_key_agreement(
    const sm2_pki_client_ctx_t *ctx)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys)
        return SM2_PKI_ERR_PARAM;
    return pki_client_require_cert_key_agreement(&state->cert);
}

sm2_pki_error_t sm2_pki_client_create(sm2_pki_client_ctx_t **ctx,
    const sm2_ec_point_t *default_ca_public_key,
    sm2_pki_service_ctx_t *revocation_service)
{
    if (!ctx)
        return SM2_PKI_ERR_PARAM;
    *ctx = NULL;

    sm2_pki_client_state_t *state
        = (sm2_pki_client_state_t *)calloc(1, sizeof(*state));
    if (!state)
        return SM2_PKI_ERR_MEMORY;

    sm2_ic_error_t ret = sm2_auth_trust_store_init(&state->trust_store);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_client_destroy(&state);
        return sm2_pki_error_from_ic(ret);
    }

    if (default_ca_public_key)
    {
        ret = sm2_auth_trust_store_add_ca(
            &state->trust_store, default_ca_public_key);
        if (ret != SM2_IC_SUCCESS)
        {
            sm2_pki_client_destroy(&state);
            return sm2_pki_error_from_ic(ret);
        }
    }

    state->initialized = true;
    *ctx = state;
    if (revocation_service)
    {
        sm2_pki_error_t bind_ret
            = sm2_pki_client_bind_revocation(state, revocation_service);
        if (bind_ret != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(ctx);
            return bind_ret;
        }
    }
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_destroy(sm2_pki_client_ctx_t **ctx)
{
    if (!ctx || !*ctx)
        return;
    sm2_pki_client_state_t *state = *ctx;
    sm2_pki_client_disable_sign_pool(state);
    if (state)
    {
        pki_client_release_bound_service(state);
        sm2_secure_memzero(state, sizeof(*state));
        free(state);
    }
    *ctx = NULL;
}

sm2_pki_error_t sm2_pki_client_add_trusted_ca(
    sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t *ca_public_key)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !ca_public_key)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(
        sm2_auth_trust_store_add_ca(&state->trust_store, ca_public_key));
}

sm2_pki_error_t sm2_pki_client_set_transparency_policy(
    sm2_pki_client_ctx_t *ctx, const sm2_pki_transparency_policy_t *policy)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;

    sm2_pki_error_t ret = pki_client_validate_transparency_policy(policy);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    memset(state->transparency_witnesses, 0,
        sizeof(state->transparency_witnesses));
    memcpy(state->transparency_witnesses, policy->witnesses,
        policy->witness_count * sizeof(state->transparency_witnesses[0]));
    state->transparency_policy.witnesses = state->transparency_witnesses;
    state->transparency_policy.witness_count = policy->witness_count;
    state->transparency_policy.threshold = policy->threshold;
    state->has_transparency_policy = true;
    pki_client_epoch_cache_drop_checkpoints(state);
    pki_client_cache_reset(state);
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_validate_epoch_checkpoint(
    sm2_pki_client_state_t *state, const sm2_pki_epoch_checkpoint_t *checkpoint,
    uint64_t now_ts, size_t *matched_ca_index)
{
    if (!state || !checkpoint || !matched_ca_index)
        return SM2_PKI_ERR_PARAM;
    if (!state->has_transparency_policy)
        return SM2_PKI_ERR_VERIFY;

    const sm2_pki_transparency_policy_t *policy = &state->transparency_policy;
    sm2_pki_error_t ret = pki_client_validate_transparency_policy(policy);
    if (ret != SM2_PKI_SUCCESS)
        return SM2_PKI_ERR_VERIFY;

    ret = pki_client_match_epoch_root_ca(
        state, &checkpoint->epoch_root_record, now_ts, matched_ca_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    ret = pki_client_check_epoch_policy_binding(
        state, &checkpoint->epoch_root_record);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    return pki_client_verify_epoch_witness_threshold(
        &checkpoint->epoch_root_record, checkpoint->witness_signatures,
        checkpoint->witness_signature_count, policy);
}

sm2_pki_error_t sm2_pki_client_import_epoch_checkpoint(
    sm2_pki_client_ctx_t *ctx, const sm2_pki_epoch_checkpoint_t *checkpoint,
    uint64_t now_ts)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !checkpoint)
        return SM2_PKI_ERR_PARAM;

    size_t matched_ca_index = 0;
    sm2_pki_error_t ret = pki_client_validate_epoch_checkpoint(
        state, checkpoint, now_ts, &matched_ca_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    return pki_client_accept_epoch_root_record(state,
        &checkpoint->epoch_root_record, now_ts, matched_ca_index,
        checkpoint->witness_signatures, checkpoint->witness_signature_count);
}

sm2_pki_error_t sm2_pki_client_export_epoch_checkpoint(
    const sm2_pki_client_ctx_t *ctx, const uint8_t *authority_id,
    size_t authority_id_len, sm2_pki_epoch_checkpoint_t *checkpoint)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !checkpoint
        || !pki_client_authority_id_valid(authority_id, authority_id_len))
    {
        return SM2_PKI_ERR_PARAM;
    }

    const sm2_pki_epoch_cache_entry_t *entry
        = pki_client_find_epoch_root_cache_entry_const(
            state, authority_id, authority_id_len);
    if (!entry || !entry->has_epoch_record
        || entry->witness_signature_count == 0)
        return SM2_PKI_ERR_NOT_FOUND;

    memset(checkpoint, 0, sizeof(*checkpoint));
    checkpoint->epoch_root_record = entry->epoch_record;
    memcpy(checkpoint->witness_signatures, entry->witness_signatures,
        entry->witness_signature_count
            * sizeof(checkpoint->witness_signatures[0]));
    checkpoint->witness_signature_count = entry->witness_signature_count;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_export_persisted_state(
    const sm2_pki_client_ctx_t *ctx, sm2_pki_client_persisted_state_t *out)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !out)
        return SM2_PKI_ERR_PARAM;

    memset(out, 0, sizeof(*out));
    out->format_version = SM2_PKI_CLIENT_PERSISTED_STATE_VERSION;

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        const sm2_pki_epoch_cache_entry_t *entry = &state->epoch_root_cache[i];
        if (!entry->used || !entry->has_pinned_ca_index
            || !entry->has_epoch_digest || !entry->has_revocation_root
            || !entry->has_issuance_root)
        {
            continue;
        }
        if (entry->pinned_ca_index >= state->trust_store.count)
            return SM2_PKI_ERR_STATE;
        if (out->record_count >= SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES)
        {
            return SM2_PKI_ERR_STATE;
        }

        sm2_pki_client_persisted_authority_state_t *record
            = &out->records[out->record_count++];
        memcpy(
            record->authority_id, entry->authority_id, entry->authority_id_len);
        record->authority_id_len = entry->authority_id_len;
        record->ca_public_key
            = state->trust_store.ca_pub_keys[entry->pinned_ca_index];
        record->highest_seen_epoch_version = entry->highest_seen_epoch_version;
        memcpy(record->epoch_digest, entry->epoch_digest,
            sizeof(record->epoch_digest));
        record->highest_seen_revocation_root_version
            = entry->highest_seen_revocation_root_version;
        memcpy(record->latest_revocation_root_hash,
            entry->latest_revocation_root_hash,
            sizeof(record->latest_revocation_root_hash));
        record->highest_seen_issuance_root_version
            = entry->highest_seen_issuance_root_version;
        memcpy(record->latest_issuance_root_hash,
            entry->latest_issuance_root_hash,
            sizeof(record->latest_issuance_root_hash));
        if (entry->has_epoch_record && entry->witness_signature_count > 0)
        {
            record->has_checkpoint = true;
            record->checkpoint.epoch_root_record = entry->epoch_record;
            memcpy(record->checkpoint.witness_signatures,
                entry->witness_signatures,
                entry->witness_signature_count
                    * sizeof(record->checkpoint.witness_signatures[0]));
            record->checkpoint.witness_signature_count
                = entry->witness_signature_count;
        }
    }

    return SM2_PKI_SUCCESS;
}

static bool pki_client_persisted_authority_duplicate(
    const sm2_pki_client_persisted_state_t *state, size_t index)
{
    const sm2_pki_client_persisted_authority_state_t *record
        = &state->records[index];
    for (size_t i = 0; i < index; i++)
    {
        const sm2_pki_client_persisted_authority_state_t *prior
            = &state->records[i];
        if (record->authority_id_len == prior->authority_id_len
            && memcmp(record->authority_id, prior->authority_id,
                   record->authority_id_len)
                == 0)
        {
            return true;
        }
    }
    return false;
}

static sm2_pki_error_t pki_client_check_persisted_record_conflict(
    const sm2_pki_epoch_cache_entry_t *entry,
    const sm2_pki_client_persisted_authority_state_t *record,
    size_t matched_ca_index)
{
    if (!entry || !record)
        return SM2_PKI_SUCCESS;
    if (entry->has_pinned_ca_index
        && entry->pinned_ca_index != matched_ca_index)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (record->highest_seen_epoch_version < entry->highest_seen_epoch_version)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (entry->has_epoch_digest
        && record->highest_seen_epoch_version
            == entry->highest_seen_epoch_version
        && memcmp(record->epoch_digest, entry->epoch_digest,
               sizeof(record->epoch_digest))
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (entry->has_revocation_root)
    {
        if (record->highest_seen_revocation_root_version
            < entry->highest_seen_revocation_root_version)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (record->highest_seen_revocation_root_version
                == entry->highest_seen_revocation_root_version
            && memcmp(record->latest_revocation_root_hash,
                   entry->latest_revocation_root_hash,
                   sizeof(record->latest_revocation_root_hash))
                != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
    }
    if (entry->has_issuance_root)
    {
        if (record->highest_seen_issuance_root_version
            < entry->highest_seen_issuance_root_version)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (record->highest_seen_issuance_root_version
                == entry->highest_seen_issuance_root_version
            && memcmp(record->latest_issuance_root_hash,
                   entry->latest_issuance_root_hash,
                   sizeof(record->latest_issuance_root_hash))
                != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
    }
    return SM2_PKI_SUCCESS;
}

static bool pki_client_cached_checkpoint_matches_persisted(
    const sm2_pki_epoch_cache_entry_t *entry,
    const sm2_pki_client_persisted_authority_state_t *record)
{
    return entry && record && entry->has_epoch_record
        && entry->epoch_record.epoch_version
        == record->highest_seen_epoch_version
        && memcmp(entry->epoch_digest, record->epoch_digest,
               sizeof(record->epoch_digest))
        == 0;
}

static sm2_pki_error_t pki_client_persisted_checkpoint_matches_record(
    const sm2_pki_client_persisted_authority_state_t *record)
{
    if (!record)
        return SM2_PKI_ERR_PARAM;
    if (!record->has_checkpoint)
        return SM2_PKI_SUCCESS;

    const sm2_pki_epoch_checkpoint_t *checkpoint = &record->checkpoint;
    const sm2_pki_epoch_root_record_t *root = &checkpoint->epoch_root_record;
    if (checkpoint->witness_signature_count == 0
        || checkpoint->witness_signature_count
            > SM2_PKI_TRANSPARENCY_MAX_WITNESSES)
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (root->authority_id_len != record->authority_id_len
        || memcmp(root->authority_id, record->authority_id,
               record->authority_id_len)
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (root->epoch_version != record->highest_seen_epoch_version
        || root->revocation_root_version
            != record->highest_seen_revocation_root_version
        || root->issuance_root_version
            != record->highest_seen_issuance_root_version)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (memcmp(root->revocation_root_hash, record->latest_revocation_root_hash,
            sizeof(root->revocation_root_hash))
            != 0
        || memcmp(root->issuance_root_hash, record->latest_issuance_root_hash,
               sizeof(root->issuance_root_hash))
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    return pki_client_epoch_root_digest_matches(root, record->epoch_digest);
}

sm2_pki_error_t sm2_pki_client_import_persisted_state(sm2_pki_client_ctx_t *ctx,
    const sm2_pki_client_persisted_state_t *persisted, uint64_t now_ts)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    size_t matched_ca_indices[SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES];
    size_t
        checkpoint_ca_indices[SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES];
    size_t new_record_count = 0;
    size_t free_entry_count = 0;

    if (!ctx || !ctx->initialized || !state || !persisted)
        return SM2_PKI_ERR_PARAM;
    if (persisted->format_version != SM2_PKI_CLIENT_PERSISTED_STATE_VERSION
        || persisted->record_count
            > SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES)
    {
        return SM2_PKI_ERR_PARAM;
    }

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        if (!state->epoch_root_cache[i].used)
            free_entry_count++;
    }

    for (size_t i = 0; i < persisted->record_count; i++)
    {
        const sm2_pki_client_persisted_authority_state_t *record
            = &persisted->records[i];
        if (!pki_client_authority_id_valid(
                record->authority_id, record->authority_id_len)
            || record->highest_seen_epoch_version == 0)
        {
            return SM2_PKI_ERR_PARAM;
        }
        if (pki_client_persisted_authority_duplicate(persisted, i))
            return SM2_PKI_ERR_VERIFY;
        if (!pki_client_find_trusted_ca_index(
                state, &record->ca_public_key, &matched_ca_indices[i]))
        {
            return SM2_PKI_ERR_VERIFY;
        }

        sm2_pki_error_t ret
            = pki_client_persisted_checkpoint_matches_record(record);
        if (ret != SM2_PKI_SUCCESS)
            return ret;
        checkpoint_ca_indices[i] = matched_ca_indices[i];
        if (state->has_transparency_policy && record->has_checkpoint)
        {
            ret = pki_client_validate_epoch_checkpoint(
                state, &record->checkpoint, now_ts, &checkpoint_ca_indices[i]);
            if (ret != SM2_PKI_SUCCESS)
                return ret;
            if (checkpoint_ca_indices[i] != matched_ca_indices[i])
                return SM2_PKI_ERR_VERIFY;
        }

        const sm2_pki_epoch_cache_entry_t *entry
            = pki_client_find_epoch_root_cache_entry(
                state, record->authority_id, record->authority_id_len);
        ret = pki_client_check_persisted_record_conflict(
            entry, record, matched_ca_indices[i]);
        if (ret != SM2_PKI_SUCCESS)
            return ret;
        if (!entry)
            new_record_count++;
    }

    if (new_record_count > free_entry_count)
        return SM2_PKI_ERR_MEMORY;

    for (size_t i = 0; i < persisted->record_count; i++)
    {
        const sm2_pki_client_persisted_authority_state_t *record
            = &persisted->records[i];
        sm2_pki_epoch_cache_entry_t *entry
            = pki_client_ensure_epoch_root_cache_entry(
                state, record->authority_id, record->authority_id_len);
        if (!entry)
            return SM2_PKI_ERR_MEMORY;

        bool keep_cached_checkpoint
            = pki_client_cached_checkpoint_matches_persisted(entry, record);
        if (!keep_cached_checkpoint)
            entry->has_epoch_record = false;

        memcpy(entry->authority_id, record->authority_id,
            record->authority_id_len);
        entry->authority_id_len = record->authority_id_len;
        entry->used = true;
        entry->has_epoch_digest = true;
        entry->has_pinned_ca_index = true;
        entry->pinned_ca_index = matched_ca_indices[i];
        entry->highest_seen_epoch_version = record->highest_seen_epoch_version;
        memcpy(entry->epoch_digest, record->epoch_digest,
            sizeof(entry->epoch_digest));
        entry->highest_seen_revocation_root_version
            = record->highest_seen_revocation_root_version;
        memcpy(entry->latest_revocation_root_hash,
            record->latest_revocation_root_hash,
            sizeof(entry->latest_revocation_root_hash));
        entry->has_revocation_root = true;
        entry->highest_seen_issuance_root_version
            = record->highest_seen_issuance_root_version;
        memcpy(entry->latest_issuance_root_hash,
            record->latest_issuance_root_hash,
            sizeof(entry->latest_issuance_root_hash));
        entry->has_issuance_root = true;

        if (state->has_transparency_policy && record->has_checkpoint)
        {
            sm2_pki_error_t ret = pki_client_accept_epoch_root_record(state,
                &record->checkpoint.epoch_root_record, now_ts,
                checkpoint_ca_indices[i], record->checkpoint.witness_signatures,
                record->checkpoint.witness_signature_count);
            if (ret != SM2_PKI_SUCCESS)
                return ret;
        }
    }

    pki_client_cache_reset(state);
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_persisted_storage_init(
    sm2_pki_client_persisted_storage_t *storage)
{
    if (!storage)
        return;
    memset(storage, 0, sizeof(*storage));
}

sm2_pki_error_t sm2_pki_client_persisted_storage_store(
    sm2_pki_client_persisted_storage_t *storage,
    const sm2_pki_client_persisted_state_t *state, const uint8_t *device_secret,
    size_t device_secret_len)
{
    if (!storage || !state || !device_secret || device_secret_len == 0)
        return SM2_PKI_ERR_PARAM;

    sm2_pki_error_t ret = pki_client_persisted_state_shape_valid(state);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    bool valid[SM2_PKI_CLIENT_PERSISTED_STORAGE_SLOT_COUNT];
    memset(valid, 0, sizeof(valid));
    uint64_t highest_sequence = 0;
    for (size_t i = 0; i < SM2_PKI_CLIENT_PERSISTED_STORAGE_SLOT_COUNT; i++)
    {
        valid[i] = pki_client_persisted_storage_slot_valid(
            &storage->slots[i], device_secret, device_secret_len);
        if (valid[i] && storage->slots[i].sequence > highest_sequence)
            highest_sequence = storage->slots[i].sequence;
    }
    if (highest_sequence == UINT64_MAX)
        return SM2_PKI_ERR_STATE;

    size_t target = 0;
    if (!valid[0])
        target = 0;
    else if (!valid[1])
        target = 1;
    else
        target
            = storage->slots[0].sequence <= storage->slots[1].sequence ? 0 : 1;

    sm2_pki_client_persisted_storage_slot_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.magic = SM2_PKI_CLIENT_PERSISTED_STORAGE_MAGIC;
    candidate.format_version = SM2_PKI_CLIENT_PERSISTED_STORAGE_VERSION;
    candidate.sequence = highest_sequence + 1U;
    candidate.state = *state;

    ret = pki_client_persisted_storage_slot_tag(
        &candidate, device_secret, device_secret_len, candidate.tag);
    if (ret != SM2_PKI_SUCCESS)
    {
        sm2_secure_memzero(&candidate, sizeof(candidate));
        return ret;
    }

    storage->slots[target] = candidate;
    sm2_secure_memzero(&candidate, sizeof(candidate));
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_persisted_storage_load(
    const sm2_pki_client_persisted_storage_t *storage,
    sm2_pki_client_persisted_state_t *state, const uint8_t *device_secret,
    size_t device_secret_len, uint64_t *selected_sequence)
{
    if (!storage || !state || !device_secret || device_secret_len == 0)
        return SM2_PKI_ERR_PARAM;

    size_t selected = SM2_PKI_CLIENT_PERSISTED_STORAGE_SLOT_COUNT;
    uint64_t highest_sequence = 0;
    for (size_t i = 0; i < SM2_PKI_CLIENT_PERSISTED_STORAGE_SLOT_COUNT; i++)
    {
        if (!pki_client_persisted_storage_slot_valid(
                &storage->slots[i], device_secret, device_secret_len))
        {
            continue;
        }
        if (selected == SM2_PKI_CLIENT_PERSISTED_STORAGE_SLOT_COUNT
            || storage->slots[i].sequence > highest_sequence)
        {
            selected = i;
            highest_sequence = storage->slots[i].sequence;
        }
    }
    if (selected == SM2_PKI_CLIENT_PERSISTED_STORAGE_SLOT_COUNT)
        return SM2_PKI_ERR_NOT_FOUND;

    *state = storage->slots[selected].state;
    if (selected_sequence)
        *selected_sequence = storage->slots[selected].sequence;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_get_cert(
    const sm2_pki_client_ctx_t *ctx, const sm2_implicit_cert_t **cert)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !cert)
        return SM2_PKI_ERR_PARAM;
    *cert = &state->cert;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_get_public_key(
    const sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t **public_key)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !public_key)
        return SM2_PKI_ERR_PARAM;
    *public_key = &state->public_key;
    return SM2_PKI_SUCCESS;
}

bool sm2_pki_client_is_sign_pool_enabled(const sm2_pki_client_ctx_t *ctx)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    return ctx && ctx->initialized && state && state->sign_pool_enabled;
}

sm2_pki_error_t sm2_pki_client_bind_revocation(
    sm2_pki_client_ctx_t *ctx, sm2_pki_service_ctx_t *service)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    sm2_pki_service_state_t *bound_service = NULL;
    if (!ctx || !ctx->initialized || !state || !service)
        return SM2_PKI_ERR_PARAM;

    if (state->revocation_service)
    {
        if (state->revocation_service == service)
            return SM2_PKI_SUCCESS;
        pki_client_release_bound_service(state);
    }

    sm2_pki_error_t ret
        = sm2_pki_service_acquire_revocation_binding(service, &bound_service);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    state->revocation_service = bound_service;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_export_epoch_evidence(sm2_pki_client_ctx_t *ctx,
    uint64_t now_ts, sm2_pki_evidence_bundle_t *evidence)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !evidence
        || !state->has_identity_keys)
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (!state->revocation_service)
        return SM2_PKI_ERR_STATE;
    if (!pki_client_bound_service_live(state))
        return SM2_PKI_ERR_VERIFY;

    size_t matched_ca_index = 0;
    sm2_ic_error_t ic_ret = sm2_auth_verify_cert_with_store(&state->cert,
        &state->public_key, &state->trust_store, &matched_ca_index);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    memset(evidence, 0, sizeof(*evidence));
    sm2_pki_epoch_root_record_t epoch_record;
    memset(&epoch_record, 0, sizeof(epoch_record));
    sm2_pki_error_t ret = sm2_pki_service_export_current_epoch_evidence(
        (sm2_pki_service_ctx_t *)state->revocation_service, &state->cert,
        &epoch_record, &evidence->revocation_proof.absence_proof,
        &evidence->issuance_proof.member_proof);
    if (ret != SM2_PKI_SUCCESS)
        return pki_client_map_service_failure_closed(ret);

    const sm2_pki_epoch_root_record_t *epoch = &epoch_record;
    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = true,
        .required_index = matched_ca_index };
    ic_ret = sm2_pki_epoch_root_verify(
        epoch, now_ts, pki_client_root_record_verify_cb, &verify_ctx);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    ic_ret = sm2_pki_epoch_root_digest(epoch, evidence->epoch_digest);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    ret = pki_client_verify_revocation_proof_with_epoch(
        &state->cert, epoch, &evidence->revocation_proof);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    return pki_client_verify_issuance_proof_with_epoch(
        &state->cert, epoch, &evidence->issuance_proof);
}

static sm2_pki_error_t pki_epoch_witness_sign_raw(
    const sm2_pki_epoch_root_record_t *root_record, const uint8_t *witness_id,
    size_t witness_id_len, const sm2_private_key_t *witness_private_key,
    sm2_pki_transparency_witness_signature_t *signature)
{
    uint8_t payload[SM2_PKI_WITNESS_PAYLOAD_MAX];
    size_t payload_len = 0;
    if (!root_record || !witness_private_key || !signature
        || !pki_client_witness_id_valid(witness_id, witness_id_len))
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_ic_error_t ic_ret = sm2_pki_epoch_root_encode_witness_payload(
        root_record, payload, sizeof(payload), &payload_len);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    sm2_auth_signature_t sig;
    ic_ret = sm2_auth_sign(witness_private_key, payload, payload_len, &sig);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    if (sig.der_len == 0 || sig.der_len > sizeof(signature->signature))
        return SM2_PKI_ERR_VERIFY;

    memset(signature, 0, sizeof(*signature));
    memcpy(signature->witness_id, witness_id, witness_id_len);
    signature->witness_id_len = witness_id_len;
    memcpy(signature->signature, sig.der, sig.der_len);
    signature->signature_len = sig.der_len;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_epoch_witness_state_init(sm2_pki_epoch_witness_state_t *state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
    state->initialized = true;
}

void sm2_pki_epoch_witness_state_cleanup(sm2_pki_epoch_witness_state_t *state)
{
    if (!state)
        return;
    free(state->commitments);
    memset(state, 0, sizeof(*state));
}

static sm2_pki_error_t pki_witness_build_candidate_commitments(
    const sm2_pki_epoch_witness_state_t *state,
    const sm2_pki_issuance_commitment_t *new_commitments,
    size_t new_commitment_count, sm2_pki_issuance_commitment_t **candidate,
    size_t *candidate_count)
{
    if (!state || !candidate || !candidate_count)
        return SM2_PKI_ERR_PARAM;
    if (new_commitment_count > 0 && !new_commitments)
        return SM2_PKI_ERR_PARAM;
    if (new_commitment_count > SIZE_MAX - state->commitment_count)
        return SM2_PKI_ERR_MEMORY;

    size_t total_count = state->commitment_count + new_commitment_count;
    *candidate = NULL;
    *candidate_count = total_count;
    if (total_count == 0)
        return SM2_PKI_SUCCESS;
    if (total_count > SIZE_MAX / sizeof(**candidate))
        return SM2_PKI_ERR_MEMORY;

    sm2_pki_issuance_commitment_t *buf = malloc(total_count * sizeof(*buf));
    if (!buf)
        return SM2_PKI_ERR_MEMORY;
    if (state->commitment_count > 0)
    {
        memcpy(buf, state->commitments, state->commitment_count * sizeof(*buf));
    }
    if (new_commitment_count > 0)
    {
        memcpy(buf + state->commitment_count, new_commitments,
            new_commitment_count * sizeof(*buf));
    }

    *candidate = buf;
    return SM2_PKI_SUCCESS;
}

static sm2_ic_error_t pki_witness_ca_verify_cb(void *user_ctx,
    const uint8_t *data, size_t data_len, const uint8_t *signature,
    size_t signature_len)
{
    const sm2_ec_point_t *ca_public_key = (const sm2_ec_point_t *)user_ctx;
    if (!ca_public_key || !data || !signature || signature_len == 0
        || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;
    return sm2_auth_verify_signature(ca_public_key, data, data_len, &sig);
}

sm2_pki_error_t sm2_pki_epoch_witness_sign_append_only(
    sm2_pki_epoch_witness_state_t *state,
    const sm2_pki_epoch_root_record_t *root_record,
    const sm2_ec_point_t *ca_public_key, uint64_t now_ts,
    const sm2_pki_issuance_commitment_t *new_commitments,
    size_t new_commitment_count, const uint8_t *witness_id,
    size_t witness_id_len, const sm2_private_key_t *witness_private_key,
    sm2_pki_transparency_witness_signature_t *signature)
{
    if (!state || !state->initialized || !root_record || !ca_public_key
        || !witness_private_key || !signature
        || !pki_client_authority_id_valid(
            root_record->authority_id, root_record->authority_id_len))
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (root_record->issuance_root_version > SIZE_MAX)
        return SM2_PKI_ERR_MEMORY;

    sm2_ic_error_t verify_ret = sm2_pki_epoch_root_verify(
        root_record, now_ts, pki_witness_ca_verify_cb, (void *)ca_public_key);
    if (verify_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(verify_ret);

    uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    sm2_ic_error_t ic_ret
        = sm2_pki_epoch_root_digest(root_record, epoch_digest);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    if (state->has_authority
        && (state->authority_id_len != root_record->authority_id_len
            || memcmp(state->authority_id, root_record->authority_id,
                   root_record->authority_id_len)
                != 0))
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (root_record->epoch_version < state->latest_epoch_version)
        return SM2_PKI_ERR_VERIFY;
    if (root_record->epoch_version == state->latest_epoch_version
        && state->has_authority
        && memcmp(
               epoch_digest, state->latest_epoch_digest, sizeof(epoch_digest))
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (state->has_authority)
    {
        if (root_record->revocation_root_version
            < state->latest_revocation_root_version)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (root_record->revocation_root_version
                == state->latest_revocation_root_version
            && memcmp(root_record->revocation_root_hash,
                   state->latest_revocation_root_hash,
                   sizeof(root_record->revocation_root_hash))
                != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (root_record->issuance_root_version
            < state->latest_issuance_root_version)
            return SM2_PKI_ERR_VERIFY;
        if (root_record->issuance_root_version
                == state->latest_issuance_root_version
            && memcmp(root_record->issuance_root_hash,
                   state->latest_issuance_root_hash,
                   sizeof(root_record->issuance_root_hash))
                != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
    }

    sm2_pki_issuance_commitment_t *candidate = NULL;
    size_t candidate_count = 0;
    sm2_pki_error_t ret = pki_witness_build_candidate_commitments(state,
        new_commitments, new_commitment_count, &candidate, &candidate_count);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    if (candidate_count != (size_t)root_record->issuance_root_version)
    {
        free(candidate);
        return SM2_PKI_ERR_VERIFY;
    }

    sm2_pki_issuance_tree_t *tree = NULL;
    ic_ret = sm2_pki_issuance_tree_build(
        &tree, candidate, candidate_count, root_record->issuance_root_version);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        free(candidate);
        return sm2_pki_error_from_ic(ic_ret);
    }
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    ic_ret = sm2_pki_issuance_tree_get_root_hash(tree, root_hash);
    sm2_pki_issuance_tree_cleanup(&tree);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        free(candidate);
        return sm2_pki_error_from_ic(ic_ret);
    }
    if (memcmp(root_hash, root_record->issuance_root_hash, sizeof(root_hash))
        != 0)
    {
        free(candidate);
        return SM2_PKI_ERR_VERIFY;
    }

    ret = pki_epoch_witness_sign_raw(root_record, witness_id, witness_id_len,
        witness_private_key, signature);
    if (ret != SM2_PKI_SUCCESS)
    {
        free(candidate);
        return ret;
    }

    free(state->commitments);
    state->commitments = candidate;
    state->commitment_count = candidate_count;
    state->commitment_capacity = candidate_count;
    memcpy(state->authority_id, root_record->authority_id,
        root_record->authority_id_len);
    state->authority_id_len = root_record->authority_id_len;
    state->latest_epoch_version = root_record->epoch_version;
    memcpy(state->latest_epoch_digest, epoch_digest,
        sizeof(state->latest_epoch_digest));
    state->latest_revocation_root_version
        = root_record->revocation_root_version;
    memcpy(state->latest_revocation_root_hash,
        root_record->revocation_root_hash,
        sizeof(state->latest_revocation_root_hash));
    state->latest_issuance_root_version = root_record->issuance_root_version;
    memcpy(state->latest_issuance_root_hash, root_record->issuance_root_hash,
        sizeof(state->latest_issuance_root_hash));
    state->has_authority = true;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_epoch_quorum_check(
    const sm2_pki_epoch_root_vote_t *votes, size_t vote_count, size_t threshold,
    sm2_pki_epoch_quorum_result_t *result)
{
    if (!votes || threshold == 0 || !result)
        return SM2_PKI_ERR_PARAM;
    if (vote_count > SIZE_MAX / sizeof(sm2_rev_quorum_vote_t))
        return SM2_PKI_ERR_MEMORY;

    memset(result, 0, sizeof(*result));
    sm2_rev_quorum_vote_t *rev_votes = calloc(vote_count, sizeof(*rev_votes));
    if (!rev_votes)
        return SM2_PKI_ERR_MEMORY;

    for (size_t i = 0; i < vote_count; i++)
    {
        memcpy(rev_votes[i].node_id, votes[i].node_id,
            sizeof(rev_votes[i].node_id));
        rev_votes[i].node_id_len = votes[i].node_id_len;
        rev_votes[i].root_version = votes[i].epoch_version;
        memcpy(rev_votes[i].root_hash, votes[i].epoch_digest,
            sizeof(rev_votes[i].root_hash));
        rev_votes[i].status = SM2_REV_STATUS_GOOD;
        rev_votes[i].proof_valid = votes[i].proof_valid;
    }

    sm2_rev_quorum_result_t rev_result;
    memset(&rev_result, 0, sizeof(rev_result));
    sm2_ic_error_t ic_ret
        = sm2_rev_quorum_check(rev_votes, vote_count, threshold, &rev_result);
    free(rev_votes);

    result->selected_epoch_version = rev_result.selected_root_version;
    memcpy(result->selected_epoch_digest, rev_result.selected_root_hash,
        sizeof(result->selected_epoch_digest));
    result->unique_node_count = rev_result.unique_node_count;
    result->valid_vote_count = rev_result.valid_vote_count;
    result->stale_vote_count = rev_result.stale_vote_count;
    result->conflict_vote_count = rev_result.conflict_vote_count;
    result->threshold = rev_result.threshold;
    result->quorum_met = rev_result.quorum_met;
    result->fork_detected = rev_result.conflict_vote_count > 0;
    return sm2_pki_error_from_ic(ic_ret);
}

sm2_pki_error_t sm2_pki_client_import_cert(sm2_pki_client_ctx_t *ctx,
    const sm2_ic_cert_result_t *cert_result,
    const sm2_private_key_t *temp_private_key,
    const sm2_ec_point_t *ca_public_key)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    sm2_private_key_t imported_private_key;
    sm2_ec_point_t imported_public_key;
    if (!ctx || !ctx->initialized || !state || !cert_result || !temp_private_key
        || !ca_public_key)
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (!pki_client_trust_store_contains_ca(state, ca_public_key))
        return SM2_PKI_ERR_VERIFY;

    memset(&imported_private_key, 0, sizeof(imported_private_key));
    memset(&imported_public_key, 0, sizeof(imported_public_key));

    sm2_ic_error_t ret = sm2_ic_reconstruct_keys(&imported_private_key,
        &imported_public_key, cert_result, temp_private_key, ca_public_key);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ret = sm2_ic_verify_cert(
        &cert_result->cert, &imported_public_key, ca_public_key);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_secure_memzero(
            imported_private_key.d, sizeof(imported_private_key.d));
        return sm2_pki_error_from_ic(ret);
    }

    sm2_pki_client_disable_sign_pool(ctx);
    sm2_secure_memzero(state->private_key.d, sizeof(state->private_key.d));
    state->private_key = imported_private_key;
    state->public_key = imported_public_key;
    state->cert = cert_result->cert;
    state->has_identity_keys = true;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_enable_sign_pool(
    sm2_pki_client_ctx_t *ctx, size_t capacity, size_t target_available)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || capacity == 0)
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_pki_client_disable_sign_pool(ctx);

    sm2_ic_error_t ret = sm2_auth_sign_pool_init(
        &state->sign_pool, &state->private_key, capacity);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ret = sm2_auth_sign_pool_fill(&state->sign_pool, target_available);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_auth_sign_pool_cleanup(&state->sign_pool);
        return sm2_pki_error_from_ic(ret);
    }

    state->sign_pool_enabled = true;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_disable_sign_pool(sm2_pki_client_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (state && state->sign_pool_enabled)
    {
        sm2_auth_sign_pool_cleanup(&state->sign_pool);
        state->sign_pool_enabled = false;
    }
}

sm2_pki_error_t sm2_pki_sign(sm2_pki_client_ctx_t *ctx, const uint8_t *message,
    size_t message_len, sm2_auth_signature_t *signature)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !message || !signature)
    {
        return SM2_PKI_ERR_PARAM;
    }
    sm2_ic_error_t ret = SM2_IC_SUCCESS;
    if (state->sign_pool_enabled
        && sm2_auth_sign_pool_available(&state->sign_pool) > 0)
    {
        ret = sm2_auth_sign_with_pool(
            &state->sign_pool, message, message_len, signature);
    }
    else
    {
        ret = sm2_auth_sign(
            &state->private_key, message, message_len, signature);
    }
    return sm2_pki_error_from_ic(ret);
}

sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
    const sm2_pki_verify_request_t *request, uint64_t now_ts,
    size_t *matched_ca_index)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !request)
        return SM2_PKI_ERR_PARAM;

    if (!request->evidence_bundle)
        return SM2_PKI_ERR_VERIFY;

    size_t local_matched_index = 0;
    sm2_pki_error_t ret = pki_client_verify_without_revocation(
        state, request, now_ts, &local_matched_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    if (matched_ca_index)
        *matched_ca_index = local_matched_index;

    if (!state->has_transparency_policy)
        return SM2_PKI_ERR_VERIFY;
    const sm2_pki_transparency_policy_t *policy = &state->transparency_policy;
    ret = pki_client_validate_transparency_policy(policy);
    if (ret != SM2_PKI_SUCCESS)
        return SM2_PKI_ERR_VERIFY;

    return pki_client_verify_epoch_evidence_bundle(state, request->cert,
        request->evidence_bundle, now_ts, local_matched_index);
}

sm2_pki_error_t sm2_pki_generate_ephemeral_keypair(
    sm2_private_key_t *ephemeral_private_key,
    sm2_ec_point_t *ephemeral_public_key)
{
    return sm2_pki_error_from_ic(sm2_auth_generate_ephemeral_keypair(
        ephemeral_private_key, ephemeral_public_key));
}

sm2_pki_error_t sm2_pki_secure_session_build_binding(
    const sm2_ec_point_t *local_ephemeral_public_key,
    const sm2_ec_point_t *peer_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len, uint8_t *output, size_t *output_len)
{
    return sm2_pki_error_from_ic(sm2_auth_build_handshake_binding(
        local_ephemeral_public_key, peer_ephemeral_public_key, transcript,
        transcript_len, output, output_len));
}

sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
    const sm2_private_key_t *local_ephemeral_private_key,
    const sm2_ec_point_t *peer_public_key,
    const sm2_ec_point_t *peer_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len, uint8_t *session_key, size_t session_key_len)
{
    sm2_pki_error_t policy_ret = pki_client_require_local_key_agreement(ctx);
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (policy_ret != SM2_PKI_SUCCESS)
        return policy_ret;
    return sm2_pki_error_from_ic(sm2_auth_derive_session_key(
        &state->private_key, local_ephemeral_private_key, peer_public_key,
        peer_ephemeral_public_key, transcript, transcript_len, session_key,
        session_key_len));
}

sm2_pki_error_t sm2_pki_secure_session_establish(sm2_pki_client_ctx_t *ctx,
    const sm2_private_key_t *local_ephemeral_private_key,
    const sm2_ec_point_t *local_ephemeral_public_key,
    const sm2_pki_verify_request_t *peer_request,
    const sm2_ec_point_t *peer_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len, uint64_t now_ts, uint8_t *session_key,
    size_t session_key_len, size_t *matched_ca_index)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    size_t local_matched_ca_index = 0;
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !local_ephemeral_private_key || !local_ephemeral_public_key
        || !peer_request || !peer_request->cert || !peer_request->public_key
        || !peer_ephemeral_public_key || !session_key || session_key_len == 0)
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_pki_error_t ret = pki_client_require_local_key_agreement(ctx);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_validate_keypair(
        local_ephemeral_private_key, local_ephemeral_public_key);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_require_handshake_binding(peer_request,
        peer_ephemeral_public_key, local_ephemeral_public_key, transcript,
        transcript_len);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    ret = sm2_pki_verify(ctx, peer_request, now_ts, &local_matched_ca_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_require_cert_key_agreement(peer_request->cert);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    ret = sm2_pki_key_agreement(ctx, local_ephemeral_private_key,
        peer_request->public_key, peer_ephemeral_public_key, transcript,
        transcript_len, session_key, session_key_len);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    if (matched_ca_index)
        *matched_ca_index = local_matched_ca_index;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_encrypt(sm2_pki_aead_mode_t mode, const uint8_t key[16],
    const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
    size_t *ciphertext_len, uint8_t *tag, size_t *tag_len)
{
    return sm2_pki_aead_encrypt(mode, key, iv, iv_len, aad, aad_len, plaintext,
        plaintext_len, ciphertext, ciphertext_len, tag, tag_len);
}

sm2_pki_error_t sm2_pki_decrypt(sm2_pki_aead_mode_t mode, const uint8_t key[16],
    const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag,
    size_t tag_len, uint8_t *plaintext, size_t *plaintext_len)
{
    return sm2_pki_aead_decrypt(mode, key, iv, iv_len, aad, aad_len, ciphertext,
        ciphertext_len, tag, tag_len, plaintext, plaintext_len);
}
