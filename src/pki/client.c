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
    if (entry->has_epoch_record
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
    size_t matched_ca_index)
{
    if (!state || !root_record)
        return SM2_PKI_ERR_PARAM;
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
    memcpy(entry->epoch_digest, epoch_digest, sizeof(entry->epoch_digest));
    entry->used = true;
    entry->has_epoch_record = true;
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

    ret = pki_client_verify_revocation_proof_with_epoch(
        cert, cached_epoch, &evidence->revocation_proof);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    ret = pki_client_verify_issuance_proof_with_epoch(
        cert, cached_epoch, &evidence->issuance_proof);
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

    sm2_ic_error_t ic_ret = sm2_auth_build_handshake_binding(
        peer_ephemeral_public_key, local_ephemeral_public_key, transcript,
        transcript_len, NULL, &expected_len);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);
    if (peer_request->message_len != expected_len)
        return SM2_PKI_ERR_VERIFY;

    expected = (uint8_t *)malloc(expected_len);
    if (!expected)
        return SM2_PKI_ERR_MEMORY;

    size_t out_len = expected_len;
    ic_ret = sm2_auth_build_handshake_binding(peer_ephemeral_public_key,
        local_ephemeral_public_key, transcript, transcript_len, expected,
        &out_len);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        free(expected);
        return sm2_pki_error_from_ic(ic_ret);
    }

    sm2_pki_error_t ret
        = memcmp(peer_request->message, expected, expected_len) == 0
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
    memset(state->epoch_root_cache, 0, sizeof(state->epoch_root_cache));
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_import_epoch_checkpoint(
    sm2_pki_client_ctx_t *ctx, const sm2_pki_epoch_checkpoint_t *checkpoint,
    uint64_t now_ts)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !checkpoint)
        return SM2_PKI_ERR_PARAM;
    if (!state->has_transparency_policy)
        return SM2_PKI_ERR_VERIFY;

    const sm2_pki_transparency_policy_t *policy = &state->transparency_policy;
    sm2_pki_error_t ret = pki_client_validate_transparency_policy(policy);
    if (ret != SM2_PKI_SUCCESS)
        return SM2_PKI_ERR_VERIFY;

    size_t matched_ca_index = 0;
    ret = pki_client_match_epoch_root_ca(
        state, &checkpoint->epoch_root_record, now_ts, &matched_ca_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    ret = pki_client_verify_epoch_witness_threshold(
        &checkpoint->epoch_root_record, checkpoint->witness_signatures,
        checkpoint->witness_signature_count, policy);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    return pki_client_accept_epoch_root_record(
        state, &checkpoint->epoch_root_record, now_ts, matched_ca_index);
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
