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
    return state && state->revocation_service
        && state->revocation_service->initialized
        && !state->revocation_service->revocation_binding_retired
        && state->revocation_service->revocation_state_ready;
}

static bool pki_client_trust_store_find_ca_index(
    const sm2_auth_trust_store_t *store, const sm2_ec_point_t *ca_public_key,
    size_t *matched_index)
{
    if (!store || !ca_public_key || !matched_index)
        return false;

    for (size_t i = 0; i < store->count; i++)
    {
        if (memcmp(
                &store->ca_pub_keys[i], ca_public_key, sizeof(*ca_public_key))
            == 0)
        {
            *matched_index = i;
            return true;
        }
    }

    return false;
}

static sm2_pki_root_cache_entry_t *pki_client_find_root_cache_entry(
    sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len)
{
    if (!state
        || !pki_client_authority_id_valid(authority_id, authority_id_len))
        return NULL;

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        sm2_pki_root_cache_entry_t *entry = &state->root_cache[i];
        if (!entry->used || entry->authority_id_len != authority_id_len)
            continue;
        if (memcmp(entry->authority_id, authority_id, authority_id_len) == 0)
            return entry;
    }

    return NULL;
}

static const sm2_pki_root_cache_entry_t *pki_client_find_root_cache_entry_const(
    const sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len)
{
    return pki_client_find_root_cache_entry(
        (sm2_pki_client_state_t *)state, authority_id, authority_id_len);
}

static sm2_pki_root_cache_entry_t *pki_client_ensure_root_cache_entry(
    sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len, size_t *entry_index)
{
    sm2_pki_root_cache_entry_t *entry = pki_client_find_root_cache_entry(
        state, authority_id, authority_id_len);
    if (entry)
    {
        if (entry_index)
            *entry_index = (size_t)(entry - state->root_cache);
        return entry;
    }

    for (size_t i = 0; i < SM2_AUTH_MAX_CA_STORE; i++)
    {
        entry = &state->root_cache[i];
        if (entry->used)
            continue;

        memset(entry, 0, sizeof(*entry));
        memcpy(entry->authority_id, authority_id, authority_id_len);
        entry->authority_id_len = authority_id_len;
        if (entry_index)
            *entry_index = i;
        return entry;
    }

    return NULL;
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

static bool pki_client_local_authority_ca_index(
    const sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len, size_t *matched_ca_index)
{
    const uint8_t *local_authority_id = NULL;
    size_t local_authority_id_len = 0;

    if (!state || !state->has_identity_keys || !authority_id
        || !matched_ca_index)
        return false;
    if (pki_client_expected_authority_from_cert(
            &state->cert, &local_authority_id, &local_authority_id_len)
        != SM2_PKI_SUCCESS)
    {
        return false;
    }
    if (local_authority_id_len != authority_id_len
        || memcmp(local_authority_id, authority_id, authority_id_len) != 0)
    {
        return false;
    }

    return sm2_auth_verify_cert_with_store(&state->cert, &state->public_key,
               &state->trust_store, matched_ca_index)
        == SM2_IC_SUCCESS;
}

static bool pki_client_bound_service_ca_index(
    const sm2_pki_client_state_t *state, const uint8_t *authority_id,
    size_t authority_id_len, size_t *matched_ca_index)
{
    if (!pki_client_bound_service_live(state) || !authority_id
        || !matched_ca_index)
        return false;
    if (state->revocation_service->issuer_id_len != authority_id_len
        || memcmp(state->revocation_service->issuer_id, authority_id,
               authority_id_len)
            != 0)
    {
        return false;
    }

    return pki_client_trust_store_find_ca_index(&state->trust_store,
        &state->revocation_service->ca_public_key, matched_ca_index);
}

static sm2_pki_error_t pki_client_select_root_ca_index(
    const sm2_pki_client_state_t *state,
    const sm2_rev_root_record_t *root_record,
    const sm2_pki_root_cache_entry_t *entry,
    const pki_client_root_verify_ctx_t *verify_ctx, size_t *matched_ca_index)
{
    size_t selected_index = 0;

    if (!state || !root_record || !verify_ctx || !matched_ca_index)
        return SM2_PKI_ERR_PARAM;
    if (state->trust_store.count == 0)
        return SM2_PKI_ERR_VERIFY;

    if (entry && entry->has_pinned_ca_index)
    {
        if (verify_ctx->require_specific_index
            && entry->pinned_ca_index != verify_ctx->required_index)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        *matched_ca_index = entry->pinned_ca_index;
        return SM2_PKI_SUCCESS;
    }

    if (verify_ctx->require_specific_index)
    {
        if (verify_ctx->required_index >= state->trust_store.count)
            return SM2_PKI_ERR_VERIFY;
        *matched_ca_index = verify_ctx->required_index;
        return SM2_PKI_SUCCESS;
    }

    if (pki_client_bound_service_ca_index(state, root_record->authority_id,
            root_record->authority_id_len, &selected_index))
    {
        *matched_ca_index = selected_index;
        return SM2_PKI_SUCCESS;
    }

    if (pki_client_local_authority_ca_index(state, root_record->authority_id,
            root_record->authority_id_len, &selected_index))
    {
        *matched_ca_index = selected_index;
        return SM2_PKI_SUCCESS;
    }

    if (state->trust_store.count == 1)
    {
        *matched_ca_index = 0;
        return SM2_PKI_SUCCESS;
    }

    return SM2_PKI_ERR_VERIFY;
}

static sm2_pki_error_t pki_client_accept_root_record(
    sm2_pki_client_state_t *state, const sm2_rev_root_record_t *root_record,
    uint64_t now_ts, const pki_client_root_verify_ctx_t *verify_ctx)
{
    const sm2_pki_root_cache_entry_t *existing_entry = NULL;
    pki_client_root_verify_ctx_t effective_verify_ctx;
    size_t matched_ca_index = 0;

    if (!state || !root_record || !verify_ctx)
        return SM2_PKI_ERR_PARAM;
    if (!pki_client_authority_id_valid(
            root_record->authority_id, root_record->authority_id_len))
    {
        return SM2_PKI_ERR_VERIFY;
    }

    existing_entry = pki_client_find_root_cache_entry_const(
        state, root_record->authority_id, root_record->authority_id_len);
    sm2_pki_error_t select_ret = pki_client_select_root_ca_index(
        state, root_record, existing_entry, verify_ctx, &matched_ca_index);
    if (select_ret != SM2_PKI_SUCCESS)
        return select_ret;

    effective_verify_ctx.store = &state->trust_store;
    effective_verify_ctx.require_specific_index = true;
    effective_verify_ctx.required_index = matched_ca_index;

    sm2_ic_error_t ic_ret = sm2_rev_root_verify(root_record, now_ts,
        pki_client_root_record_verify_cb, &effective_verify_ctx);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    size_t entry_index = 0;
    sm2_pki_root_cache_entry_t *entry
        = pki_client_ensure_root_cache_entry(state, root_record->authority_id,
            root_record->authority_id_len, &entry_index);
    if (!entry)
        return SM2_PKI_ERR_MEMORY;

    if (root_record->root_version < entry->highest_seen_root_version)
        return SM2_PKI_ERR_VERIFY;

    if (entry->has_root_record
        && root_record->root_version == entry->highest_seen_root_version)
    {
        if (memcmp(root_record->root_hash, entry->root_record.root_hash,
                sizeof(root_record->root_hash))
            != 0)
        {
            return SM2_PKI_ERR_VERIFY;
        }
        if (root_record->valid_until < entry->root_record.valid_until)
            return SM2_PKI_ERR_VERIFY;
    }
    if (entry->has_pinned_ca_index
        && entry->pinned_ca_index != matched_ca_index)
        return SM2_PKI_ERR_VERIFY;

    entry->root_record = *root_record;
    entry->used = true;
    entry->has_root_record = true;
    entry->has_pinned_ca_index = true;
    entry->pinned_ca_index = matched_ca_index;
    if (root_record->root_version > entry->highest_seen_root_version)
        entry->highest_seen_root_version = root_record->root_version;
    state->last_root_cache_index = entry_index;
    state->has_last_root_cache_index = true;
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t pki_client_import_bound_root(
    sm2_pki_client_state_t *state, uint64_t now_ts,
    const pki_client_root_verify_ctx_t *verify_ctx)
{
    if (!state || !state->revocation_service || !verify_ctx)
        return SM2_PKI_ERR_STATE;
    if (!pki_client_bound_service_live(state))
        return SM2_PKI_ERR_STATE;

    sm2_rev_root_record_t root_record;
    memset(&root_record, 0, sizeof(root_record));
    sm2_pki_error_t ret = sm2_pki_service_get_root_record(
        (sm2_pki_service_ctx_t *)state->revocation_service, &root_record);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    return pki_client_accept_root_record(
        state, &root_record, now_ts, verify_ctx);
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

static sm2_pki_error_t pki_client_export_bound_evidence(
    sm2_pki_client_state_t *state, uint64_t now_ts,
    sm2_pki_revocation_evidence_t *evidence)
{
    if (!state || !evidence || !state->has_identity_keys)
        return SM2_PKI_ERR_PARAM;
    if (!state->revocation_service)
        return SM2_PKI_ERR_STATE;
    if (!pki_client_bound_service_live(state))
        return SM2_PKI_ERR_VERIFY;

    size_t matched_ca_index = 0;
    sm2_ic_error_t ic_ret = sm2_auth_verify_cert_with_store(&state->cert,
        &state->public_key, &state->trust_store, &matched_ca_index);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    const uint8_t *authority_id = NULL;
    size_t authority_id_len = 0;
    sm2_pki_error_t ret = pki_client_expected_authority_from_cert(
        &state->cert, &authority_id, &authority_id_len);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = true,
        .required_index = matched_ca_index };
    ret = pki_client_import_bound_root(state, now_ts, &verify_ctx);
    if (ret != SM2_PKI_SUCCESS)
        return pki_client_map_service_failure_closed(ret);

    const sm2_pki_root_cache_entry_t *entry
        = pki_client_find_root_cache_entry_const(
            state, authority_id, authority_id_len);
    if (!entry)
        return SM2_PKI_ERR_VERIFY;

    memset(evidence, 0, sizeof(*evidence));
    evidence->root_record = entry->root_record;

    ret = sm2_pki_service_export_absence_proof(
        (sm2_pki_service_ctx_t *)state->revocation_service,
        state->cert.serial_number, &evidence->absence_proof);
    if (ret != SM2_PKI_SUCCESS)
        return pki_client_map_service_failure_closed(ret);

    if (evidence->absence_proof.target_serial != state->cert.serial_number)
        return SM2_PKI_ERR_VERIFY;

    ic_ret = sm2_rev_absence_proof_verify_with_root(&evidence->root_record,
        now_ts, &evidence->absence_proof, pki_client_root_record_verify_cb,
        &verify_ctx);
    return sm2_pki_error_from_ic(ic_ret);
}

static sm2_pki_error_t pki_client_verify_carried_evidence(
    sm2_pki_client_state_t *state, const sm2_implicit_cert_t *cert,
    const sm2_pki_revocation_evidence_t *evidence, uint64_t now_ts,
    size_t matched_ca_index)
{
    if (!state || !cert || !evidence)
        return SM2_PKI_ERR_PARAM;

    const uint8_t *authority_id = NULL;
    size_t authority_id_len = 0;
    sm2_pki_error_t ret = pki_client_expected_authority_from_cert(
        cert, &authority_id, &authority_id_len);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    if (evidence->root_record.authority_id_len != authority_id_len
        || memcmp(evidence->root_record.authority_id, authority_id,
               authority_id_len)
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    if (evidence->absence_proof.target_serial != cert->serial_number)
        return SM2_PKI_ERR_VERIFY;

    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = true,
        .required_index = matched_ca_index };
    ret = pki_client_accept_root_record(
        state, &evidence->root_record, now_ts, &verify_ctx);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    const sm2_pki_root_cache_entry_t *entry
        = pki_client_find_root_cache_entry_const(
            state, authority_id, authority_id_len);
    if (!entry)
        return SM2_PKI_ERR_VERIFY;

    sm2_ic_error_t ic_ret = sm2_rev_absence_proof_verify_with_root(
        &entry->root_record, now_ts, &evidence->absence_proof,
        pki_client_root_record_verify_cb, &verify_ctx);
    return sm2_pki_error_from_ic(ic_ret);
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

sm2_pki_error_t sm2_pki_client_import_root_record(sm2_pki_client_ctx_t *ctx,
    const sm2_rev_root_record_t *root_record, uint64_t now_ts)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !root_record)
        return SM2_PKI_ERR_PARAM;

    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = false,
        .required_index = 0 };
    return pki_client_accept_root_record(
        state, root_record, now_ts, &verify_ctx);
}

sm2_pki_error_t sm2_pki_client_refresh_root(
    sm2_pki_client_ctx_t *ctx, uint64_t now_ts)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;
    if (!state->revocation_service)
        return SM2_PKI_ERR_STATE;
    if (!pki_client_bound_service_live(state))
        return SM2_PKI_ERR_STATE;

    pki_client_root_verify_ctx_t verify_ctx = { .store = &state->trust_store,
        .require_specific_index = false,
        .required_index = 0 };
    return pki_client_import_bound_root(state, now_ts, &verify_ctx);
}

sm2_pki_error_t sm2_pki_client_get_cached_root_record(
    const sm2_pki_client_ctx_t *ctx, sm2_rev_root_record_t *root_record)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !root_record)
        return SM2_PKI_ERR_PARAM;
    if (!state->has_last_root_cache_index
        || state->last_root_cache_index >= SM2_AUTH_MAX_CA_STORE)
        return SM2_PKI_ERR_STATE;

    const sm2_pki_root_cache_entry_t *entry
        = &state->root_cache[state->last_root_cache_index];
    if (!entry->used || !entry->has_root_record)
        return SM2_PKI_ERR_STATE;

    *root_record = entry->root_record;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_get_cached_root_record_for_authority(
    const sm2_pki_client_ctx_t *ctx, const uint8_t *authority_id,
    size_t authority_id_len, sm2_rev_root_record_t *root_record)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !root_record)
        return SM2_PKI_ERR_PARAM;

    const sm2_pki_root_cache_entry_t *entry
        = pki_client_find_root_cache_entry_const(
            state, authority_id, authority_id_len);
    if (!entry || !entry->has_root_record)
        return SM2_PKI_ERR_STATE;

    *root_record = entry->root_record;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_export_revocation_evidence(
    sm2_pki_client_ctx_t *ctx, uint64_t now_ts,
    sm2_pki_revocation_evidence_t *evidence)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !evidence)
        return SM2_PKI_ERR_PARAM;
    return pki_client_export_bound_evidence(state, now_ts, evidence);
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

    if (!request->revocation_evidence)
        return SM2_PKI_ERR_VERIFY;

    size_t local_matched_index = 0;
    sm2_pki_error_t ret = pki_client_verify_without_revocation(
        state, request, now_ts, &local_matched_index);
    if (ret != SM2_PKI_SUCCESS)
        return ret;
    if (matched_ca_index)
        *matched_ca_index = local_matched_index;

    return pki_client_verify_carried_evidence(state, request->cert,
        request->revocation_evidence, now_ts, local_matched_index);
}

sm2_pki_error_t sm2_pki_batch_verify(
    const sm2_auth_verify_item_t *items, size_t item_count, size_t *valid_count)
{
    return sm2_pki_error_from_ic(
        sm2_auth_batch_verify(items, item_count, valid_count));
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
