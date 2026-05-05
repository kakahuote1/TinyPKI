/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_service.c
 * @brief In-memory CA/RA service implementation.
 */

#include "pki_internal.h"
#include "sm2_auth.h"
#include "sm2_secure_mem.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static sm2_pki_service_state_t *service_state(sm2_pki_service_ctx_t *ctx)
{
    return ctx;
}

static const sm2_pki_service_state_t *service_state_const(
    const sm2_pki_service_ctx_t *ctx)
{
    return ctx;
}

static void service_finalize_state(sm2_pki_service_state_t *state)
{
    if (!state)
        return;

    sm2_pki_issuance_tree_cleanup(&state->issuance_tree);
    free(state->issuance_commitments);
    state->issuance_commitments = NULL;
    free(state->certs);
    state->certs = NULL;
    sm2_secure_memzero(state, sizeof(*state));
    free(state);
}

static void service_retire_state(sm2_pki_service_state_t *state)
{
    if (!state || state->revocation_binding_retired)
        return;

    size_t binding_refs = state->revocation_binding_refs;
    sm2_pki_issuance_tree_cleanup(&state->issuance_tree);
    sm2_rev_tree_cleanup(&state->rev_tree);
    sm2_rev_cleanup(&state->rev_ctx);
    free(state->issuance_commitments);
    state->issuance_commitments = NULL;
    free(state->certs);
    state->certs = NULL;
    sm2_secure_memzero(state, sizeof(*state));
    state->revocation_binding_refs = binding_refs;
    state->revocation_binding_retired = true;
}

static bool service_valid_key_usage(uint8_t key_usage)
{
    const uint8_t allowed_mask = SM2_KU_DIGITAL_SIGNATURE
        | SM2_KU_NON_REPUDIATION | SM2_KU_KEY_ENCIPHERMENT
        | SM2_KU_DATA_ENCIPHERMENT | SM2_KU_KEY_AGREEMENT;
    return key_usage != 0 && (key_usage & (uint8_t)(~allowed_mask)) == 0;
}

static bool service_request_matches_identity(
    const sm2_pki_identity_entry_t *entry, const sm2_ic_cert_request_t *request)
{
    if (!entry || !request)
        return false;
    if (request->subject_id_len != entry->identity_len)
        return false;
    if (memcmp(request->subject_id, entry->identity, entry->identity_len) != 0)
        return false;
    return request->key_usage == entry->key_usage;
}

static bool service_request_matches_pending(
    const sm2_pki_identity_entry_t *entry, const sm2_ic_cert_request_t *request)
{
    if (!entry || !entry->has_pending_request || !request)
        return false;

    return service_request_matches_identity(entry, request)
        && memcmp(&entry->pending_temp_public_key, &request->temp_public_key,
               sizeof(request->temp_public_key))
        == 0;
}

static void service_clear_pending_request(sm2_pki_identity_entry_t *entry)
{
    if (!entry)
        return;
    entry->has_pending_request = false;
    memset(&entry->pending_temp_public_key, 0,
        sizeof(entry->pending_temp_public_key));
}

static sm2_pki_identity_entry_t *service_find_identity(
    sm2_pki_service_ctx_t *ctx, const uint8_t *identity, size_t identity_len)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state || !identity)
        return NULL;
    for (size_t i = 0; i < SM2_PKI_MAX_IDENTITIES; i++)
    {
        sm2_pki_identity_entry_t *e = &state->identities[i];
        if (!e->used)
            continue;
        if (e->identity_len == identity_len
            && memcmp(e->identity, identity, identity_len) == 0)
        {
            return e;
        }
    }
    return NULL;
}

static sm2_pki_cert_entry_t *service_find_by_serial(
    sm2_pki_service_ctx_t *ctx, uint64_t serial_number)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state || !state->certs)
        return NULL;
    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        sm2_pki_cert_entry_t *e = &state->certs[i];
        if (!e->used)
            continue;
        if (e->serial_number == serial_number)
            return e;
    }
    return NULL;
}

static sm2_pki_identity_entry_t *service_alloc_identity(
    sm2_pki_service_ctx_t *ctx)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state)
        return NULL;
    for (size_t i = 0; i < SM2_PKI_MAX_IDENTITIES; i++)
    {
        if (!state->identities[i].used)
            return &state->identities[i];
    }
    return NULL;
}

static size_t service_identity_index(
    const sm2_pki_service_state_t *state, const sm2_pki_identity_entry_t *entry)
{
    if (!state || !entry)
        return SIZE_MAX;
    return (size_t)(entry - state->identities);
}

static void service_compact_certificate_table(sm2_pki_service_state_t *state)
{
    if (!state || !state->certs || state->cert_capacity == 0)
        return;

    size_t write_index = 0;
    for (size_t read_index = 0; read_index < state->cert_capacity; read_index++)
    {
        sm2_pki_cert_entry_t *entry = &state->certs[read_index];
        if (!entry->used)
            continue;
        if (write_index != read_index)
            state->certs[write_index] = *entry;
        write_index++;
    }

    for (size_t i = write_index; i < state->cert_capacity; i++)
        memset(&state->certs[i], 0, sizeof(state->certs[i]));
    state->cert_count = write_index;
}

static sm2_pki_error_t service_grow_certificate_table(
    sm2_pki_service_ctx_t *ctx)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state)
        return SM2_PKI_ERR_PARAM;

    size_t new_capacity = state->cert_capacity == 0
        ? SM2_PKI_INITIAL_CERT_CAPACITY
        : state->cert_capacity * 2U;
    if (new_capacity < state->cert_capacity || new_capacity == 0)
        return SM2_PKI_ERR_MEMORY;
    if (new_capacity > SIZE_MAX / sizeof(*state->certs))
        return SM2_PKI_ERR_MEMORY;
    if (state->cert_count > new_capacity)
        return SM2_PKI_ERR_MEMORY;

    sm2_pki_cert_entry_t *new_entries
        = (sm2_pki_cert_entry_t *)calloc(new_capacity, sizeof(*new_entries));
    if (!new_entries)
        return SM2_PKI_ERR_MEMORY;

    if (state->certs && state->cert_count > 0)
    {
        memcpy(new_entries, state->certs,
            state->cert_count * sizeof(*new_entries));
    }

    free(state->certs);
    state->certs = new_entries;
    state->cert_capacity = new_capacity;
    return SM2_PKI_SUCCESS;
}

static sm2_pki_error_t service_alloc_certificate(
    sm2_pki_service_ctx_t *ctx, sm2_pki_cert_entry_t **cert_entry)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state || !cert_entry)
        return SM2_PKI_ERR_PARAM;

    *cert_entry = NULL;
    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        if (!state->certs[i].used)
        {
            *cert_entry = &state->certs[i];
            return SM2_PKI_SUCCESS;
        }
    }

    service_compact_certificate_table(state);
    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        if (!state->certs[i].used)
        {
            *cert_entry = &state->certs[i];
            return SM2_PKI_SUCCESS;
        }
    }

    sm2_pki_error_t ret = service_grow_certificate_table(ctx);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        if (!state->certs[i].used)
        {
            *cert_entry = &state->certs[i];
            return SM2_PKI_SUCCESS;
        }
    }

    return SM2_PKI_ERR_MEMORY;
}

static sm2_ic_error_t service_merkle_sign_cb(void *user_ctx,
    const uint8_t *data, size_t data_len, uint8_t *signature,
    size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    sm2_pki_service_ctx_t *ctx = (sm2_pki_service_ctx_t *)user_ctx;
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!state)
        return SM2_IC_ERR_PARAM;
    sm2_auth_signature_t sig;
    sm2_ic_error_t ret
        = sm2_auth_sign(&state->ca_private_key, data, data_len, &sig);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*signature_len < sig.der_len)
        return SM2_IC_ERR_MEMORY;

    memcpy(signature, sig.der, sig.der_len);
    *signature_len = sig.der_len;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t service_merkle_verify_cb(void *user_ctx,
    const uint8_t *data, size_t data_len, const uint8_t *signature,
    size_t signature_len)
{
    if (!user_ctx || !data || !signature || signature_len == 0
        || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_pki_service_ctx_t *ctx = (sm2_pki_service_ctx_t *)user_ctx;
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!state)
        return SM2_IC_ERR_PARAM;
    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    return sm2_auth_verify_signature(
        &state->ca_public_key, data, data_len, &sig);
}

static sm2_ic_error_t service_publish_revocation_root(
    sm2_pki_service_ctx_t *ctx, uint64_t now_ts, bool rebuild_tree)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state)
        return SM2_IC_ERR_PARAM;

    sm2_rev_root_record_t new_root_record;
    uint64_t new_root_valid_until = 0;
    memset(&new_root_record, 0, sizeof(new_root_record));

    sm2_ic_error_t ret = SM2_IC_SUCCESS;
    if (rebuild_tree)
    {
        sm2_rev_tree_t *new_tree = NULL;
        ret = sm2_pki_rev_prepare_root_publication(state->rev_ctx, now_ts,
            service_merkle_sign_cb, ctx, state->issuer_id, state->issuer_id_len,
            &new_tree, &new_root_record, &new_root_valid_until);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        sm2_rev_tree_cleanup(&state->rev_tree);
        state->rev_tree = new_tree;
    }
    else
    {
        ret = sm2_pki_rev_sign_existing_root(state->rev_ctx, state->rev_tree,
            now_ts, service_merkle_sign_cb, ctx, state->issuer_id,
            state->issuer_id_len, &new_root_record, &new_root_valid_until);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    state->rev_root_record = new_root_record;
    sm2_pki_rev_set_root_valid_until(state->rev_ctx, new_root_valid_until);
    state->revocation_state_ready = true;
    return SM2_IC_SUCCESS;
}

static uint64_t service_root_valid_until(
    const sm2_pki_service_state_t *state, uint64_t now_ts)
{
    uint64_t ttl = 300;
    if (state && state->rev_ctx)
    {
        uint64_t rev_until = sm2_rev_root_valid_until(state->rev_ctx);
        if (rev_until > now_ts)
            ttl = rev_until - now_ts;
    }
    if (ttl <= UINT64_MAX - now_ts)
        return now_ts + ttl;
    return UINT64_MAX;
}

static sm2_ic_error_t service_publish_issuance_root(
    sm2_pki_service_ctx_t *ctx, uint64_t now_ts, bool rebuild_tree)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state)
        return SM2_IC_ERR_PARAM;

    sm2_pki_issuance_tree_t *new_tree = NULL;
    sm2_pki_issuance_tree_t *tree_to_sign = state->issuance_tree;
    sm2_rev_root_record_t new_root_record;
    memset(&new_root_record, 0, sizeof(new_root_record));

    if (rebuild_tree || !tree_to_sign)
    {
        sm2_ic_error_t ret = sm2_pki_issuance_tree_build(&new_tree,
            state->issuance_commitments, state->issued_count,
            (uint64_t)state->issued_count);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        tree_to_sign = new_tree;
    }

    uint64_t valid_until = service_root_valid_until(state, now_ts);
    uint64_t valid_from = now_ts > 300U ? now_ts - 300U : 0U;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret
        = sm2_pki_issuance_tree_get_root_hash(tree_to_sign, root_hash);
    if (ret == SM2_IC_SUCCESS)
    {
        ret = sm2_pki_root_record_sign_hash(state->issuer_id,
            state->issuer_id_len, (uint64_t)state->issued_count, root_hash,
            valid_from, valid_until, service_merkle_sign_cb, ctx,
            &new_root_record);
    }
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_issuance_tree_cleanup(&new_tree);
        return ret;
    }

    if (new_tree)
    {
        sm2_pki_issuance_tree_cleanup(&state->issuance_tree);
        state->issuance_tree = new_tree;
    }
    state->issuance_root_record = new_root_record;
    state->issuance_state_ready = true;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t service_publish_epoch_root(
    sm2_pki_service_ctx_t *ctx, uint64_t now_ts)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !state || !state->revocation_state_ready
        || !state->issuance_state_ready)
    {
        return SM2_IC_ERR_PARAM;
    }

    uint64_t valid_from = state->rev_root_record.valid_from
            > state->issuance_root_record.valid_from
        ? state->rev_root_record.valid_from
        : state->issuance_root_record.valid_from;
    uint64_t valid_until = state->rev_root_record.valid_until
            < state->issuance_root_record.valid_until
        ? state->rev_root_record.valid_until
        : state->issuance_root_record.valid_until;
    if (now_ts > valid_from)
        valid_from = now_ts;
    if (valid_until < valid_from)
        return SM2_IC_ERR_VERIFY;

    uint64_t next_epoch_version
        = state->epoch_state_ready ? state->epoch_version + 1U : 1U;
    if (next_epoch_version == 0)
        return SM2_IC_ERR_VERIFY;

    sm2_pki_epoch_root_record_t epoch_root;
    memset(&epoch_root, 0, sizeof(epoch_root));
    sm2_ic_error_t ret = sm2_pki_epoch_root_sign(state->issuer_id,
        state->issuer_id_len, next_epoch_version,
        state->rev_root_record.root_version, state->rev_root_record.root_hash,
        state->issuance_root_record.root_version,
        state->issuance_root_record.root_hash, valid_from, valid_until,
        service_merkle_sign_cb, ctx, &epoch_root);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    state->epoch_root_record = epoch_root;
    state->epoch_version = next_epoch_version;
    state->epoch_state_ready = true;
    return SM2_IC_SUCCESS;
}

static sm2_pki_error_t service_ensure_issued_capacity(
    sm2_pki_service_state_t *state)
{
    if (!state)
        return SM2_PKI_ERR_PARAM;
    if (state->issued_count < state->issued_capacity)
        return SM2_PKI_SUCCESS;

    size_t new_capacity = state->issued_capacity == 0
        ? SM2_PKI_INITIAL_CERT_CAPACITY
        : state->issued_capacity * 2U;
    if (new_capacity < state->issued_capacity || new_capacity == 0
        || new_capacity > SIZE_MAX / sizeof(*state->issuance_commitments))
    {
        return SM2_PKI_ERR_MEMORY;
    }

    size_t commitment_size = sizeof(*state->issuance_commitments);
    void *new_commitments = calloc(new_capacity, commitment_size);
    if (!new_commitments)
        return SM2_PKI_ERR_MEMORY;
    if (state->issuance_commitments && state->issued_count > 0)
    {
        memcpy(new_commitments, state->issuance_commitments,
            state->issued_count * commitment_size);
    }

    free(state->issuance_commitments);
    state->issuance_commitments = new_commitments;
    state->issued_capacity = new_capacity;
    return SM2_PKI_SUCCESS;
}

static sm2_ic_error_t service_merkle_query(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    if (!cert || !user_ctx || !status)
        return SM2_IC_ERR_PARAM;

    sm2_pki_service_ctx_t *ctx = (sm2_pki_service_ctx_t *)user_ctx;
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!state || !state->revocation_state_ready)
        return SM2_IC_ERR_VERIFY;

    sm2_rev_member_proof_t member_proof;
    sm2_rev_absence_proof_t absence_proof;
    memset(&member_proof, 0, sizeof(member_proof));
    memset(&absence_proof, 0, sizeof(absence_proof));

    sm2_ic_error_t ret = sm2_rev_tree_prove_member(
        state->rev_tree, cert->serial_number, &member_proof);
    if (ret == SM2_IC_SUCCESS)
    {
        ret = sm2_rev_member_proof_verify_with_root(&state->rev_root_record,
            now_ts, &member_proof, service_merkle_verify_cb, ctx);
        if (ret == SM2_IC_SUCCESS)
            *status = SM2_REV_STATUS_REVOKED;
        return ret;
    }

    if (ret != SM2_IC_ERR_VERIFY)
        return ret;

    ret = sm2_rev_tree_prove_absence(
        state->rev_tree, cert->serial_number, &absence_proof);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_rev_absence_proof_verify_with_root(&state->rev_root_record,
        now_ts, &absence_proof, service_merkle_verify_cb, ctx);
    if (ret == SM2_IC_SUCCESS)
        *status = SM2_REV_STATUS_GOOD;
    return ret;
}

static bool service_private_key_in_valid_range(
    const sm2_private_key_t *private_key)
{
    if (!private_key)
        return false;

    bool valid = false;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    BIGNUM *order = BN_new();
    BIGNUM *upper_bound = BN_new();
    BIGNUM *d_bn = BN_bin2bn(private_key->d, SM2_KEY_LEN, NULL);

    if (!group || !order || !upper_bound || !d_bn)
        goto cleanup;
    if (EC_GROUP_get_order(group, order, NULL) != 1)
        goto cleanup;
    if (BN_copy(upper_bound, order) == NULL)
        goto cleanup;
    if (!BN_sub_word(upper_bound, 1))
        goto cleanup;

    if (!BN_is_zero(d_bn) && !BN_is_negative(d_bn)
        && BN_cmp(d_bn, upper_bound) <= 0)
    {
        valid = true;
    }

cleanup:
    BN_clear_free(d_bn);
    BN_free(upper_bound);
    BN_free(order);
    EC_GROUP_free(group);
    return valid;
}

static sm2_pki_error_t service_generate_ca_private_key(
    sm2_private_key_t *private_key)
{
    if (!private_key)
        return SM2_PKI_ERR_PARAM;

    for (size_t attempt = 0; attempt < 64; attempt++)
    {
        if (sm2_ic_generate_random(private_key->d, SM2_KEY_LEN)
            != SM2_IC_SUCCESS)
        {
            return SM2_PKI_ERR_CRYPTO;
        }
        if (service_private_key_in_valid_range(private_key))
            return SM2_PKI_SUCCESS;
    }

    sm2_secure_memzero(private_key->d, SM2_KEY_LEN);
    return SM2_PKI_ERR_CRYPTO;
}

sm2_pki_error_t sm2_pki_service_acquire_revocation_binding(
    sm2_pki_service_ctx_t *ctx, sm2_pki_service_state_t **bound_state)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !state || !bound_state
        || state->revocation_binding_retired)
    {
        return SM2_PKI_ERR_PARAM;
    }

    if (state->revocation_binding_refs == SIZE_MAX)
        return SM2_PKI_ERR_MEMORY;

    state->revocation_binding_refs++;
    *bound_state = state;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_service_release_revocation_binding(sm2_pki_service_state_t *state)
{
    if (!state)
        return;

    if (state->revocation_binding_refs > 0)
        state->revocation_binding_refs--;
    if (state->revocation_binding_retired
        && state->revocation_binding_refs == 0)
        service_finalize_state(state);
}

bool sm2_pki_service_binding_live(const sm2_pki_service_state_t *state)
{
    return state && state->initialized && !state->revocation_binding_retired
        && state->revocation_state_ready;
}

sm2_pki_error_t sm2_pki_service_create(sm2_pki_service_ctx_t **ctx,
    const uint8_t *issuer_id, size_t issuer_id_len,
    size_t expected_revoked_items, uint64_t filter_ttl_sec, uint64_t now_ts)
{
    if (!ctx || !issuer_id || issuer_id_len == 0
        || issuer_id_len > SM2_PKI_MAX_ISSUER_LEN)
    {
        return SM2_PKI_ERR_PARAM;
    }
    *ctx = NULL;

    sm2_pki_service_state_t *state
        = (sm2_pki_service_state_t *)calloc(1, sizeof(*state));
    if (!state)
        return SM2_PKI_ERR_MEMORY;

    sm2_pki_error_t key_ret
        = service_generate_ca_private_key(&state->ca_private_key);
    if (key_ret != SM2_PKI_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return key_ret;
    }

    if (sm2_ic_sm2_point_mult(
            &state->ca_public_key, state->ca_private_key.d, SM2_KEY_LEN, NULL)
        != SM2_IC_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return SM2_PKI_ERR_CRYPTO;
    }
    sm2_ic_error_t ic_ret = sm2_rev_init(
        &state->rev_ctx, expected_revoked_items, filter_ttl_sec, now_ts);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return sm2_pki_error_from_ic(ic_ret);
    }

    memcpy(state->issuer_id, issuer_id, issuer_id_len);
    state->issuer_id_len = issuer_id_len;

    ic_ret = service_publish_revocation_root(state, now_ts, true);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return sm2_pki_error_from_ic(ic_ret);
    }

    ic_ret = service_publish_issuance_root(state, now_ts, true);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return sm2_pki_error_from_ic(ic_ret);
    }

    ic_ret = service_publish_epoch_root(state, now_ts);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return sm2_pki_error_from_ic(ic_ret);
    }

    ic_ret = sm2_rev_set_lookup(state->rev_ctx, service_merkle_query, state);
    if (ic_ret != SM2_IC_SUCCESS)
    {
        sm2_pki_service_destroy(&state);
        return sm2_pki_error_from_ic(ic_ret);
    }

    state->initialized = true;
    *ctx = state;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_service_destroy(sm2_pki_service_ctx_t **ctx)
{
    if (!ctx || !*ctx)
        return;
    sm2_pki_service_state_t *state = *ctx;
    if (state)
    {
        service_retire_state(state);
        if (state->revocation_binding_refs == 0)
            service_finalize_state(state);
    }
    *ctx = NULL;
}

sm2_pki_error_t sm2_pki_service_get_ca_public_key(
    const sm2_pki_service_ctx_t *ctx, sm2_ec_point_t *ca_public_key)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ca_public_key || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;
    *ca_public_key = state->ca_public_key;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_validate_ca_key_material(
    const sm2_pki_service_ctx_t *ctx)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;
    return service_private_key_in_valid_range(&state->ca_private_key)
        ? SM2_PKI_SUCCESS
        : SM2_PKI_ERR_VERIFY;
}

sm2_pki_error_t sm2_pki_service_get_root_record(
    const sm2_pki_service_ctx_t *ctx, sm2_rev_root_record_t *root_record)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !root_record || !ctx->initialized || !state
        || !state->revocation_state_ready)
        return SM2_PKI_ERR_PARAM;
    *root_record = state->rev_root_record;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_get_epoch_root_record(
    const sm2_pki_service_ctx_t *ctx, sm2_pki_epoch_root_record_t *root_record)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !root_record || !ctx->initialized || !state
        || !state->epoch_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }
    *root_record = state->epoch_root_record;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_export_epoch_dir(sm2_pki_service_ctx_t *ctx,
    uint64_t epoch_id, uint64_t valid_from, uint64_t valid_until,
    sm2_rev_epoch_dir_t **directory)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !state || !directory
        || !state->revocation_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }

    return sm2_pki_error_from_ic(sm2_rev_epoch_dir_build_with_authority(
        state->rev_tree, epoch_id, state->issuer_id, state->issuer_id_len,
        valid_from, valid_until, service_merkle_sign_cb, ctx, directory));
}

sm2_pki_error_t sm2_pki_service_export_member_proof(
    const sm2_pki_service_ctx_t *ctx, uint64_t serial_number,
    sm2_rev_member_proof_t *proof)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !proof
        || !state->revocation_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }

    return sm2_pki_error_from_ic(
        sm2_rev_tree_prove_member(state->rev_tree, serial_number, proof));
}

sm2_pki_error_t sm2_pki_service_export_absence_proof(
    const sm2_pki_service_ctx_t *ctx, uint64_t serial_number,
    sm2_rev_absence_proof_t *proof)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !proof
        || !state->revocation_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }

    return sm2_pki_error_from_ic(
        sm2_rev_tree_prove_absence(state->rev_tree, serial_number, proof));
}

sm2_pki_error_t sm2_pki_service_export_issuance_proof(
    const sm2_pki_service_ctx_t *ctx, const sm2_implicit_cert_t *cert,
    sm2_pki_issuance_member_proof_t *proof)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !cert || !proof
        || !state->issuance_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }

    uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    sm2_ic_error_t ret = sm2_pki_issuance_cert_commitment(cert, commitment);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    return sm2_pki_error_from_ic(sm2_pki_issuance_tree_prove_member(
        state->issuance_tree, commitment, proof));
}

sm2_pki_error_t sm2_pki_service_export_current_epoch_evidence(
    const sm2_pki_service_ctx_t *ctx, const sm2_implicit_cert_t *cert,
    sm2_pki_epoch_root_record_t *epoch_root,
    sm2_rev_absence_proof_t *revocation_proof,
    sm2_pki_issuance_member_proof_t *issuance_proof)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !cert || !epoch_root
        || !revocation_proof || !issuance_proof || !state->epoch_state_ready
        || !state->revocation_state_ready || !state->issuance_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }

    const sm2_pki_epoch_root_record_t *epoch = &state->epoch_root_record;
    if (epoch->revocation_root_version != state->rev_root_record.root_version
        || memcmp(epoch->revocation_root_hash, state->rev_root_record.root_hash,
               sizeof(epoch->revocation_root_hash))
            != 0
        || epoch->issuance_root_version
            != state->issuance_root_record.root_version
        || memcmp(epoch->issuance_root_hash,
               state->issuance_root_record.root_hash,
               sizeof(epoch->issuance_root_hash))
            != 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }

    sm2_rev_absence_proof_t rev_proof;
    sm2_pki_issuance_member_proof_t iss_proof;
    memset(&rev_proof, 0, sizeof(rev_proof));
    memset(&iss_proof, 0, sizeof(iss_proof));

    sm2_ic_error_t ic_ret = sm2_rev_tree_prove_absence(
        state->rev_tree, cert->serial_number, &rev_proof);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    ic_ret = sm2_pki_issuance_cert_commitment(cert, commitment);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    ic_ret = sm2_pki_issuance_tree_prove_member(
        state->issuance_tree, commitment, &iss_proof);
    if (ic_ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ic_ret);

    *epoch_root = *epoch;
    *revocation_proof = rev_proof;
    *issuance_proof = iss_proof;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_get_issuance_commitment_count(
    const sm2_pki_service_ctx_t *ctx, size_t *commitment_count)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !commitment_count
        || !state->issuance_state_ready)
    {
        return SM2_PKI_ERR_PARAM;
    }

    *commitment_count = state->issued_count;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_export_issuance_commitments(
    const sm2_pki_service_ctx_t *ctx, size_t start_index,
    sm2_pki_issuance_commitment_t *commitments, size_t commitment_capacity,
    size_t *commitment_count)
{
    const sm2_pki_service_state_t *state = service_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !commitment_count
        || !state->issuance_state_ready || start_index > state->issued_count)
    {
        return SM2_PKI_ERR_PARAM;
    }

    size_t available = state->issued_count - start_index;
    *commitment_count = available;
    if (available == 0)
        return SM2_PKI_SUCCESS;
    if (!commitments || commitment_capacity < available)
        return SM2_PKI_ERR_MEMORY;

    memcpy(commitments, state->issuance_commitments + start_index,
        available * sizeof(*commitments));
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_refresh_root(
    sm2_pki_service_ctx_t *ctx, uint64_t now_ts)
{
    if (!ctx || !ctx->initialized || !service_state(ctx))
        return SM2_PKI_ERR_PARAM;
    sm2_ic_error_t ret = service_publish_revocation_root(ctx, now_ts, false);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);
    ret = service_publish_issuance_root(ctx, now_ts, false);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);
    ret = service_publish_epoch_root(ctx, now_ts);
    return sm2_pki_error_from_ic(ret);
}

sm2_pki_error_t sm2_pki_identity_register(sm2_pki_service_ctx_t *ctx,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !identity || identity_len == 0
        || identity_len > SM2_PKI_MAX_ID_LEN || !state)
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (!service_valid_key_usage(key_usage))
        return SM2_PKI_ERR_PARAM;
    if (service_find_identity(ctx, identity, identity_len))
        return SM2_PKI_ERR_CONFLICT;

    sm2_pki_identity_entry_t *slot = service_alloc_identity(ctx);
    if (!slot)
        return SM2_PKI_ERR_MEMORY;

    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->identity, identity, identity_len);
    slot->identity_len = identity_len;
    slot->key_usage = key_usage;
    state->identity_count++;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_cert_authorize_request(
    sm2_pki_service_ctx_t *ctx, const sm2_ic_cert_request_t *request)
{
    if (!ctx || !ctx->initialized || !service_state(ctx) || !request)
        return SM2_PKI_ERR_PARAM;
    if (!service_valid_key_usage(request->key_usage))
        return SM2_PKI_ERR_PARAM;

    sm2_pki_identity_entry_t *entry = service_find_identity(
        ctx, request->subject_id, request->subject_id_len);
    if (!entry)
        return SM2_PKI_ERR_NOT_FOUND;
    if (!service_request_matches_identity(entry, request))
        return SM2_PKI_ERR_VERIFY;

    if (entry->has_pending_request
        && !service_request_matches_pending(entry, request))
    {
        return SM2_PKI_ERR_CONFLICT;
    }

    entry->pending_temp_public_key = request->temp_public_key;
    entry->has_pending_request = true;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_cert_issue(sm2_pki_service_ctx_t *ctx,
    const sm2_ic_cert_request_t *request, uint64_t now_ts,
    sm2_ic_cert_result_t *result)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !state || !request || !result)
        return SM2_PKI_ERR_PARAM;

    sm2_pki_identity_entry_t *entry = service_find_identity(
        ctx, request->subject_id, request->subject_id_len);
    if (!entry)
        return SM2_PKI_ERR_NOT_FOUND;
    if (!service_request_matches_pending(entry, request))
        return SM2_PKI_ERR_VERIFY;

    sm2_pki_cert_entry_t *cert_entry = NULL;
    sm2_pki_error_t alloc_ret = service_alloc_certificate(ctx, &cert_entry);
    if (alloc_ret != SM2_PKI_SUCCESS)
        return alloc_ret;

    sm2_ic_error_t ret = sm2_ic_ca_generate_cert(result, request,
        state->issuer_id, state->issuer_id_len, &state->ca_private_key,
        &state->ca_public_key, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    uint8_t issuance_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    ret = sm2_pki_issuance_cert_commitment(&result->cert, issuance_commitment);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    sm2_pki_error_t issued_ret = service_ensure_issued_capacity(state);
    if (issued_ret != SM2_PKI_SUCCESS)
        return issued_ret;

    ret = sm2_pki_issuance_tree_append(&state->issuance_tree,
        issuance_commitment, (uint64_t)state->issued_count + 1U);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    memcpy(state->issuance_commitments[state->issued_count],
        issuance_commitment, sizeof(issuance_commitment));
    state->issued_count++;
    ret = service_publish_issuance_root(ctx, now_ts, false);
    if (ret != SM2_IC_SUCCESS)
    {
        state->issued_count--;
        sm2_pki_issuance_tree_build(&state->issuance_tree,
            state->issuance_commitments, state->issued_count,
            (uint64_t)state->issued_count);
        return sm2_pki_error_from_ic(ret);
    }
    ret = service_publish_epoch_root(ctx, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    memset(cert_entry, 0, sizeof(*cert_entry));
    cert_entry->used = true;
    cert_entry->identity_index = service_identity_index(state, entry);
    cert_entry->serial_number = result->cert.serial_number;
    cert_entry->valid_until
        = result->cert.valid_duration <= UINT64_MAX - result->cert.valid_from
        ? result->cert.valid_from + result->cert.valid_duration
        : UINT64_MAX;
    cert_entry->revoked = false;
    state->cert_count++;
    service_clear_pending_request(entry);
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_revoke(
    sm2_pki_service_ctx_t *ctx, uint64_t serial_number, uint64_t now_ts)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !state || serial_number == 0)
        return SM2_PKI_ERR_PARAM;
    sm2_pki_cert_entry_t *entry = service_find_by_serial(ctx, serial_number);
    if (!entry)
        return SM2_PKI_ERR_NOT_FOUND;

    sm2_rev_delta_item_t item;
    item.serial_number = serial_number;
    item.revoked = true;

    sm2_rev_delta_t delta;
    delta.base_version = sm2_rev_version(state->rev_ctx);
    delta.new_version = delta.base_version + 1;
    delta.items = &item;
    delta.item_count = 1;

    sm2_rev_ctx_t *rollback = NULL;
    sm2_ic_error_t ret = sm2_pki_rev_snapshot_create(state->rev_ctx, &rollback);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ret = sm2_rev_apply_delta(state->rev_ctx, &delta, now_ts);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_rev_snapshot_release(&rollback);
        return sm2_pki_error_from_ic(ret);
    }

    ret = service_publish_revocation_root(ctx, now_ts, true);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_rev_snapshot_restore(state->rev_ctx, &rollback);
        return sm2_pki_error_from_ic(ret);
    }

    sm2_pki_rev_snapshot_release(&rollback);
    entry->revoked = true;
    ret = service_publish_epoch_root(ctx, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);
    return SM2_PKI_SUCCESS;
}

static bool service_cert_prunable(
    const sm2_pki_cert_entry_t *entry, uint64_t now_ts, uint64_t grace_sec)
{
    if (!entry || !entry->used || !entry->revoked)
        return false;
    if (now_ts <= entry->valid_until)
        return false;
    return now_ts - entry->valid_until > grace_sec;
}

sm2_pki_error_t sm2_pki_service_prune_expired_revocations(
    sm2_pki_service_ctx_t *ctx, uint64_t now_ts, uint64_t grace_sec,
    size_t *pruned_count)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;
    if (pruned_count)
        *pruned_count = 0;

    size_t candidate_count = 0;
    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        if (service_cert_prunable(&state->certs[i], now_ts, grace_sec))
            candidate_count++;
    }
    if (candidate_count == 0)
        return SM2_PKI_SUCCESS;

    sm2_rev_delta_item_t *items
        = (sm2_rev_delta_item_t *)calloc(candidate_count, sizeof(*items));
    if (!items)
        return SM2_PKI_ERR_MEMORY;

    size_t write = 0;
    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        if (!service_cert_prunable(&state->certs[i], now_ts, grace_sec))
            continue;
        items[write].serial_number = state->certs[i].serial_number;
        items[write].revoked = false;
        write++;
    }

    sm2_rev_delta_t delta;
    delta.base_version = sm2_rev_version(state->rev_ctx);
    delta.new_version = delta.base_version + 1U;
    delta.items = items;
    delta.item_count = write;

    sm2_rev_ctx_t *rollback = NULL;
    sm2_ic_error_t ret = sm2_pki_rev_snapshot_create(state->rev_ctx, &rollback);
    if (ret != SM2_IC_SUCCESS)
    {
        free(items);
        return sm2_pki_error_from_ic(ret);
    }

    ret = sm2_rev_apply_delta(state->rev_ctx, &delta, now_ts);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_rev_snapshot_release(&rollback);
        free(items);
        return sm2_pki_error_from_ic(ret);
    }

    ret = service_publish_revocation_root(ctx, now_ts, true);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_rev_snapshot_restore(state->rev_ctx, &rollback);
        free(items);
        return sm2_pki_error_from_ic(ret);
    }
    sm2_pki_rev_snapshot_release(&rollback);

    for (size_t i = 0; i < state->cert_capacity; i++)
    {
        if (!service_cert_prunable(&state->certs[i], now_ts, grace_sec))
            continue;
        memset(&state->certs[i], 0, sizeof(state->certs[i]));
        if (state->cert_count > 0)
            state->cert_count--;
    }
    if (pruned_count)
        *pruned_count = write;

    free(items);
    ret = service_publish_issuance_root(ctx, now_ts, false);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);
    ret = service_publish_epoch_root(ctx, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_check_revocation(sm2_pki_service_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    sm2_pki_service_state_t *state = service_state(ctx);
    if (!ctx || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(
        sm2_rev_query(state->rev_ctx, serial_number, now_ts, status, source));
}
