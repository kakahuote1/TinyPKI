/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2_PKI_INTERNAL_H
#define SM2_PKI_INTERNAL_H

#include "sm2_pki_client.h"
#include "sm2_pki_service.h"

typedef struct sm2_pki_service_ctx_st sm2_pki_service_state_t;
typedef struct sm2_pki_client_ctx_st sm2_pki_client_state_t;

sm2_ic_error_t sm2_pki_rev_snapshot_create(
    const sm2_rev_ctx_t *src, sm2_rev_ctx_t **snapshot);
void sm2_pki_rev_snapshot_release(sm2_rev_ctx_t **snapshot);
void sm2_pki_rev_snapshot_restore(sm2_rev_ctx_t *dst, sm2_rev_ctx_t **snapshot);
sm2_ic_error_t sm2_pki_rev_prepare_root_publication(const sm2_rev_ctx_t *ctx,
    uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    const uint8_t *authority_id, size_t authority_id_len,
    sm2_rev_tree_t **tree, sm2_rev_root_record_t *root_record,
    uint64_t *root_valid_until);
void sm2_pki_rev_set_root_valid_until(
    sm2_rev_ctx_t *ctx, uint64_t root_valid_until);

sm2_pki_error_t sm2_pki_service_acquire_revocation_binding(
    sm2_pki_service_ctx_t *ctx, sm2_pki_service_state_t **bound_state);
void sm2_pki_service_release_revocation_binding(sm2_pki_service_state_t *state);
sm2_ic_error_t sm2_pki_service_query_revocation_binding(
    sm2_pki_service_state_t *state, uint64_t serial_number, uint64_t now_ts,
    sm2_rev_status_t *status, sm2_rev_source_t *source);

typedef struct
{
    bool used;
    bool has_root_record;
    uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
    size_t authority_id_len;
    sm2_rev_root_record_t root_record;
    uint64_t highest_seen_root_version;
} sm2_pki_root_cache_entry_t;

typedef struct
{
    bool used;
    uint8_t identity[SM2_PKI_MAX_ID_LEN];
    size_t identity_len;
    uint8_t key_usage;
    uint64_t issued_serial;
    bool revoked;
    bool has_pending_request;
    sm2_ec_point_t pending_temp_public_key;
} sm2_pki_identity_entry_t;

struct sm2_pki_service_ctx_st
{
    bool initialized;
    uint8_t issuer_id[SM2_PKI_MAX_ISSUER_LEN];
    size_t issuer_id_len;

    sm2_private_key_t ca_private_key;
    sm2_ec_point_t ca_public_key;

    sm2_pki_identity_entry_t identities[SM2_PKI_MAX_IDENTITIES];
    size_t identity_count;

    sm2_rev_ctx_t *rev_ctx;
    sm2_rev_tree_t *rev_tree;
    sm2_rev_root_record_t rev_root_record;
    bool revocation_state_ready;
    size_t revocation_binding_refs;
    bool revocation_binding_retired;
};

struct sm2_pki_client_ctx_st
{
    bool initialized;
    sm2_implicit_cert_t cert;
    sm2_private_key_t private_key;
    sm2_ec_point_t public_key;
    bool has_identity_keys;

    sm2_auth_trust_store_t trust_store;
    sm2_pki_service_state_t *revocation_service;
    sm2_auth_revocation_query_fn revocation_query_fn;
    void *revocation_query_user_ctx;
    sm2_pki_root_cache_entry_t root_cache[SM2_AUTH_MAX_CA_STORE];
    size_t last_root_cache_index;
    bool has_last_root_cache_index;

    sm2_auth_sign_pool_t sign_pool;
    bool sign_pool_enabled;
};

#endif /* SM2_PKI_INTERNAL_H */
