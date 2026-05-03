/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_service.h
 * @brief In-memory CA/RA service APIs for registration, issuance and
 * revocation.
 */

#ifndef SM2_PKI_SERVICE_H
#define SM2_PKI_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "sm2_crypto.h"
#include "sm2_revocation.h"
#include "sm2_implicit_cert.h"
#include "sm2_pki_transparency.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_PKI_MAX_IDENTITIES 256
#define SM2_PKI_MAX_ID_LEN 64
#define SM2_PKI_MAX_ISSUER_LEN 64

    typedef struct sm2_pki_service_ctx_st sm2_pki_service_ctx_t;

    /*
     * Opaque owning handle.
     * Instances must be created/destroyed via the API below.
     */
    sm2_pki_error_t sm2_pki_service_create(sm2_pki_service_ctx_t **ctx,
        const uint8_t *issuer_id, size_t issuer_id_len,
        size_t expected_revoked_items, uint64_t filter_ttl_sec,
        uint64_t now_ts);

    void sm2_pki_service_destroy(sm2_pki_service_ctx_t **ctx);

    sm2_pki_error_t sm2_pki_service_get_ca_public_key(
        const sm2_pki_service_ctx_t *ctx, sm2_ec_point_t *ca_public_key);

    /*
     * Startup/self-check helper. Validates that the internally managed CA
     * signing key remains within the expected SM2 private key range.
     */
    sm2_pki_error_t sm2_pki_service_validate_ca_key_material(
        const sm2_pki_service_ctx_t *ctx);

    sm2_pki_error_t sm2_pki_service_get_root_record(
        const sm2_pki_service_ctx_t *ctx, sm2_rev_root_record_t *root_record);

    /*
     * Returns the CA-signed issuance transparency root. Its Merkle leaves are
     * stable certificate commitments derived from the issued ECQV certificate
     * encoding.
     */
    sm2_pki_error_t sm2_pki_service_get_issuance_root_record(
        const sm2_pki_service_ctx_t *ctx, sm2_rev_root_record_t *root_record);

    /*
     * Preferred publication/export APIs for revocation artifacts. These keep
     * the service-side Merkle tree internal while exposing signed outputs.
     */
    sm2_pki_error_t sm2_pki_service_export_epoch_dir(sm2_pki_service_ctx_t *ctx,
        uint64_t epoch_id, size_t cache_top_levels, uint64_t valid_from,
        uint64_t valid_until, sm2_rev_epoch_dir_t **directory);

    sm2_pki_error_t sm2_pki_service_export_member_proof(
        const sm2_pki_service_ctx_t *ctx, uint64_t serial_number,
        sm2_rev_member_proof_t *proof);

    sm2_pki_error_t sm2_pki_service_export_absence_proof(
        const sm2_pki_service_ctx_t *ctx, uint64_t serial_number,
        sm2_rev_absence_proof_t *proof);

    sm2_pki_error_t sm2_pki_service_export_issuance_proof(
        const sm2_pki_service_ctx_t *ctx, const sm2_implicit_cert_t *cert,
        sm2_pki_issuance_member_proof_t *proof);

    /*
     * Explicitly publishes a fresh CA-signed revocation root/heartbeat object.
     * Query handling must not mint new signed facts implicitly.
     */
    sm2_pki_error_t sm2_pki_service_refresh_root(
        sm2_pki_service_ctx_t *ctx, uint64_t now_ts);

    sm2_pki_error_t sm2_pki_identity_register(sm2_pki_service_ctx_t *ctx,
        const uint8_t *identity, size_t identity_len, uint8_t key_usage);

    /*
     * New deployments must generate ECQV requests on the end-entity side and
     * submit them for authorization before issuance.
     */
    sm2_pki_error_t sm2_pki_cert_authorize_request(
        sm2_pki_service_ctx_t *ctx, const sm2_ic_cert_request_t *request);

    sm2_pki_error_t sm2_pki_cert_issue(sm2_pki_service_ctx_t *ctx,
        const sm2_ic_cert_request_t *request, uint64_t now_ts,
        sm2_ic_cert_result_t *result);

    sm2_pki_error_t sm2_pki_service_revoke(
        sm2_pki_service_ctx_t *ctx, uint64_t serial_number, uint64_t now_ts);

    sm2_pki_error_t sm2_pki_service_check_revocation(sm2_pki_service_ctx_t *ctx,
        uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
        sm2_rev_source_t *source);

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_SERVICE_H */
