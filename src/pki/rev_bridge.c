/* SPDX-License-Identifier: Apache-2.0 */

#include "pki_internal.h"
#include "../revoke/revoke_internal.h"
#include <stdlib.h>

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
    const uint8_t *authority_id, size_t authority_id_len,
    sm2_rev_tree_t **tree, sm2_rev_root_record_t *root_record,
    uint64_t *root_valid_until)
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
