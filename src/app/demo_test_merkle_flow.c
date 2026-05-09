/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Demo Test 2:
 * Merkle accumulator capabilities:
 * 1) member/absence proof verification,
 * 2) multiproof bandwidth reduction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../revoke/revoke_internal.h"

static int check_ic(sm2_ic_error_t err, const char *step)
{
    if (err != SM2_IC_SUCCESS)
    {
        printf("[FAIL] %s, err=%d\n", step, (int)err);
        return 0;
    }
    printf("[OK]   %s\n", step);
    return 1;
}

int main(void)
{
    sm2_ic_error_t ret;

    enum
    {
        revoked_n = 1024,
        query_n = 16
    };

    uint64_t *revoked = NULL;

    sm2_rev_tree_t *tree = NULL;
    sm2_rev_member_proof_t mp_real;
    sm2_rev_absence_proof_t nmp;
    sm2_rev_multi_proof_t *multi = NULL;
    uint64_t queries[query_n];
    uint8_t tree_root_hash[SM2_REV_MERKLE_HASH_LEN];

    uint8_t multi_buf[1048576];
    size_t multi_len = sizeof(multi_buf);

    memset(&mp_real, 0, sizeof(mp_real));
    memset(&nmp, 0, sizeof(nmp));
    memset(queries, 0, sizeof(queries));
    memset(tree_root_hash, 0, sizeof(tree_root_hash));

    revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    if (!revoked)
    {
        printf("[FAIL] Allocate buffers\n");
        free(revoked);
        return 1;
    }
    printf("[OK]   Allocate buffers\n");

    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 700000ULL + i;

    uint64_t real_serial = revoked[512];
    uint64_t good_serial = 799999ULL;
    for (size_t i = 0; i < query_n; i++)
        queries[i] = revoked[500 + i];

    ret = sm2_rev_tree_build(&tree, revoked, revoked_n, 2026030701ULL);
    if (!check_ic(ret, "Build Merkle Tree"))
        goto cleanup;
    ret = sm2_rev_tree_get_root_hash(tree, tree_root_hash);
    if (!check_ic(ret, "Read Merkle Root Hash"))
        goto cleanup;

    ret = sm2_rev_tree_prove_member(tree, real_serial, &mp_real);
    if (!check_ic(ret, "Build Member Proof"))
        goto cleanup;

    ret = sm2_rev_tree_verify_member(tree_root_hash, &mp_real);
    if (!check_ic(ret, "Verify Member Proof"))
        goto cleanup;

    ret = sm2_rev_tree_prove_absence(tree, good_serial, &nmp);
    if (!check_ic(ret, "Build Non-Member Proof"))
        goto cleanup;

    ret = sm2_rev_tree_verify_absence(tree_root_hash, &nmp);
    if (!check_ic(ret, "Verify Non-Member Proof"))
        goto cleanup;

    ret = sm2_rev_multi_proof_build(tree, queries, query_n, &multi);
    if (!check_ic(ret, "Build Multi-Proof"))
        goto cleanup;

    ret = sm2_rev_multi_proof_verify(tree_root_hash, multi);
    if (!check_ic(ret, "Verify Multi-Proof"))
        goto cleanup;

    ret = sm2_rev_multi_proof_encode(multi, multi_buf, &multi_len);
    if (!check_ic(ret, "Encode Multi-Proof"))
        goto cleanup;

    size_t single_total = 0;
    for (size_t i = 0; i < query_n; i++)
    {
        sm2_rev_member_proof_t mp_each;
        uint8_t mp_buf[16384];
        size_t mp_len = sizeof(mp_buf);

        memset(&mp_each, 0, sizeof(mp_each));
        ret = sm2_rev_tree_prove_member(tree, queries[i], &mp_each);
        if (ret != SM2_IC_SUCCESS)
        {
            printf("[FAIL] Build Single Proof #%zu, err=%d\n", i, (int)ret);
            goto cleanup;
        }

        ret = sm2_rev_member_proof_encode(&mp_each, mp_buf, &mp_len);
        if (ret != SM2_IC_SUCCESS)
        {
            printf("[FAIL] Encode Single Proof #%zu, err=%d\n", i, (int)ret);
            goto cleanup;
        }
        single_total += mp_len;
    }

    double reduction = 0.0;
    if (single_total > 0)
        reduction = ((double)(single_total - multi_len) * 100.0)
            / (double)single_total;

    printf("[METRIC] single_total=%zu bytes, multiproof=%zu bytes, "
           "reduction=%.2f%%\n",
        single_total, multi_len, reduction);

    if (!(multi_len < single_total))
    {
        printf("[FAIL] Multi-Proof is not smaller than single proofs\n");
        goto cleanup;
    }
    printf("[OK]   Multi-Proof bandwidth reduction confirmed\n");

    printf("[PASS] demo_test_merkle_flow\n");
    sm2_rev_multi_proof_cleanup(&multi);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return 0;

cleanup:
    sm2_rev_multi_proof_cleanup(&multi);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return 1;
}
