/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle_cbor.c
 * @brief CBOR codec for Merkle proof types (member, non-member, multiproof,
 *        root record, cached member, epoch directory).
 */

#include "merkle_internal.h"
sm2_ic_error_t cbor_put_type_value(
    uint8_t major, uint64_t value, uint8_t *out, size_t out_cap, size_t *offset)
{
    if (!out || !offset || major > 7)
        return SM2_IC_ERR_PARAM;

    size_t off = *offset;
    if (value < 24)
    {
        if (off + 1 > out_cap)
            return SM2_IC_ERR_CBOR;
        out[off++] = (uint8_t)((major << 5) | (uint8_t)value);
    }
    else if (value <= 0xFFU)
    {
        if (off + 2 > out_cap)
            return SM2_IC_ERR_CBOR;
        out[off++] = (uint8_t)((major << 5) | 24U);
        out[off++] = (uint8_t)value;
    }
    else if (value <= 0xFFFFU)
    {
        if (off + 3 > out_cap)
            return SM2_IC_ERR_CBOR;
        out[off++] = (uint8_t)((major << 5) | 25U);
        out[off++] = (uint8_t)((value >> 8) & 0xFFU);
        out[off++] = (uint8_t)(value & 0xFFU);
    }
    else if (value <= 0xFFFFFFFFULL)
    {
        if (off + 5 > out_cap)
            return SM2_IC_ERR_CBOR;
        out[off++] = (uint8_t)((major << 5) | 26U);
        for (int i = 3; i >= 0; i--)
            out[off++] = (uint8_t)((value >> (i * 8)) & 0xFFU);
    }
    else
    {
        if (off + 9 > out_cap)
            return SM2_IC_ERR_CBOR;
        out[off++] = (uint8_t)((major << 5) | 27U);
        for (int i = 7; i >= 0; i--)
            out[off++] = (uint8_t)((value >> (i * 8)) & 0xFFU);
    }

    *offset = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_get_type_value(const uint8_t *in, size_t in_len,
    size_t *offset, uint8_t *major, uint64_t *value)
{
    if (!in || !offset || !major || !value)
        return SM2_IC_ERR_PARAM;
    if (*offset >= in_len)
        return SM2_IC_ERR_CBOR;

    uint8_t head = in[*offset];
    (*offset)++;

    *major = (uint8_t)(head >> 5);
    uint8_t add = (uint8_t)(head & 0x1FU);

    if (add < 24)
    {
        *value = add;
        return SM2_IC_SUCCESS;
    }

    if (add == 24)
    {
        if (*offset + 1 > in_len)
            return SM2_IC_ERR_CBOR;
        *value = in[(*offset)++];
        return SM2_IC_SUCCESS;
    }
    if (add == 25)
    {
        if (*offset + 2 > in_len)
            return SM2_IC_ERR_CBOR;
        *value = ((uint64_t)in[*offset] << 8) | (uint64_t)in[*offset + 1];
        *offset += 2;
        return SM2_IC_SUCCESS;
    }
    if (add == 26)
    {
        if (*offset + 4 > in_len)
            return SM2_IC_ERR_CBOR;
        uint64_t v = 0;
        for (int i = 0; i < 4; i++)
            v = (v << 8) | (uint64_t)in[*offset + i];
        *offset += 4;
        *value = v;
        return SM2_IC_SUCCESS;
    }
    if (add == 27)
    {
        if (*offset + 8 > in_len)
            return SM2_IC_ERR_CBOR;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++)
            v = (v << 8) | (uint64_t)in[*offset + i];
        *offset += 8;
        *value = v;
        return SM2_IC_SUCCESS;
    }

    return SM2_IC_ERR_CBOR;
}

sm2_ic_error_t cbor_put_bytes(const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_cap, size_t *offset)
{
    sm2_ic_error_t ret
        = cbor_put_type_value(2, (uint64_t)data_len, out, out_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*offset + data_len > out_cap)
        return SM2_IC_ERR_CBOR;
    memcpy(out + *offset, data, data_len);
    *offset += data_len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_get_bytes(const uint8_t *in, size_t in_len, size_t *offset,
    uint8_t *out, size_t out_len, size_t *actual_len)
{
    uint8_t major = 0;
    uint64_t len64 = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(in, in_len, offset, &major, &len64);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (major != 2)
        return SM2_IC_ERR_CBOR;
    if (len64 > SIZE_MAX)
        return SM2_IC_ERR_CBOR;

    size_t len = (size_t)len64;
    if (*offset + len > in_len)
        return SM2_IC_ERR_CBOR;
    if (!out || out_len < len)
        return SM2_IC_ERR_CBOR;

    memcpy(out, in + *offset, len);
    *offset += len;
    if (actual_len)
        *actual_len = len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_put_bool(
    bool value, uint8_t *out, size_t out_cap, size_t *offset)
{
    if (!out || !offset)
        return SM2_IC_ERR_PARAM;
    if (*offset + 1 > out_cap)
        return SM2_IC_ERR_CBOR;

    out[*offset] = value ? 0xF5U : 0xF4U;
    (*offset)++;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_get_bool(
    const uint8_t *in, size_t in_len, size_t *offset, bool *value)
{
    if (!in || !offset || !value)
        return SM2_IC_ERR_PARAM;
    if (*offset >= in_len)
        return SM2_IC_ERR_CBOR;

    if (in[*offset] == 0xF4U)
    {
        *value = false;
        (*offset)++;
        return SM2_IC_SUCCESS;
    }
    if (in[*offset] == 0xF5U)
    {
        *value = true;
        (*offset)++;
        return SM2_IC_SUCCESS;
    }
    return SM2_IC_ERR_CBOR;
}

sm2_ic_error_t cbor_put_null(uint8_t *out, size_t out_cap, size_t *offset)
{
    if (!out || !offset)
        return SM2_IC_ERR_PARAM;
    if (*offset + 1 > out_cap)
        return SM2_IC_ERR_CBOR;

    out[*offset] = 0xF6U;
    (*offset)++;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_get_null(const uint8_t *in, size_t in_len, size_t *offset)
{
    if (!in || !offset)
        return SM2_IC_ERR_PARAM;
    if (*offset >= in_len)
        return SM2_IC_ERR_CBOR;
    if (in[*offset] != 0xF6U)
        return SM2_IC_ERR_CBOR;

    (*offset)++;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_encode_member_proof_inner(
    const sm2_rev_merkle_membership_proof_t *proof, uint8_t *output,
    size_t output_cap, size_t *offset)
{
    if (!proof || !output || !offset)
        return SM2_IC_ERR_PARAM;
    if (proof->sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = cbor_put_type_value(4, 6, output, output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, proof->serial_number, output, output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)proof->leaf_index, output, output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)proof->leaf_count, output, output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)proof->sibling_count, output, output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        4, (uint64_t)proof->sibling_count, output, output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        ret = cbor_put_bytes(proof->sibling_hashes[i], SM2_REV_MERKLE_HASH_LEN,
            output, output_cap, offset);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_bytes(proof->sibling_on_left, proof->sibling_count, output,
        output_cap, offset);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t cbor_decode_member_proof_inner(
    sm2_rev_merkle_membership_proof_t *proof, const uint8_t *input,
    size_t input_len, size_t *offset)
{
    if (!proof || !input || !offset)
        return SM2_IC_ERR_PARAM;

    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, offset, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (major != 4 || arr_len != 6)
        return SM2_IC_ERR_CBOR;

    uint64_t serial = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &serial);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    uint64_t leaf_idx = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &leaf_idx);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    uint64_t leaf_count = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &leaf_count);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    uint64_t sibling_count = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &sibling_count);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;
    if (sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_CBOR;

    uint64_t hash_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &hash_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || hash_arr_len != sibling_count)
        return SM2_IC_ERR_CBOR;

    memset(proof, 0, sizeof(*proof));
    proof->serial_number = serial;
    proof->leaf_index = (size_t)leaf_idx;
    proof->leaf_count = (size_t)leaf_count;
    proof->sibling_count = (size_t)sibling_count;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        size_t actual = 0;
        ret = cbor_get_bytes(input, input_len, offset, proof->sibling_hashes[i],
            SM2_REV_MERKLE_HASH_LEN, &actual);
        if (ret != SM2_IC_SUCCESS || actual != SM2_REV_MERKLE_HASH_LEN)
            return SM2_IC_ERR_CBOR;
    }

    size_t path_len = 0;
    ret = cbor_get_bytes(input, input_len, offset, proof->sibling_on_left,
        SM2_REV_MERKLE_MAX_DEPTH, &path_len);
    if (ret != SM2_IC_SUCCESS || path_len != proof->sibling_count)
        return SM2_IC_ERR_CBOR;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_encode_member_proof(
    const sm2_rev_merkle_membership_proof_t *proof, uint8_t *output,
    size_t *output_len)
{
    if (!proof || !output || !output_len)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    sm2_ic_error_t ret
        = cbor_encode_member_proof_inner(proof, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_decode_member_proof(
    sm2_rev_merkle_membership_proof_t *proof, const uint8_t *input,
    size_t input_len)
{
    if (!proof || !input)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    sm2_ic_error_t ret
        = cbor_decode_member_proof_inner(proof, input, input_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (off != input_len)
        return SM2_IC_ERR_CBOR;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_encode_non_member_proof(
    const sm2_rev_merkle_non_membership_proof_t *proof, uint8_t *output,
    size_t *output_len)
{
    if (!proof || !output || !output_len)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    sm2_ic_error_t ret = cbor_put_type_value(4, 6, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, proof->target_serial, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(0, proof->leaf_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bool(proof->has_left_neighbor, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (proof->has_left_neighbor)
    {
        ret = cbor_encode_member_proof_inner(
            &proof->left_proof, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }
    else
    {
        ret = cbor_put_null(output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_bool(proof->has_right_neighbor, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (proof->has_right_neighbor)
    {
        ret = cbor_encode_member_proof_inner(
            &proof->right_proof, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }
    else
    {
        ret = cbor_put_null(output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_decode_non_member_proof(
    sm2_rev_merkle_non_membership_proof_t *proof, const uint8_t *input,
    size_t input_len)
{
    if (!proof || !input)
        return SM2_IC_ERR_PARAM;

    memset(proof, 0, sizeof(*proof));

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 6)
        return SM2_IC_ERR_CBOR;

    uint64_t target = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &target);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;
    proof->target_serial = target;

    uint64_t leaf_count = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &leaf_count);
    if (ret != SM2_IC_SUCCESS || major != 0 || leaf_count > SIZE_MAX)
        return SM2_IC_ERR_CBOR;
    proof->leaf_count = (size_t)leaf_count;

    ret = cbor_get_bool(input, input_len, &off, &proof->has_left_neighbor);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (proof->has_left_neighbor)
    {
        ret = cbor_decode_member_proof_inner(
            &proof->left_proof, input, input_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }
    else
    {
        ret = cbor_get_null(input, input_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_get_bool(input, input_len, &off, &proof->has_right_neighbor);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (proof->has_right_neighbor)
    {
        ret = cbor_decode_member_proof_inner(
            &proof->right_proof, input, input_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }
    else
    {
        ret = cbor_get_null(input, input_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    if (off != input_len)
        return SM2_IC_ERR_CBOR;

    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_revocation_merkle_cbor_encode_root_record(
    const sm2_rev_merkle_root_record_t *root_record, uint8_t *output,
    size_t *output_len)
{
    if (!root_record || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (root_record->signature_len == 0
        || root_record->signature_len > sizeof(root_record->signature))
    {
        return SM2_IC_ERR_PARAM;
    }

    size_t off = 0;
    sm2_ic_error_t ret = cbor_put_type_value(4, 5, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, root_record->root_version, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bytes(root_record->root_hash, SM2_REV_MERKLE_HASH_LEN,
        output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, root_record->valid_from, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, root_record->valid_until, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bytes(root_record->signature, root_record->signature_len,
        output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_decode_root_record(
    sm2_rev_merkle_root_record_t *root_record, const uint8_t *input,
    size_t input_len)
{
    if (!root_record || !input)
        return SM2_IC_ERR_PARAM;

    memset(root_record, 0, sizeof(*root_record));

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 5)
        return SM2_IC_ERR_CBOR;

    ret = cbor_get_type_value(
        input, input_len, &off, &major, &root_record->root_version);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    size_t hash_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, root_record->root_hash,
        SM2_REV_MERKLE_HASH_LEN, &hash_len);
    if (ret != SM2_IC_SUCCESS || hash_len != SM2_REV_MERKLE_HASH_LEN)
        return SM2_IC_ERR_CBOR;

    ret = cbor_get_type_value(
        input, input_len, &off, &major, &root_record->valid_from);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    ret = cbor_get_type_value(
        input, input_len, &off, &major, &root_record->valid_until);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    size_t sig_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, root_record->signature,
        sizeof(root_record->signature), &sig_len);
    if (ret != SM2_IC_SUCCESS || sig_len == 0)
        return SM2_IC_ERR_CBOR;

    root_record->signature_len = sig_len;

    if (off != input_len)
        return SM2_IC_ERR_CBOR;

    return SM2_IC_SUCCESS;
}
void sm2_revocation_merkle_multiproof_cleanup(
    sm2_rev_merkle_multiproof_t *proof)
{
    if (!proof)
        return;

    free(proof->items);
    free(proof->unique_hashes);
    memset(proof, 0, sizeof(*proof));
}

size_t multiproof_next_pow2(size_t v)
{
    if (v <= 1)
        return 1;

    size_t n = 1;
    while (n < v && n <= (SIZE_MAX >> 1))
        n <<= 1;

    return n < v ? v : n;
}

sm2_ic_error_t multiproof_reserve_unique_hashes(
    sm2_rev_merkle_multiproof_t *proof, size_t *capacity, size_t required,
    size_t hard_limit)
{
    if (!proof || !capacity)
        return SM2_IC_ERR_PARAM;
    if (required == 0)
        return SM2_IC_SUCCESS;
    if (required > hard_limit)
        return SM2_IC_ERR_MEMORY;

    if (*capacity >= required)
        return SM2_IC_SUCCESS;

    size_t new_capacity = (*capacity == 0) ? 1 : *capacity;
    while (new_capacity < required)
    {
        if (new_capacity > (SIZE_MAX >> 1))
            break;
        new_capacity <<= 1;
    }
    if (new_capacity < required)
        new_capacity = required;
    if (new_capacity > hard_limit)
        new_capacity = hard_limit;
    if (new_capacity < required)
        return SM2_IC_ERR_MEMORY;

    if (new_capacity > (SIZE_MAX / SM2_REV_MERKLE_HASH_LEN))
        return SM2_IC_ERR_MEMORY;
    void *new_mem = calloc(new_capacity, sizeof(*proof->unique_hashes));
    if (!new_mem)
        return SM2_IC_ERR_MEMORY;

    if (proof->unique_hashes && proof->unique_hash_count > 0)
    {
        memcpy(new_mem, proof->unique_hashes,
            proof->unique_hash_count * SM2_REV_MERKLE_HASH_LEN);
    }
    free(proof->unique_hashes);
    proof->unique_hashes = new_mem;
    *capacity = new_capacity;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t multiproof_find_or_add_hash(sm2_rev_merkle_multiproof_t *proof,
    const uint8_t hash[SM2_REV_MERKLE_HASH_LEN], size_t *capacity,
    size_t hard_limit, uint16_t *out_ref)
{
    if (!proof || !hash || !out_ref || !capacity)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < proof->unique_hash_count; i++)
    {
        if (memcmp(proof->unique_hashes[i], hash, SM2_REV_MERKLE_HASH_LEN) == 0)
        {
            *out_ref = (uint16_t)i;
            return SM2_IC_SUCCESS;
        }
    }

    if (proof->unique_hash_count > UINT16_MAX)
        return SM2_IC_ERR_MEMORY;

    sm2_ic_error_t ret = multiproof_reserve_unique_hashes(
        proof, capacity, proof->unique_hash_count + 1, hard_limit);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t idx = proof->unique_hash_count;
    memcpy(proof->unique_hashes[idx], hash, SM2_REV_MERKLE_HASH_LEN);
    proof->unique_hash_count++;
    *out_ref = (uint16_t)idx;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t multiproof_expand_member(
    const sm2_rev_merkle_multiproof_t *proof,
    const sm2_rev_merkle_multiproof_item_t *item,
    sm2_rev_merkle_membership_proof_t *member)
{
    if (!proof || !item || !member)
        return SM2_IC_ERR_PARAM;
    if (!proof->items || !proof->unique_hashes || proof->query_count == 0
        || proof->unique_hash_count == 0)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (item->sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_VERIFY;

    memset(member, 0, sizeof(*member));
    member->serial_number = item->serial_number;
    member->leaf_index = item->leaf_index;
    member->leaf_count = item->leaf_count;
    member->sibling_count = item->sibling_count;

    for (size_t i = 0; i < item->sibling_count; i++)
    {
        uint16_t ref = item->sibling_ref[i];
        if ((size_t)ref >= proof->unique_hash_count)
            return SM2_IC_ERR_VERIFY;

        memcpy(member->sibling_hashes[i], proof->unique_hashes[ref],
            SM2_REV_MERKLE_HASH_LEN);
        member->sibling_on_left[i] = item->sibling_on_left[i] ? 1U : 0U;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_build_multiproof(
    const sm2_rev_merkle_tree_t *tree, const uint64_t *serial_numbers,
    size_t serial_count, sm2_rev_merkle_multiproof_t *proof)
{
    if (!tree || !proof || !serial_numbers || serial_count == 0)
        return SM2_IC_ERR_PARAM;
    if (!tree->node_hashes || tree->level_count == 0 || tree->leaf_count == 0)
        return SM2_IC_ERR_PARAM;
    if (serial_count > SM2_REV_MERKLE_MULTI_MAX_QUERIES)
        return SM2_IC_ERR_PARAM;

    sm2_revocation_merkle_multiproof_cleanup(proof);

    if (serial_count > SIZE_MAX / sizeof(sm2_rev_merkle_multiproof_item_t))
        return SM2_IC_ERR_MEMORY;

    proof->items = (sm2_rev_merkle_multiproof_item_t *)calloc(
        serial_count, sizeof(sm2_rev_merkle_multiproof_item_t));
    if (!proof->items)
        return SM2_IC_ERR_MEMORY;

    size_t hash_capacity = 0;
    if (tree->level_count > (SIZE_MAX / serial_count))
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_MEMORY;
    }
    size_t hard_limit = serial_count * tree->level_count;
    if (hard_limit == 0)
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_MEMORY;
    }
    if (hard_limit > ((size_t)UINT16_MAX + 1U))
        hard_limit = (size_t)UINT16_MAX + 1U;

    size_t initial_capacity = multiproof_next_pow2(serial_count);
    if (initial_capacity > hard_limit)
        initial_capacity = hard_limit;

    sm2_ic_error_t reserve_ret = multiproof_reserve_unique_hashes(
        proof, &hash_capacity, initial_capacity, hard_limit);
    if (reserve_ret != SM2_IC_SUCCESS)
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return reserve_ret;
    }

    proof->query_count = serial_count;
    proof->unique_hash_count = 0;

    for (size_t i = 0; i < serial_count; i++)
    {
        sm2_rev_merkle_membership_proof_t member;
        sm2_ic_error_t ret = sm2_revocation_merkle_prove_member(
            tree, serial_numbers[i], &member);
        if (ret != SM2_IC_SUCCESS)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return ret;
        }

        sm2_rev_merkle_multiproof_item_t *item = &proof->items[i];
        item->serial_number = member.serial_number;
        item->leaf_index = member.leaf_index;
        item->leaf_count = member.leaf_count;
        item->sibling_count = member.sibling_count;

        for (size_t j = 0; j < member.sibling_count; j++)
        {
            uint16_t ref = 0;
            ret = multiproof_find_or_add_hash(proof, member.sibling_hashes[j],
                &hash_capacity, hard_limit, &ref);
            if (ret != SM2_IC_SUCCESS)
            {
                sm2_revocation_merkle_multiproof_cleanup(proof);
                return ret;
            }
            item->sibling_ref[j] = ref;
            item->sibling_on_left[j] = member.sibling_on_left[j] ? 1U : 0U;
        }
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_verify_multiproof(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_merkle_multiproof_t *proof)
{
    if (!root_hash || !proof)
        return SM2_IC_ERR_PARAM;
    if (!proof->items || !proof->unique_hashes || proof->query_count == 0
        || proof->unique_hash_count == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    for (size_t i = 0; i < proof->query_count; i++)
    {
        sm2_rev_merkle_membership_proof_t member;
        sm2_ic_error_t ret
            = multiproof_expand_member(proof, &proof->items[i], &member);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = sm2_revocation_merkle_verify_member(root_hash, &member);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_verify_multiproof_with_root(
    const sm2_rev_merkle_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_merkle_multiproof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx)
{
    sm2_ic_error_t ret = sm2_revocation_merkle_verify_root_record(
        root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    return sm2_revocation_merkle_verify_multiproof(
        root_record->root_hash, proof);
}

sm2_ic_error_t sm2_revocation_merkle_cbor_encode_multiproof(
    const sm2_rev_merkle_multiproof_t *proof, uint8_t *output,
    size_t *output_len)
{
    if (!proof || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (!proof->items || !proof->unique_hashes || proof->query_count == 0
        || proof->unique_hash_count == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    size_t off = 0;
    sm2_ic_error_t ret = cbor_put_type_value(4, 2, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        4, (uint64_t)proof->unique_hash_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < proof->unique_hash_count; i++)
    {
        ret = cbor_put_bytes(proof->unique_hashes[i], SM2_REV_MERKLE_HASH_LEN,
            output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_type_value(
        4, (uint64_t)proof->query_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < proof->query_count; i++)
    {
        const sm2_rev_merkle_multiproof_item_t *item = &proof->items[i];
        if (item->sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_PARAM;

        ret = cbor_put_type_value(4, 6, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(
            0, item->serial_number, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(
            0, (uint64_t)item->leaf_index, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(
            0, (uint64_t)item->leaf_count, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(
            0, (uint64_t)item->sibling_count, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(
            4, (uint64_t)item->sibling_count, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        for (size_t j = 0; j < item->sibling_count; j++)
        {
            if ((size_t)item->sibling_ref[j] >= proof->unique_hash_count)
                return SM2_IC_ERR_PARAM;

            ret = cbor_put_type_value(
                0, (uint64_t)item->sibling_ref[j], output, *output_len, &off);
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }

        ret = cbor_put_bytes(item->sibling_on_left, item->sibling_count, output,
            *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_decode_multiproof(
    sm2_rev_merkle_multiproof_t *proof, const uint8_t *input, size_t input_len)
{
    if (!proof || !input)
        return SM2_IC_ERR_PARAM;

    sm2_revocation_merkle_multiproof_cleanup(proof);

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 2)
        return SM2_IC_ERR_CBOR;

    uint64_t hash_count64 = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &hash_count64);
    if (ret != SM2_IC_SUCCESS || major != 4 || hash_count64 == 0
        || hash_count64 > UINT16_MAX)
    {
        return SM2_IC_ERR_CBOR;
    }

    size_t hash_count = (size_t)hash_count64;
    if (hash_count > SIZE_MAX / SM2_REV_MERKLE_HASH_LEN)
        return SM2_IC_ERR_CBOR;

    proof->unique_hashes = calloc(hash_count, sizeof(*proof->unique_hashes));
    if (!proof->unique_hashes)
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_MEMORY;
    }
    proof->unique_hash_count = hash_count;

    for (size_t i = 0; i < hash_count; i++)
    {
        size_t hash_len = 0;
        ret = cbor_get_bytes(input, input_len, &off, proof->unique_hashes[i],
            SM2_REV_MERKLE_HASH_LEN, &hash_len);
        if (ret != SM2_IC_SUCCESS || hash_len != SM2_REV_MERKLE_HASH_LEN)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }
    }

    uint64_t item_count64 = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &item_count64);
    if (ret != SM2_IC_SUCCESS || major != 4 || item_count64 == 0
        || item_count64 > SM2_REV_MERKLE_MULTI_MAX_QUERIES)
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_CBOR;
    }

    size_t item_count = (size_t)item_count64;
    if (item_count > SIZE_MAX / sizeof(sm2_rev_merkle_multiproof_item_t))
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_CBOR;
    }

    proof->items = (sm2_rev_merkle_multiproof_item_t *)calloc(
        item_count, sizeof(sm2_rev_merkle_multiproof_item_t));
    if (!proof->items)
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_MEMORY;
    }
    proof->query_count = item_count;

    for (size_t i = 0; i < item_count; i++)
    {
        uint64_t item_arr_len = 0;
        ret = cbor_get_type_value(
            input, input_len, &off, &major, &item_arr_len);
        if (ret != SM2_IC_SUCCESS || major != 4 || item_arr_len != 6)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t serial = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &serial);
        if (ret != SM2_IC_SUCCESS || major != 0)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t leaf_idx = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &leaf_idx);
        if (ret != SM2_IC_SUCCESS || major != 0)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t leaf_count = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &leaf_count);
        if (ret != SM2_IC_SUCCESS || major != 0)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t sibling_count = 0;
        ret = cbor_get_type_value(
            input, input_len, &off, &major, &sibling_count);
        if (ret != SM2_IC_SUCCESS || major != 0
            || sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t ref_arr_len = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &ref_arr_len);
        if (ret != SM2_IC_SUCCESS || major != 4 || ref_arr_len != sibling_count)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }

        sm2_rev_merkle_multiproof_item_t *item = &proof->items[i];
        item->serial_number = serial;
        item->leaf_index = (size_t)leaf_idx;
        item->leaf_count = (size_t)leaf_count;
        item->sibling_count = (size_t)sibling_count;

        for (size_t j = 0; j < item->sibling_count; j++)
        {
            uint64_t ref64 = 0;
            ret = cbor_get_type_value(input, input_len, &off, &major, &ref64);
            if (ret != SM2_IC_SUCCESS || major != 0 || ref64 > UINT16_MAX
                || ref64 >= hash_count)
            {
                sm2_revocation_merkle_multiproof_cleanup(proof);
                return SM2_IC_ERR_CBOR;
            }
            item->sibling_ref[j] = (uint16_t)ref64;
        }

        size_t path_len = 0;
        ret = cbor_get_bytes(input, input_len, &off, item->sibling_on_left,
            SM2_REV_MERKLE_MAX_DEPTH, &path_len);
        if (ret != SM2_IC_SUCCESS || path_len != item->sibling_count)
        {
            sm2_revocation_merkle_multiproof_cleanup(proof);
            return SM2_IC_ERR_CBOR;
        }
    }

    if (off != input_len)
    {
        sm2_revocation_merkle_multiproof_cleanup(proof);
        return SM2_IC_ERR_CBOR;
    }

    return SM2_IC_SUCCESS;
}
sm2_ic_error_t cbor_get_bytes_alloc(const uint8_t *in, size_t in_len,
    size_t *offset, uint8_t **out, size_t *out_len)
{
    uint8_t major = 0;
    uint64_t len64 = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(in, in_len, offset, &major, &len64);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (major != 2 || len64 > SIZE_MAX)
        return SM2_IC_ERR_CBOR;

    size_t len = (size_t)len64;
    if (*offset + len > in_len)
        return SM2_IC_ERR_CBOR;

    uint8_t *buf = NULL;
    if (len > 0)
    {
        buf = (uint8_t *)calloc(len, 1);
        if (!buf)
            return SM2_IC_ERR_MEMORY;
        memcpy(buf, in + *offset, len);
    }

    *offset += len;
    *out = buf;
    *out_len = len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_encode_cached_member_proof(
    const sm2_rev_merkle_cached_member_proof_t *proof, uint8_t *output,
    size_t *output_len)
{
    if (!proof || !output || !output_len)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    sm2_ic_error_t ret = cbor_put_type_value(4, 2, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)proof->omitted_top_levels, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_encode_member_proof_inner(
        &proof->proof, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_decode_cached_member_proof(
    sm2_rev_merkle_cached_member_proof_t *proof, const uint8_t *input,
    size_t input_len)
{
    if (!proof || !input)
        return SM2_IC_ERR_PARAM;

    memset(proof, 0, sizeof(*proof));

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 2)
        return SM2_IC_ERR_CBOR;

    uint64_t omitted = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &omitted);
    if (ret != SM2_IC_SUCCESS || major != 0
        || omitted > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_CBOR;

    ret = cbor_decode_member_proof_inner(&proof->proof, input, input_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (off != input_len)
        return SM2_IC_ERR_CBOR;

    proof->omitted_top_levels = (size_t)omitted;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_encode_epoch_directory(
    const sm2_rev_merkle_epoch_directory_t *directory, uint8_t *output,
    size_t *output_len)
{
    if (!directory || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (!directory->cached_hashes || directory->cache_level_count == 0)
        return SM2_IC_ERR_PARAM;
    if (directory->directory_signature_len == 0
        || directory->directory_signature_len
            > sizeof(directory->directory_signature))
    {
        return SM2_IC_ERR_PARAM;
    }

    uint8_t root_buf[512];
    size_t root_len = sizeof(root_buf);
    sm2_ic_error_t ret = sm2_revocation_merkle_cbor_encode_root_record(
        &directory->root_record, root_buf, &root_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t off = 0;
    ret = cbor_put_type_value(4, 8, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, directory->epoch_id, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bytes(root_buf, root_len, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)directory->tree_level_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)directory->cache_level_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        4, (uint64_t)directory->cache_level_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < directory->cache_level_count; i++)
    {
        ret = cbor_put_type_value(4, 2, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(0,
            (uint64_t)directory->cached_level_indices[i], output, *output_len,
            &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        size_t level_size = directory->cached_level_sizes[i];
        size_t level_off = directory->cached_level_offsets[i];
        ret = cbor_put_bytes(
            (const uint8_t *)(directory->cached_hashes + level_off),
            level_size * SM2_REV_MERKLE_HASH_LEN, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_type_value(
        0, directory->patch_version, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        4, (uint64_t)directory->patch_item_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < directory->patch_item_count; i++)
    {
        ret = cbor_put_type_value(4, 2, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(0, directory->patch_items[i].serial_number,
            output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_bool(
            directory->patch_items[i].revoked, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_bytes(directory->directory_signature,
        directory->directory_signature_len, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_cbor_decode_epoch_directory(
    sm2_rev_merkle_epoch_directory_t *directory, const uint8_t *input,
    size_t input_len)
{
    if (!directory || !input)
        return SM2_IC_ERR_PARAM;

    sm2_revocation_merkle_epoch_directory_cleanup(directory);

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 8)
        return SM2_IC_ERR_CBOR;

    ret = cbor_get_type_value(
        input, input_len, &off, &major, &directory->epoch_id);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    uint8_t *root_buf = NULL;
    size_t root_len = 0;
    ret = cbor_get_bytes_alloc(input, input_len, &off, &root_buf, &root_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_revocation_merkle_cbor_decode_root_record(
        &directory->root_record, root_buf, root_len);
    free(root_buf);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint64_t tree_levels = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &tree_levels);
    if (ret != SM2_IC_SUCCESS || major != 0 || tree_levels <= 1
        || tree_levels > SM2_REV_MERKLE_MAX_DEPTH)
    {
        return SM2_IC_ERR_CBOR;
    }
    directory->tree_level_count = (size_t)tree_levels;

    uint64_t cache_levels = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &cache_levels);
    if (ret != SM2_IC_SUCCESS || major != 0 || cache_levels == 0
        || cache_levels > SM2_REV_MERKLE_EPOCH_MAX_CACHE_LEVELS
        || cache_levels >= tree_levels)
    {
        return SM2_IC_ERR_CBOR;
    }
    directory->cache_level_count = (size_t)cache_levels;

    uint64_t level_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &level_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || level_arr_len != cache_levels)
        return SM2_IC_ERR_CBOR;

    uint8_t *level_blobs[SM2_REV_MERKLE_MAX_DEPTH];
    size_t level_blob_lens[SM2_REV_MERKLE_MAX_DEPTH];
    memset(level_blobs, 0, sizeof(level_blobs));
    memset(level_blob_lens, 0, sizeof(level_blob_lens));

    size_t total_hashes = 0;
    for (size_t i = 0; i < directory->cache_level_count; i++)
    {
        uint64_t entry_len = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &entry_len);
        if (ret != SM2_IC_SUCCESS || major != 4 || entry_len != 2)
            goto decode_fail;

        uint64_t level_idx = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &level_idx);
        if (ret != SM2_IC_SUCCESS || major != 0 || level_idx >= tree_levels)
            goto decode_fail;

        uint8_t *blob = NULL;
        size_t blob_len = 0;
        ret = cbor_get_bytes_alloc(input, input_len, &off, &blob, &blob_len);
        if (ret != SM2_IC_SUCCESS)
            goto decode_fail;
        if (blob_len == 0 || (blob_len % SM2_REV_MERKLE_HASH_LEN) != 0)
        {
            free(blob);
            ret = SM2_IC_ERR_CBOR;
            goto decode_fail;
        }

        size_t level_size = blob_len / SM2_REV_MERKLE_HASH_LEN;
        if (total_hashes > SIZE_MAX - level_size)
        {
            free(blob);
            ret = SM2_IC_ERR_CBOR;
            goto decode_fail;
        }

        directory->cached_level_indices[i] = (size_t)level_idx;
        directory->cached_level_sizes[i] = level_size;
        directory->cached_level_offsets[i] = total_hashes;
        total_hashes += level_size;

        level_blobs[i] = blob;
        level_blob_lens[i] = blob_len;
    }

    directory->cached_hash_count = total_hashes;
    directory->cached_hashes
        = calloc(total_hashes, sizeof(*directory->cached_hashes));
    if (!directory->cached_hashes)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto decode_fail;
    }

    for (size_t i = 0; i < directory->cache_level_count; i++)
    {
        size_t level_off = directory->cached_level_offsets[i];
        memcpy(directory->cached_hashes + level_off, level_blobs[i],
            level_blob_lens[i]);
        free(level_blobs[i]);
        level_blobs[i] = NULL;
    }

    ret = cbor_get_type_value(
        input, input_len, &off, &major, &directory->patch_version);
    if (ret != SM2_IC_SUCCESS || major != 0)
        goto decode_fail;

    uint64_t patch_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &patch_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4)
        goto decode_fail;
    if (patch_arr_len > SIZE_MAX / sizeof(sm2_crl_delta_item_t))
    {
        ret = SM2_IC_ERR_CBOR;
        goto decode_fail;
    }

    directory->patch_item_count = (size_t)patch_arr_len;
    if (directory->patch_item_count > 0)
    {
        directory->patch_items = (sm2_crl_delta_item_t *)calloc(
            directory->patch_item_count, sizeof(sm2_crl_delta_item_t));
        if (!directory->patch_items)
        {
            ret = SM2_IC_ERR_MEMORY;
            goto decode_fail;
        }

        for (size_t i = 0; i < directory->patch_item_count; i++)
        {
            uint64_t pair_len = 0;
            ret = cbor_get_type_value(
                input, input_len, &off, &major, &pair_len);
            if (ret != SM2_IC_SUCCESS || major != 4 || pair_len != 2)
                goto decode_fail;

            ret = cbor_get_type_value(input, input_len, &off, &major,
                &directory->patch_items[i].serial_number);
            if (ret != SM2_IC_SUCCESS || major != 0)
                goto decode_fail;

            ret = cbor_get_bool(
                input, input_len, &off, &directory->patch_items[i].revoked);
            if (ret != SM2_IC_SUCCESS)
                goto decode_fail;
        }
    }

    size_t sig_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, directory->directory_signature,
        sizeof(directory->directory_signature), &sig_len);
    if (ret != SM2_IC_SUCCESS || sig_len == 0)
        goto decode_fail;
    directory->directory_signature_len = sig_len;

    if (off != input_len)
    {
        ret = SM2_IC_ERR_CBOR;
        goto decode_fail;
    }

    return SM2_IC_SUCCESS;

decode_fail:
    for (size_t i = 0; i < SM2_REV_MERKLE_MAX_DEPTH; i++)
        free(level_blobs[i]);
    sm2_revocation_merkle_epoch_directory_cleanup(directory);
    return ret;
}
