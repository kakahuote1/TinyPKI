/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle_cbor.c
 * @brief CBOR codec for Merkle proof types (member, absence, multiproof,
 *
 * root record, epoch directory).
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
    const sm2_rev_member_proof_t *proof, uint8_t *output, size_t output_cap,
    size_t *offset)
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

    ret = cbor_put_bytes(
        proof->key, SM2_REV_MERKLE_HASH_LEN, output, output_cap, offset);
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
        ret = cbor_put_type_value(
            0, proof->sibling_depths[i], output, output_cap, offset);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

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

sm2_ic_error_t cbor_decode_member_proof_inner(sm2_rev_member_proof_t *proof,
    const uint8_t *input, size_t input_len, size_t *offset)
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

    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    size_t key_len = 0;
    ret = cbor_get_bytes(input, input_len, offset, key, sizeof(key), &key_len);
    if (ret != SM2_IC_SUCCESS || key_len != SM2_REV_MERKLE_HASH_LEN)
        return SM2_IC_ERR_CBOR;

    uint64_t sibling_count = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &sibling_count);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;
    if (sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_CBOR;

    uint64_t depth_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &depth_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || depth_arr_len != sibling_count)
        return SM2_IC_ERR_CBOR;

    memset(proof, 0, sizeof(*proof));
    proof->serial_number = serial;
    memcpy(proof->key, key, SM2_REV_MERKLE_HASH_LEN);
    proof->sibling_count = (size_t)sibling_count;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        uint64_t depth = 0;
        ret = cbor_get_type_value(input, input_len, offset, &major, &depth);
        if (ret != SM2_IC_SUCCESS || major != 0
            || depth >= SM2_REV_MERKLE_MAX_DEPTH)
        {
            return SM2_IC_ERR_CBOR;
        }
        proof->sibling_depths[i] = (uint16_t)depth;
    }

    uint64_t hash_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, offset, &major, &hash_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || hash_arr_len != sibling_count)
        return SM2_IC_ERR_CBOR;

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

sm2_ic_error_t sm2_rev_member_proof_encode(
    const sm2_rev_member_proof_t *proof, uint8_t *output, size_t *output_len)
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

sm2_ic_error_t sm2_rev_member_proof_decode(
    sm2_rev_member_proof_t *proof, const uint8_t *input, size_t input_len)
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

sm2_ic_error_t sm2_rev_absence_proof_encode(
    const sm2_rev_absence_proof_t *proof, uint8_t *output, size_t *output_len)
{
    if (!proof || !output || !output_len)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    if (proof->sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = cbor_put_type_value(4, 9, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, proof->target_serial, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bool(proof->tree_empty, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, proof->terminal_depth, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bytes(proof->terminal_key, SM2_REV_MERKLE_HASH_LEN, output,
        *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bytes(proof->terminal_hash, SM2_REV_MERKLE_HASH_LEN, output,
        *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        0, (uint64_t)proof->sibling_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_type_value(
        4, (uint64_t)proof->sibling_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        ret = cbor_put_type_value(
            0, proof->sibling_depths[i], output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_type_value(
        4, (uint64_t)proof->sibling_count, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        ret = cbor_put_bytes(proof->sibling_hashes[i], SM2_REV_MERKLE_HASH_LEN,
            output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    ret = cbor_put_bytes(proof->sibling_on_left, proof->sibling_count, output,
        *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_absence_proof_decode(
    sm2_rev_absence_proof_t *proof, const uint8_t *input, size_t input_len)
{
    if (!proof || !input)
        return SM2_IC_ERR_PARAM;

    memset(proof, 0, sizeof(*proof));

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 9)
        return SM2_IC_ERR_CBOR;

    uint64_t target = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &target);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;
    proof->target_serial = target;
    ret = merkle_serial_key(target, proof->target_key);
    if (ret != SM2_IC_SUCCESS)
        return SM2_IC_ERR_CBOR;

    ret = cbor_get_bool(input, input_len, &off, &proof->tree_empty);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint64_t terminal_depth = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &terminal_depth);
    if (ret != SM2_IC_SUCCESS || major != 0
        || terminal_depth > SM2_REV_MERKLE_MAX_DEPTH)
    {
        return SM2_IC_ERR_CBOR;
    }
    proof->terminal_depth = (uint16_t)terminal_depth;

    size_t terminal_key_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, proof->terminal_key,
        SM2_REV_MERKLE_HASH_LEN, &terminal_key_len);
    if (ret != SM2_IC_SUCCESS || terminal_key_len != SM2_REV_MERKLE_HASH_LEN)
    {
        return SM2_IC_ERR_CBOR;
    }

    size_t terminal_hash_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, proof->terminal_hash,
        SM2_REV_MERKLE_HASH_LEN, &terminal_hash_len);
    if (ret != SM2_IC_SUCCESS || terminal_hash_len != SM2_REV_MERKLE_HASH_LEN)
    {
        return SM2_IC_ERR_CBOR;
    }

    uint64_t sibling_count = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &sibling_count);
    if (ret != SM2_IC_SUCCESS || major != 0
        || sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
    {
        return SM2_IC_ERR_CBOR;
    }
    proof->sibling_count = (size_t)sibling_count;

    uint64_t depth_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &depth_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || depth_arr_len != sibling_count)
        return SM2_IC_ERR_CBOR;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        uint64_t depth = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &depth);
        if (ret != SM2_IC_SUCCESS || major != 0
            || depth >= SM2_REV_MERKLE_MAX_DEPTH)
        {
            return SM2_IC_ERR_CBOR;
        }
        proof->sibling_depths[i] = (uint16_t)depth;
    }

    uint64_t hash_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &hash_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || hash_arr_len != sibling_count)
        return SM2_IC_ERR_CBOR;

    for (size_t i = 0; i < proof->sibling_count; i++)
    {
        size_t hash_len = 0;
        ret = cbor_get_bytes(input, input_len, &off, proof->sibling_hashes[i],
            SM2_REV_MERKLE_HASH_LEN, &hash_len);
        if (ret != SM2_IC_SUCCESS || hash_len != SM2_REV_MERKLE_HASH_LEN)
            return SM2_IC_ERR_CBOR;
    }

    size_t path_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, proof->sibling_on_left,
        SM2_REV_MERKLE_MAX_DEPTH, &path_len);
    if (ret != SM2_IC_SUCCESS || path_len != proof->sibling_count)
        return SM2_IC_ERR_CBOR;

    if (off != input_len)
        return SM2_IC_ERR_CBOR;

    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_rev_root_encode(const sm2_rev_root_record_t *root_record,
    uint8_t *output, size_t *output_len)
{
    if (!root_record || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (root_record->authority_id_len == 0
        || root_record->authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
        return SM2_IC_ERR_PARAM;
    if (root_record->signature_len == 0
        || root_record->signature_len > sizeof(root_record->signature))
    {
        return SM2_IC_ERR_PARAM;
    }

    size_t off = 0;
    sm2_ic_error_t ret = cbor_put_type_value(4, 6, output, *output_len, &off);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = cbor_put_bytes(root_record->authority_id,
        root_record->authority_id_len, output, *output_len, &off);
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

sm2_ic_error_t sm2_rev_root_decode(
    sm2_rev_root_record_t *root_record, const uint8_t *input, size_t input_len)
{
    if (!root_record || !input)
        return SM2_IC_ERR_PARAM;

    memset(root_record, 0, sizeof(*root_record));

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    sm2_ic_error_t ret
        = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 6)
        return SM2_IC_ERR_CBOR;

    size_t authority_id_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, root_record->authority_id,
        SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN, &authority_id_len);
    if (ret != SM2_IC_SUCCESS || authority_id_len == 0)
        return SM2_IC_ERR_CBOR;
    root_record->authority_id_len = authority_id_len;

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
static void multiproof_reset(sm2_rev_multi_proof_t *proof)
{
    if (!proof)
        return;

    free(proof->items);
    free(proof->unique_hashes);
    memset(proof, 0, sizeof(*proof));
}

static sm2_ic_error_t multiproof_ensure(sm2_rev_multi_proof_t **proof)
{
    if (!proof)
        return SM2_IC_ERR_PARAM;
    if (!*proof)
    {
        *proof = (sm2_rev_multi_proof_t *)calloc(1, sizeof(**proof));
        if (!*proof)
            return SM2_IC_ERR_MEMORY;
    }
    return SM2_IC_SUCCESS;
}

static void epoch_dir_decode_reset(sm2_rev_epoch_dir_t *directory)
{
    if (!directory)
        return;

    free(directory->patch_items);
    memset(directory, 0, sizeof(*directory));
}

static sm2_ic_error_t epoch_dir_decode_ensure(sm2_rev_epoch_dir_t **directory)
{
    if (!directory)
        return SM2_IC_ERR_PARAM;
    if (!*directory)
    {
        *directory = (sm2_rev_epoch_dir_t *)calloc(1, sizeof(**directory));
        if (!*directory)
            return SM2_IC_ERR_MEMORY;
    }
    return SM2_IC_SUCCESS;
}

void sm2_rev_multi_proof_cleanup(sm2_rev_multi_proof_t **proof)
{
    if (!proof || !*proof)
        return;

    multiproof_reset(*proof);
    free(*proof);
    *proof = NULL;
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

sm2_ic_error_t multiproof_reserve_unique_hashes(sm2_rev_multi_proof_t *proof,
    size_t *capacity, size_t required, size_t hard_limit)
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

sm2_ic_error_t multiproof_find_or_add_hash(sm2_rev_multi_proof_t *proof,
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

sm2_ic_error_t multiproof_expand_member(const sm2_rev_multi_proof_t *proof,
    const sm2_rev_multi_item_t *item, sm2_rev_member_proof_t *member)
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
    memcpy(member->key, item->key, SM2_REV_MERKLE_HASH_LEN);
    member->sibling_count = item->sibling_count;

    for (size_t i = 0; i < item->sibling_count; i++)
    {
        uint16_t ref = item->sibling_ref[i];
        if ((size_t)ref >= proof->unique_hash_count)
            return SM2_IC_ERR_VERIFY;

        member->sibling_depths[i] = item->sibling_depths[i];
        memcpy(member->sibling_hashes[i], proof->unique_hashes[ref],
            SM2_REV_MERKLE_HASH_LEN);
        member->sibling_on_left[i] = item->sibling_on_left[i] ? 1U : 0U;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_multi_proof_build(const sm2_rev_tree_t *tree,
    const uint64_t *serial_numbers, size_t serial_count,
    sm2_rev_multi_proof_t **proof)
{
    if (!tree || !proof || !serial_numbers || serial_count == 0)
        return SM2_IC_ERR_PARAM;
    if (sm2_rev_tree_leaf_count(tree) == 0)
        return SM2_IC_ERR_PARAM;
    if (serial_count > SM2_REV_MERKLE_MULTI_MAX_QUERIES)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = multiproof_ensure(proof);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    sm2_rev_multi_proof_t *state = *proof;
    multiproof_reset(state);

    if (serial_count > SIZE_MAX / sizeof(sm2_rev_multi_item_t))
        return SM2_IC_ERR_MEMORY;

    state->items = (sm2_rev_multi_item_t *)calloc(
        serial_count, sizeof(sm2_rev_multi_item_t));
    if (!state->items)
        return SM2_IC_ERR_MEMORY;

    size_t hash_capacity = 0;
    if (SM2_REV_MERKLE_MAX_DEPTH > (SIZE_MAX / serial_count))
    {
        multiproof_reset(state);
        return SM2_IC_ERR_MEMORY;
    }
    size_t hard_limit = serial_count * SM2_REV_MERKLE_MAX_DEPTH;
    if (hard_limit == 0)
    {
        multiproof_reset(state);
        return SM2_IC_ERR_MEMORY;
    }
    if (hard_limit > ((size_t)UINT16_MAX + 1U))
        hard_limit = (size_t)UINT16_MAX + 1U;

    size_t initial_capacity = multiproof_next_pow2(serial_count);
    if (initial_capacity > hard_limit)
        initial_capacity = hard_limit;

    ret = multiproof_reserve_unique_hashes(
        state, &hash_capacity, initial_capacity, hard_limit);
    if (ret != SM2_IC_SUCCESS)
    {
        multiproof_reset(state);
        return ret;
    }

    state->query_count = serial_count;
    state->unique_hash_count = 0;

    for (size_t i = 0; i < serial_count; i++)
    {
        sm2_rev_member_proof_t member;
        ret = sm2_rev_tree_prove_member(tree, serial_numbers[i], &member);
        if (ret != SM2_IC_SUCCESS)
        {
            multiproof_reset(state);
            return ret;
        }

        sm2_rev_multi_item_t *item = &state->items[i];
        item->serial_number = member.serial_number;
        memcpy(item->key, member.key, SM2_REV_MERKLE_HASH_LEN);
        item->sibling_count = member.sibling_count;

        for (size_t j = 0; j < member.sibling_count; j++)
        {
            uint16_t ref = 0;
            item->sibling_depths[j] = member.sibling_depths[j];
            ret = multiproof_find_or_add_hash(state, member.sibling_hashes[j],
                &hash_capacity, hard_limit, &ref);
            if (ret != SM2_IC_SUCCESS)
            {
                multiproof_reset(state);
                return ret;
            }
            item->sibling_ref[j] = ref;
            item->sibling_on_left[j] = member.sibling_on_left[j] ? 1U : 0U;
        }
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_multi_proof_verify(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_multi_proof_t *proof)
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
        sm2_rev_member_proof_t member;
        sm2_ic_error_t ret
            = multiproof_expand_member(proof, &proof->items[i], &member);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = sm2_rev_tree_verify_member(root_hash, &member);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_multi_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_multi_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx)
{
    sm2_ic_error_t ret
        = sm2_rev_root_verify(root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    return sm2_rev_multi_proof_verify(root_record->root_hash, proof);
}

sm2_ic_error_t sm2_rev_multi_proof_encode(
    const sm2_rev_multi_proof_t *proof, uint8_t *output, size_t *output_len)
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
        const sm2_rev_multi_item_t *item = &proof->items[i];
        if (item->sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_PARAM;

        ret = cbor_put_type_value(4, 6, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_type_value(
            0, item->serial_number, output, *output_len, &off);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = cbor_put_bytes(
            item->key, SM2_REV_MERKLE_HASH_LEN, output, *output_len, &off);
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
            ret = cbor_put_type_value(
                0, item->sibling_depths[j], output, *output_len, &off);
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }

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

sm2_ic_error_t sm2_rev_multi_proof_decode(
    sm2_rev_multi_proof_t **proof, const uint8_t *input, size_t input_len)
{
    if (!proof || !input)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = multiproof_ensure(proof);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    sm2_rev_multi_proof_t *state = *proof;
    multiproof_reset(state);

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
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

    state->unique_hashes = calloc(hash_count, sizeof(*state->unique_hashes));
    if (!state->unique_hashes)
    {
        multiproof_reset(state);
        return SM2_IC_ERR_MEMORY;
    }
    state->unique_hash_count = hash_count;

    for (size_t i = 0; i < hash_count; i++)
    {
        size_t hash_len = 0;
        ret = cbor_get_bytes(input, input_len, &off, state->unique_hashes[i],
            SM2_REV_MERKLE_HASH_LEN, &hash_len);
        if (ret != SM2_IC_SUCCESS || hash_len != SM2_REV_MERKLE_HASH_LEN)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }
    }

    uint64_t item_count64 = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &item_count64);
    if (ret != SM2_IC_SUCCESS || major != 4 || item_count64 == 0
        || item_count64 > SM2_REV_MERKLE_MULTI_MAX_QUERIES)
    {
        multiproof_reset(state);
        return SM2_IC_ERR_CBOR;
    }

    size_t item_count = (size_t)item_count64;
    if (item_count > SIZE_MAX / sizeof(sm2_rev_multi_item_t))
    {
        multiproof_reset(state);
        return SM2_IC_ERR_CBOR;
    }

    state->items = (sm2_rev_multi_item_t *)calloc(
        item_count, sizeof(sm2_rev_multi_item_t));
    if (!state->items)
    {
        multiproof_reset(state);
        return SM2_IC_ERR_MEMORY;
    }
    state->query_count = item_count;

    for (size_t i = 0; i < item_count; i++)
    {
        uint64_t item_arr_len = 0;
        ret = cbor_get_type_value(
            input, input_len, &off, &major, &item_arr_len);
        if (ret != SM2_IC_SUCCESS || major != 4 || item_arr_len != 6)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t serial = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &serial);
        if (ret != SM2_IC_SUCCESS || major != 0)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }

        uint8_t key[SM2_REV_MERKLE_HASH_LEN];
        size_t key_len = 0;
        ret = cbor_get_bytes(
            input, input_len, &off, key, sizeof(key), &key_len);
        if (ret != SM2_IC_SUCCESS || key_len != SM2_REV_MERKLE_HASH_LEN)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }

        uint64_t sibling_count = 0;
        ret = cbor_get_type_value(
            input, input_len, &off, &major, &sibling_count);
        if (ret != SM2_IC_SUCCESS || major != 0
            || sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }

        sm2_rev_multi_item_t *item = &state->items[i];
        item->serial_number = serial;
        memcpy(item->key, key, SM2_REV_MERKLE_HASH_LEN);
        item->sibling_count = (size_t)sibling_count;

        uint64_t depth_arr_len = 0;
        ret = cbor_get_type_value(
            input, input_len, &off, &major, &depth_arr_len);
        if (ret != SM2_IC_SUCCESS || major != 4
            || depth_arr_len != sibling_count)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }

        for (size_t j = 0; j < item->sibling_count; j++)
        {
            uint64_t depth = 0;
            ret = cbor_get_type_value(input, input_len, &off, &major, &depth);
            if (ret != SM2_IC_SUCCESS || major != 0
                || depth >= SM2_REV_MERKLE_MAX_DEPTH)
            {
                multiproof_reset(state);
                return SM2_IC_ERR_CBOR;
            }
            item->sibling_depths[j] = (uint16_t)depth;
        }

        uint64_t ref_arr_len = 0;
        ret = cbor_get_type_value(input, input_len, &off, &major, &ref_arr_len);
        if (ret != SM2_IC_SUCCESS || major != 4 || ref_arr_len != sibling_count)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }

        for (size_t j = 0; j < item->sibling_count; j++)
        {
            uint64_t ref64 = 0;
            ret = cbor_get_type_value(input, input_len, &off, &major, &ref64);
            if (ret != SM2_IC_SUCCESS || major != 0 || ref64 > UINT16_MAX
                || ref64 >= hash_count)
            {
                multiproof_reset(state);
                return SM2_IC_ERR_CBOR;
            }
            item->sibling_ref[j] = (uint16_t)ref64;
        }

        size_t path_len = 0;
        ret = cbor_get_bytes(input, input_len, &off, item->sibling_on_left,
            SM2_REV_MERKLE_MAX_DEPTH, &path_len);
        if (ret != SM2_IC_SUCCESS || path_len != item->sibling_count)
        {
            multiproof_reset(state);
            return SM2_IC_ERR_CBOR;
        }
    }

    if (off != input_len)
    {
        multiproof_reset(state);
        return SM2_IC_ERR_CBOR;
    }

    return SM2_IC_SUCCESS;
}

size_t sm2_rev_multi_proof_query_count(const sm2_rev_multi_proof_t *proof)
{
    return proof ? proof->query_count : 0;
}

size_t sm2_rev_multi_proof_unique_hash_count(const sm2_rev_multi_proof_t *proof)
{
    return proof ? proof->unique_hash_count : 0;
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

sm2_ic_error_t sm2_rev_epoch_dir_encode(
    const sm2_rev_epoch_dir_t *directory, uint8_t *output, size_t *output_len)
{
    if (!directory || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (directory->directory_signature_len == 0
        || directory->directory_signature_len
            > sizeof(directory->directory_signature))
    {
        return SM2_IC_ERR_PARAM;
    }

    uint8_t root_buf[512];
    size_t root_len = sizeof(root_buf);
    sm2_ic_error_t ret
        = sm2_rev_root_encode(&directory->root_record, root_buf, &root_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t off = 0;
    ret = cbor_put_type_value(4, 6, output, *output_len, &off);
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

sm2_ic_error_t sm2_rev_epoch_dir_decode(
    sm2_rev_epoch_dir_t **directory, const uint8_t *input, size_t input_len)
{
    if (!directory || !input)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = epoch_dir_decode_ensure(directory);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    sm2_rev_epoch_dir_t *state = *directory;
    epoch_dir_decode_reset(state);

    size_t off = 0;
    uint8_t major = 0;
    uint64_t arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4 || arr_len != 6)
        return SM2_IC_ERR_CBOR;

    ret = cbor_get_type_value(input, input_len, &off, &major, &state->epoch_id);
    if (ret != SM2_IC_SUCCESS || major != 0)
        return SM2_IC_ERR_CBOR;

    uint8_t *root_buf = NULL;
    size_t root_len = 0;
    ret = cbor_get_bytes_alloc(input, input_len, &off, &root_buf, &root_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_rev_root_decode(&state->root_record, root_buf, root_len);
    free(root_buf);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint64_t tree_levels = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &tree_levels);
    if (ret != SM2_IC_SUCCESS || major != 0
        || tree_levels != SM2_REV_MERKLE_MAX_DEPTH + 1U)
    {
        return SM2_IC_ERR_CBOR;
    }
    state->tree_level_count = (size_t)tree_levels;

    ret = cbor_get_type_value(
        input, input_len, &off, &major, &state->patch_version);
    if (ret != SM2_IC_SUCCESS || major != 0)
        goto decode_fail;

    uint64_t patch_arr_len = 0;
    ret = cbor_get_type_value(input, input_len, &off, &major, &patch_arr_len);
    if (ret != SM2_IC_SUCCESS || major != 4)
        goto decode_fail;
    if (patch_arr_len > SIZE_MAX / sizeof(sm2_rev_delta_item_t))
    {
        ret = SM2_IC_ERR_CBOR;
        goto decode_fail;
    }

    state->patch_item_count = (size_t)patch_arr_len;
    if (state->patch_item_count > 0)
    {
        state->patch_items = (sm2_rev_delta_item_t *)calloc(
            state->patch_item_count, sizeof(sm2_rev_delta_item_t));
        if (!state->patch_items)
        {
            ret = SM2_IC_ERR_MEMORY;
            goto decode_fail;
        }

        for (size_t i = 0; i < state->patch_item_count; i++)
        {
            uint64_t pair_len = 0;
            ret = cbor_get_type_value(
                input, input_len, &off, &major, &pair_len);
            if (ret != SM2_IC_SUCCESS || major != 4 || pair_len != 2)
                goto decode_fail;

            ret = cbor_get_type_value(input, input_len, &off, &major,
                &state->patch_items[i].serial_number);
            if (ret != SM2_IC_SUCCESS || major != 0)
                goto decode_fail;

            ret = cbor_get_bool(
                input, input_len, &off, &state->patch_items[i].revoked);
            if (ret != SM2_IC_SUCCESS)
                goto decode_fail;
        }
    }

    size_t sig_len = 0;
    ret = cbor_get_bytes(input, input_len, &off, state->directory_signature,
        sizeof(state->directory_signature), &sig_len);
    if (ret != SM2_IC_SUCCESS || sig_len == 0)
        goto decode_fail;
    state->directory_signature_len = sig_len;

    if (off != input_len)
    {
        ret = SM2_IC_ERR_CBOR;
        goto decode_fail;
    }

    return SM2_IC_SUCCESS;

decode_fail:
    epoch_dir_decode_reset(state);
    return ret;
}
