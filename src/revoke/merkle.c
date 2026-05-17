/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle.c
 * @brief Dynamic sparse Merkle accumulator for revocation state.
 */

#include "merkle_internal.h"

typedef enum
{
    SM2_REV_SPARSE_LEAF = 1,
    SM2_REV_SPARSE_BRANCH = 2
} sm2_rev_sparse_node_type_t;

typedef struct sm2_rev_sparse_node_st
{
    sm2_rev_sparse_node_type_t type;
    uint16_t depth;
    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    uint64_t serial_number;
    struct sm2_rev_sparse_node_st *left;
    struct sm2_rev_sparse_node_st *right;
    uint8_t hash[SM2_REV_MERKLE_HASH_LEN];
    bool hash_valid;
} sm2_rev_sparse_node_t;

#define SM2_REV_SPARSE_POOL_BLOCK_NODES 256U

typedef struct sm2_rev_sparse_pool_block_st
{
    struct sm2_rev_sparse_pool_block_st *next;
    sm2_rev_sparse_node_t nodes[SM2_REV_SPARSE_POOL_BLOCK_NODES];
} sm2_rev_sparse_pool_block_t;

static sm2_rev_tree_debug_stats_t g_sparse_debug_stats;

void merkle_tree_debug_stats_reset(void)
{
    memset(&g_sparse_debug_stats, 0, sizeof(g_sparse_debug_stats));
}

void merkle_tree_debug_stats_get(sm2_rev_tree_debug_stats_t *stats)
{
    if (!stats)
        return;
    *stats = g_sparse_debug_stats;
}

static uint8_t sparse_key_bit(
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN], size_t depth)
{
    return (uint8_t)((key[depth / 8U] >> (7U - (depth % 8U))) & 0x01U);
}

static bool sparse_key_equal(const uint8_t a[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t b[SM2_REV_MERKLE_HASH_LEN])
{
    return memcmp(a, b, SM2_REV_MERKLE_HASH_LEN) == 0;
}

static size_t sparse_first_diff_depth(const uint8_t a[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t b[SM2_REV_MERKLE_HASH_LEN], size_t start_depth)
{
    for (size_t d = start_depth; d < SM2_REV_MERKLE_MAX_DEPTH; d++)
    {
        if (sparse_key_bit(a, d) != sparse_key_bit(b, d))
            return d;
    }
    return SM2_REV_MERKLE_MAX_DEPTH;
}

static bool sparse_prefix_matches(const uint8_t a[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t b[SM2_REV_MERKLE_HASH_LEN], size_t start_depth,
    size_t end_depth)
{
    for (size_t d = start_depth; d < end_depth; d++)
    {
        if (sparse_key_bit(a, d) != sparse_key_bit(b, d))
            return false;
    }
    return true;
}

static void sparse_key_prefix(const uint8_t key[SM2_REV_MERKLE_HASH_LEN],
    size_t depth, uint8_t prefix[SM2_REV_MERKLE_HASH_LEN])
{
    memset(prefix, 0, SM2_REV_MERKLE_HASH_LEN);
    if (!key || depth == 0)
        return;

    size_t full_bytes = depth / 8U;
    size_t rem_bits = depth % 8U;
    if (full_bytes > 0)
        memcpy(prefix, key, full_bytes);
    if (rem_bits != 0 && full_bytes < SM2_REV_MERKLE_HASH_LEN)
    {
        uint8_t mask = (uint8_t)(0xFFU << (8U - rem_bits));
        prefix[full_bytes] = (uint8_t)(key[full_bytes] & mask);
    }
}

static sm2_ic_error_t sparse_pool_add_block(sm2_rev_tree_t *tree)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sparse_pool_block_t *block
        = (sm2_rev_sparse_pool_block_t *)calloc(1, sizeof(*block));
    if (!block)
        return SM2_IC_ERR_MEMORY;

    block->next = tree->node_pool_blocks;
    tree->node_pool_blocks = block;
    g_sparse_debug_stats.node_pool_block_alloc_count++;

    for (size_t i = 0; i < SM2_REV_SPARSE_POOL_BLOCK_NODES; i++)
    {
        block->nodes[i].left = tree->free_nodes;
        tree->free_nodes = &block->nodes[i];
    }
    return SM2_IC_SUCCESS;
}

static sm2_rev_sparse_node_t *sparse_node_alloc(sm2_rev_tree_t *tree)
{
    if (!tree)
        return NULL;
    if (!tree->free_nodes)
    {
        if (sparse_pool_add_block(tree) != SM2_IC_SUCCESS)
            return NULL;
    }

    sm2_rev_sparse_node_t *node = tree->free_nodes;
    tree->free_nodes = node->left;
    memset(node, 0, sizeof(*node));
    tree->node_pool_live_count++;
    if (tree->node_pool_live_count > tree->node_pool_peak_live_count)
        tree->node_pool_peak_live_count = tree->node_pool_live_count;
    g_sparse_debug_stats.node_alloc_count++;
    return node;
}

static void sparse_node_release(
    sm2_rev_tree_t *tree, sm2_rev_sparse_node_t *node)
{
    if (!tree || !node)
        return;
    memset(node, 0, sizeof(*node));
    node->left = tree->free_nodes;
    tree->free_nodes = node;
    if (tree->node_pool_live_count > 0)
        tree->node_pool_live_count--;
    g_sparse_debug_stats.node_free_count++;
}

static void sparse_pool_release_all(sm2_rev_tree_t *tree)
{
    if (!tree)
        return;
    sm2_rev_sparse_pool_block_t *block
        = (sm2_rev_sparse_pool_block_t *)tree->node_pool_blocks;
    while (block)
    {
        sm2_rev_sparse_pool_block_t *next = block->next;
        free(block);
        block = next;
    }
    tree->node_pool_blocks = NULL;
    tree->free_nodes = NULL;
    tree->node_pool_live_count = 0;
    tree->node_pool_peak_live_count = 0;
}

static sm2_rev_sparse_node_t *sparse_node_new_leaf(sm2_rev_tree_t *tree,
    uint64_t serial_number, const uint8_t key[SM2_REV_MERKLE_HASH_LEN])
{
    sm2_rev_sparse_node_t *node = sparse_node_alloc(tree);
    if (!node)
        return NULL;
    node->type = SM2_REV_SPARSE_LEAF;
    node->depth = SM2_REV_MERKLE_MAX_DEPTH;
    node->serial_number = serial_number;
    memcpy(node->key, key, SM2_REV_MERKLE_HASH_LEN);
    return node;
}

static sm2_rev_sparse_node_t *sparse_node_new_branch(sm2_rev_tree_t *tree,
    size_t depth, const uint8_t key[SM2_REV_MERKLE_HASH_LEN])
{
    sm2_rev_sparse_node_t *node = sparse_node_alloc(tree);
    if (!node)
        return NULL;
    node->type = SM2_REV_SPARSE_BRANCH;
    node->depth = (uint16_t)depth;
    memcpy(node->key, key, SM2_REV_MERKLE_HASH_LEN);
    return node;
}

static void sparse_node_free(sm2_rev_tree_t *tree, sm2_rev_sparse_node_t *node)
{
    if (!node)
        return;
    sparse_node_free(tree, node->left);
    sparse_node_free(tree, node->right);
    sparse_node_release(tree, node);
}

static sm2_rev_sparse_node_t *sparse_node_clone(
    sm2_rev_tree_t *dst_tree, const sm2_rev_sparse_node_t *node)
{
    if (!node)
        return NULL;

    sm2_rev_sparse_node_t *copy = sparse_node_alloc(dst_tree);
    if (!copy)
        return NULL;

    *copy = *node;
    copy->left = NULL;
    copy->right = NULL;

    copy->left = sparse_node_clone(dst_tree, node->left);
    if (node->left && !copy->left)
    {
        sparse_node_release(dst_tree, copy);
        return NULL;
    }

    copy->right = sparse_node_clone(dst_tree, node->right);
    if (node->right && !copy->right)
    {
        sparse_node_free(dst_tree, copy->left);
        sparse_node_release(dst_tree, copy);
        return NULL;
    }

    return copy;
}

static sm2_ic_error_t merkle_hash_empty_subtree(
    size_t depth, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    static const uint8_t tag[] = "SM2REV_COMPRESSED_EMPTY_V1";
    uint8_t buf[(sizeof(tag) - 1U) + 8U];
    if (!out_hash || depth > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_PARAM;

    memcpy(buf, tag, sizeof(tag) - 1U);
    merkle_u64_to_be((uint64_t)depth, buf + sizeof(tag) - 1U);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

static sm2_ic_error_t merkle_hash_skip(
    const uint8_t child_hash[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN], size_t from_depth,
    size_t to_depth, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    static const uint8_t tag[] = "SM2REV_COMPRESSED_SKIP_V1";
    uint8_t buf[(sizeof(tag) - 1U) + 8U + 8U + SM2_REV_MERKLE_HASH_LEN
        + SM2_REV_MERKLE_HASH_LEN];
    if (!child_hash || !key || !out_hash
        || from_depth > SM2_REV_MERKLE_MAX_DEPTH || to_depth > from_depth)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (from_depth == to_depth)
    {
        memcpy(out_hash, child_hash, SM2_REV_MERKLE_HASH_LEN);
        return SM2_IC_SUCCESS;
    }

    uint8_t prefix[SM2_REV_MERKLE_HASH_LEN];
    sparse_key_prefix(key, from_depth, prefix);

    size_t off = 0;
    memcpy(buf + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    merkle_u64_to_be((uint64_t)to_depth, buf + off);
    off += 8U;
    merkle_u64_to_be((uint64_t)from_depth, buf + off);
    off += 8U;
    memcpy(buf + off, prefix, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;
    memcpy(buf + off, child_hash, SM2_REV_MERKLE_HASH_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

static sm2_ic_error_t merkle_hash_branch_at_depth(size_t depth,
    const uint8_t left[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t right[SM2_REV_MERKLE_HASH_LEN],
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    static const uint8_t tag[] = "SM2REV_COMPRESSED_BRANCH_V1";
    uint8_t buf[(sizeof(tag) - 1U) + 8U + SM2_REV_MERKLE_HASH_LEN
        + SM2_REV_MERKLE_HASH_LEN];
    if (!left || !right || !out_hash || depth >= SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_PARAM;

    size_t off = 0;
    memcpy(buf + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    merkle_u64_to_be((uint64_t)depth, buf + off);
    off += 8U;
    memcpy(buf + off, left, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;
    memcpy(buf + off, right, SM2_REV_MERKLE_HASH_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

static sm2_ic_error_t sparse_fold_hash_up(uint8_t hash[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN], size_t from_depth,
    size_t to_depth)
{
    if (!hash || !key || from_depth > SM2_REV_MERKLE_MAX_DEPTH
        || to_depth > from_depth)
    {
        return SM2_IC_ERR_PARAM;
    }

    uint8_t next[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret
        = merkle_hash_skip(hash, key, from_depth, to_depth, next);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    memcpy(hash, next, SM2_REV_MERKLE_HASH_LEN);
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t sparse_cached_hash_at(const sm2_rev_sparse_node_t *node,
    size_t depth, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    if (!out_hash || depth > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_PARAM;

    if (!node)
        return merkle_hash_empty_subtree(depth, out_hash);

    if (!node->hash_valid || node->depth < depth)
        return SM2_IC_ERR_VERIFY;

    memcpy(out_hash, node->hash, SM2_REV_MERKLE_HASH_LEN);
    return sparse_fold_hash_up(out_hash, node->key, node->depth, depth);
}

static sm2_ic_error_t sparse_node_refresh_hash(sm2_rev_sparse_node_t *node)
{
    if (!node)
        return SM2_IC_SUCCESS;
    g_sparse_debug_stats.root_refresh_node_visit_count++;

    if (node->type == SM2_REV_SPARSE_LEAF)
    {
        sm2_ic_error_t ret
            = merkle_hash_leaf(node->serial_number, node->key, node->hash);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        node->hash_valid = true;
        return SM2_IC_SUCCESS;
    }

    if (node->depth >= SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_VERIFY;

    sm2_ic_error_t ret = sparse_node_refresh_hash(node->left);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = sparse_node_refresh_hash(node->right);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint8_t left_hash[SM2_REV_MERKLE_HASH_LEN];
    uint8_t right_hash[SM2_REV_MERKLE_HASH_LEN];
    ret = sparse_cached_hash_at(
        node->left, (size_t)node->depth + 1U, left_hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = sparse_cached_hash_at(
        node->right, (size_t)node->depth + 1U, right_hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = merkle_hash_branch_at_depth(
        node->depth, left_hash, right_hash, node->hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    node->hash_valid = true;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t sparse_tree_refresh_root(sm2_rev_tree_t *tree)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    g_sparse_debug_stats.root_refresh_count++;
    if (!tree->root)
        return merkle_hash_empty_subtree(0, tree->root_hash);

    sm2_ic_error_t ret = sparse_node_refresh_hash(tree->root);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return sparse_cached_hash_at(tree->root, 0, tree->root_hash);
}

static sm2_ic_error_t sparse_insert_node(sm2_rev_tree_t *tree,
    sm2_rev_sparse_node_t **slot, sm2_rev_sparse_node_t *leaf, size_t depth,
    bool *inserted)
{
    if (!tree || !slot || !leaf || !inserted)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sparse_node_t *cur = *slot;
    if (!cur)
    {
        *slot = leaf;
        *inserted = true;
        return SM2_IC_SUCCESS;
    }

    if (cur->type == SM2_REV_SPARSE_LEAF)
    {
        if (sparse_key_equal(cur->key, leaf->key))
        {
            cur->serial_number = leaf->serial_number;
            sparse_node_free(tree, leaf);
            *inserted = false;
            return SM2_IC_SUCCESS;
        }

        size_t diff = sparse_first_diff_depth(cur->key, leaf->key, depth);
        if (diff >= SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_VERIFY;

        sm2_rev_sparse_node_t *branch
            = sparse_node_new_branch(tree, diff, cur->key);
        if (!branch)
            return SM2_IC_ERR_MEMORY;
        if (sparse_key_bit(cur->key, diff) == 0)
        {
            branch->left = cur;
            branch->right = leaf;
        }
        else
        {
            branch->left = leaf;
            branch->right = cur;
        }
        *slot = branch;
        *inserted = true;
        return SM2_IC_SUCCESS;
    }

    if (!sparse_prefix_matches(cur->key, leaf->key, depth, cur->depth))
    {
        size_t diff = sparse_first_diff_depth(cur->key, leaf->key, depth);
        if (diff >= cur->depth || diff >= SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_VERIFY;

        sm2_rev_sparse_node_t *branch
            = sparse_node_new_branch(tree, diff, cur->key);
        if (!branch)
            return SM2_IC_ERR_MEMORY;
        if (sparse_key_bit(cur->key, diff) == 0)
        {
            branch->left = cur;
            branch->right = leaf;
        }
        else
        {
            branch->left = leaf;
            branch->right = cur;
        }
        *slot = branch;
        *inserted = true;
        return SM2_IC_SUCCESS;
    }

    uint8_t bit = sparse_key_bit(leaf->key, cur->depth);
    return sparse_insert_node(tree, bit == 0 ? &cur->left : &cur->right, leaf,
        cur->depth + 1U, inserted);
}

static sm2_ic_error_t sparse_delete_node(sm2_rev_tree_t *tree,
    sm2_rev_sparse_node_t **slot, const uint8_t key[SM2_REV_MERKLE_HASH_LEN],
    size_t depth, bool *removed)
{
    if (!tree || !slot || !key || !removed)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sparse_node_t *cur = *slot;
    if (!cur)
        return SM2_IC_SUCCESS;

    if (cur->type == SM2_REV_SPARSE_LEAF)
    {
        if (!sparse_key_equal(cur->key, key))
            return SM2_IC_SUCCESS;
        sparse_node_free(tree, cur);
        *slot = NULL;
        *removed = true;
        return SM2_IC_SUCCESS;
    }

    if (!sparse_prefix_matches(cur->key, key, depth, cur->depth))
        return SM2_IC_SUCCESS;

    uint8_t bit = sparse_key_bit(key, cur->depth);
    sm2_ic_error_t ret = sparse_delete_node(tree,
        bit == 0 ? &cur->left : &cur->right, key, cur->depth + 1U, removed);
    if (ret != SM2_IC_SUCCESS || !*removed)
        return ret;

    if (cur->left && cur->right)
        return SM2_IC_SUCCESS;

    sm2_rev_sparse_node_t *child = cur->left ? cur->left : cur->right;
    cur->left = NULL;
    cur->right = NULL;
    sparse_node_release(tree, cur);
    *slot = child;
    return SM2_IC_SUCCESS;
}

static bool sparse_find_node(const sm2_rev_sparse_node_t *node,
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN], size_t depth,
    uint64_t *serial_number)
{
    if (!node || !key)
        return false;
    if (node->type == SM2_REV_SPARSE_LEAF)
    {
        if (!sparse_key_equal(node->key, key))
            return false;
        if (serial_number)
            *serial_number = node->serial_number;
        return true;
    }
    if (!sparse_prefix_matches(node->key, key, depth, node->depth))
        return false;
    uint8_t bit = sparse_key_bit(key, node->depth);
    return sparse_find_node(bit == 0 ? node->left : node->right, key,
        node->depth + 1U, serial_number);
}

static sm2_ic_error_t sparse_store_sibling(size_t depth,
    const uint8_t sibling_hash[SM2_REV_MERKLE_HASH_LEN], uint8_t sibling_left,
    uint16_t sibling_depths[SM2_REV_MERKLE_MAX_DEPTH],
    uint8_t sibling_hashes[SM2_REV_MERKLE_MAX_DEPTH][SM2_REV_MERKLE_HASH_LEN],
    uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH], size_t *sibling_count)
{
    if (!sibling_hash || !sibling_depths || !sibling_hashes || !sibling_on_left
        || !sibling_count || depth >= SM2_REV_MERKLE_MAX_DEPTH)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (*sibling_count >= SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_VERIFY;

    size_t idx = *sibling_count;
    sibling_depths[idx] = (uint16_t)depth;
    memcpy(sibling_hashes[idx], sibling_hash, SM2_REV_MERKLE_HASH_LEN);
    sibling_on_left[idx] = sibling_left ? 1U : 0U;
    *sibling_count = idx + 1U;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t sparse_collect_member_siblings(
    const sm2_rev_sparse_node_t *root,
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN],
    uint16_t sibling_depths[SM2_REV_MERKLE_MAX_DEPTH],
    uint8_t sibling_hashes[SM2_REV_MERKLE_MAX_DEPTH][SM2_REV_MERKLE_HASH_LEN],
    uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH], size_t *sibling_count)
{
    if (!key || !sibling_depths || !sibling_hashes || !sibling_on_left
        || !sibling_count)
        return SM2_IC_ERR_PARAM;

    const sm2_rev_sparse_node_t *cur = root;
    size_t path_depth = 0;
    size_t count = 0;
    while (cur)
    {
        if (cur->type == SM2_REV_SPARSE_LEAF)
        {
            *sibling_count = count;
            return sparse_key_equal(cur->key, key) ? SM2_IC_SUCCESS
                                                   : SM2_IC_ERR_VERIFY;
        }

        if (cur->depth >= SM2_REV_MERKLE_MAX_DEPTH
            || !sparse_prefix_matches(cur->key, key, path_depth, cur->depth))
        {
            return SM2_IC_ERR_VERIFY;
        }

        uint8_t bit = sparse_key_bit(key, cur->depth);
        const sm2_rev_sparse_node_t *sibling_node
            = bit == 0 ? cur->right : cur->left;
        const sm2_rev_sparse_node_t *next_node
            = bit == 0 ? cur->left : cur->right;
        uint8_t sibling_hash[SM2_REV_MERKLE_HASH_LEN];
        sm2_ic_error_t ret = sparse_cached_hash_at(
            sibling_node, (size_t)cur->depth + 1U, sibling_hash);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        ret = sparse_store_sibling(cur->depth, sibling_hash, bit ? 1U : 0U,
            sibling_depths, sibling_hashes, sibling_on_left, &count);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        cur = next_node;
        path_depth = (size_t)sibling_depths[count - 1U] + 1U;
    }

    return SM2_IC_ERR_VERIFY;
}

static sm2_ic_error_t sparse_collect_absence_path(
    const sm2_rev_sparse_node_t *root,
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN], sm2_rev_absence_proof_t *proof)
{
    if (!key || !proof)
        return SM2_IC_ERR_PARAM;

    const sm2_rev_sparse_node_t *cur = root;
    size_t path_depth = 0;
    size_t count = 0;
    while (cur)
    {
        if (cur->type == SM2_REV_SPARSE_LEAF)
        {
            if (sparse_key_equal(cur->key, key))
                return SM2_IC_ERR_VERIFY;
            proof->terminal_depth = cur->depth;
            memcpy(proof->terminal_key, cur->key, SM2_REV_MERKLE_HASH_LEN);
            memcpy(proof->terminal_hash, cur->hash, SM2_REV_MERKLE_HASH_LEN);
            proof->sibling_count = count;
            return SM2_IC_SUCCESS;
        }

        if (cur->depth >= SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_VERIFY;
        if (!sparse_prefix_matches(cur->key, key, path_depth, cur->depth))
        {
            proof->terminal_depth = cur->depth;
            memcpy(proof->terminal_key, cur->key, SM2_REV_MERKLE_HASH_LEN);
            memcpy(proof->terminal_hash, cur->hash, SM2_REV_MERKLE_HASH_LEN);
            proof->sibling_count = count;
            return SM2_IC_SUCCESS;
        }

        uint8_t bit = sparse_key_bit(key, cur->depth);
        const sm2_rev_sparse_node_t *sibling_node
            = bit == 0 ? cur->right : cur->left;
        const sm2_rev_sparse_node_t *next_node
            = bit == 0 ? cur->left : cur->right;
        uint8_t sibling_hash[SM2_REV_MERKLE_HASH_LEN];
        sm2_ic_error_t ret = sparse_cached_hash_at(
            sibling_node, (size_t)cur->depth + 1U, sibling_hash);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        ret = sparse_store_sibling(cur->depth, sibling_hash, bit ? 1U : 0U,
            proof->sibling_depths, proof->sibling_hashes,
            proof->sibling_on_left, &count);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        cur = next_node;
        path_depth = (size_t)proof->sibling_depths[count - 1U] + 1U;
    }

    return SM2_IC_ERR_VERIFY;
}

static sm2_ic_error_t sparse_verify_compressed_path(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN],
    const uint8_t start_hash[SM2_REV_MERKLE_HASH_LEN], size_t start_depth,
    size_t sibling_count,
    const uint16_t sibling_depths[SM2_REV_MERKLE_MAX_DEPTH],
    const uint8_t sibling_hashes[SM2_REV_MERKLE_MAX_DEPTH]
                                [SM2_REV_MERKLE_HASH_LEN],
    const uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH])
{
    if (!root_hash || !key || !start_hash || !sibling_depths || !sibling_hashes
        || !sibling_on_left || start_depth > SM2_REV_MERKLE_MAX_DEPTH)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (sibling_count > SM2_REV_MERKLE_MAX_DEPTH)
        return SM2_IC_ERR_VERIFY;

    for (size_t i = 0; i < sibling_count; i++)
    {
        if (sibling_depths[i] >= SM2_REV_MERKLE_MAX_DEPTH)
            return SM2_IC_ERR_VERIFY;
        if (i > 0 && sibling_depths[i] <= sibling_depths[i - 1U])
            return SM2_IC_ERR_VERIFY;
        uint8_t expected_on_left
            = sparse_key_bit(key, sibling_depths[i]) ? 1U : 0U;
        if ((sibling_on_left[i] ? 1U : 0U) != expected_on_left)
            return SM2_IC_ERR_VERIFY;
    }

    uint8_t cur[SM2_REV_MERKLE_HASH_LEN];
    uint8_t next[SM2_REV_MERKLE_HASH_LEN];
    memcpy(cur, start_hash, SM2_REV_MERKLE_HASH_LEN);
    size_t cur_depth = start_depth;

    size_t entry = sibling_count;
    while (entry > 0)
    {
        entry--;
        size_t depth = sibling_depths[entry];
        size_t child_depth = depth + 1U;
        if (cur_depth < child_depth)
            return SM2_IC_ERR_VERIFY;

        sm2_ic_error_t ret
            = merkle_hash_skip(cur, key, cur_depth, child_depth, next);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        memcpy(cur, next, SM2_REV_MERKLE_HASH_LEN);
        cur_depth = child_depth;

        if (sibling_on_left[entry])
            ret = merkle_hash_branch_at_depth(
                depth, sibling_hashes[entry], cur, next);
        else
            ret = merkle_hash_branch_at_depth(
                depth, cur, sibling_hashes[entry], next);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        memcpy(cur, next, SM2_REV_MERKLE_HASH_LEN);
        cur_depth = depth;
    }

    sm2_ic_error_t ret = merkle_hash_skip(cur, key, cur_depth, 0, next);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    memcpy(cur, next, SM2_REV_MERKLE_HASH_LEN);

    return memcmp(cur, root_hash, SM2_REV_MERKLE_HASH_LEN) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}

static void rev_tree_reset(sm2_rev_tree_t *tree)
{
    if (!tree)
        return;
    sparse_node_free(tree, tree->root);
    sparse_pool_release_all(tree);
    memset(tree, 0, sizeof(*tree));
}

int merkle_cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb)
        return -1;
    if (va > vb)
        return 1;
    return 0;
}

void merkle_u64_to_be(uint64_t v, uint8_t out[8])
{
    for (int i = 0; i < 8; i++)
        out[7 - i] = (uint8_t)((v >> (i * 8)) & 0xFFU);
}

sm2_ic_error_t merkle_serial_key(
    uint64_t serial_number, uint8_t out_key[SM2_REV_MERKLE_HASH_LEN])
{
    static const uint8_t tag[] = "SM2REV_SPARSE_KEY_V1";
    uint8_t buf[(sizeof(tag) - 1U) + 8U];
    if (!out_key || serial_number == 0)
        return SM2_IC_ERR_PARAM;
    memcpy(buf, tag, sizeof(tag) - 1U);
    merkle_u64_to_be(serial_number, buf + sizeof(tag) - 1U);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_key);
}

sm2_ic_error_t merkle_hash_leaf(uint64_t serial_number,
    const uint8_t key[SM2_REV_MERKLE_HASH_LEN],
    uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN])
{
    uint8_t buf[1U + SM2_REV_MERKLE_HASH_LEN + 8U];
    if (!key || !out_hash || serial_number == 0)
        return SM2_IC_ERR_PARAM;
    buf[0] = 0x10U;
    memcpy(buf + 1U, key, SM2_REV_MERKLE_HASH_LEN);
    merkle_u64_to_be(serial_number, buf + 1U + SM2_REV_MERKLE_HASH_LEN);
    return sm2_ic_sm3_hash(buf, sizeof(buf), out_hash);
}

sm2_ic_error_t sm2_rev_tree_build(sm2_rev_tree_t **tree,
    const uint64_t *revoked_serials, size_t revoked_count,
    uint64_t root_version)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    if (revoked_count > 0 && !revoked_serials)
        return SM2_IC_ERR_PARAM;

    if (!*tree)
    {
        *tree = (sm2_rev_tree_t *)calloc(1, sizeof(**tree));
        if (!*tree)
            return SM2_IC_ERR_MEMORY;
    }

    sm2_rev_tree_t *state = *tree;
    rev_tree_reset(state);
    state->root_version = root_version;

    for (size_t i = 0; i < revoked_count; i++)
    {
        uint8_t key[SM2_REV_MERKLE_HASH_LEN];
        sm2_ic_error_t ret = merkle_serial_key(revoked_serials[i], key);
        if (ret != SM2_IC_SUCCESS)
        {
            rev_tree_reset(state);
            return ret;
        }

        sm2_rev_sparse_node_t *leaf
            = sparse_node_new_leaf(state, revoked_serials[i], key);
        if (!leaf)
        {
            rev_tree_reset(state);
            return SM2_IC_ERR_MEMORY;
        }

        bool inserted = false;
        ret = sparse_insert_node(state, &state->root, leaf, 0, &inserted);
        if (ret != SM2_IC_SUCCESS)
        {
            sparse_node_free(state, leaf);
            rev_tree_reset(state);
            return ret;
        }
        if (inserted)
            state->leaf_count++;
    }

    return sparse_tree_refresh_root(state);
}

void sm2_rev_tree_cleanup(sm2_rev_tree_t **tree)
{
    if (!tree || !*tree)
        return;
    rev_tree_reset(*tree);
    free(*tree);
    *tree = NULL;
}

size_t sm2_rev_tree_leaf_count(const sm2_rev_tree_t *tree)
{
    return tree ? tree->leaf_count : 0;
}

uint64_t sm2_rev_tree_root_version(const sm2_rev_tree_t *tree)
{
    return tree ? tree->root_version : 0;
}

sm2_ic_error_t sm2_rev_tree_get_root_hash(
    const sm2_rev_tree_t *tree, uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN])
{
    if (!tree || !root_hash)
        return SM2_IC_ERR_PARAM;
    memcpy(root_hash, tree->root_hash, SM2_REV_MERKLE_HASH_LEN);
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t merkle_tree_update_serial_no_refresh(
    sm2_rev_tree_t *tree, uint64_t serial, bool revoked)
{
    if (!tree || serial == 0)
        return SM2_IC_ERR_PARAM;

    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = merkle_serial_key(serial, key);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (revoked)
    {
        sm2_rev_sparse_node_t *leaf = sparse_node_new_leaf(tree, serial, key);
        if (!leaf)
            return SM2_IC_ERR_MEMORY;
        bool inserted = false;
        ret = sparse_insert_node(tree, &tree->root, leaf, 0, &inserted);
        if (ret != SM2_IC_SUCCESS)
        {
            sparse_node_free(tree, leaf);
            return ret;
        }
        if (inserted)
            tree->leaf_count++;
    }
    else
    {
        bool removed = false;
        ret = sparse_delete_node(tree, &tree->root, key, 0, &removed);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        if (removed && tree->leaf_count > 0)
            tree->leaf_count--;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t merkle_tree_update_serial(
    sm2_rev_tree_t *tree, uint64_t serial, bool revoked)
{
    sm2_ic_error_t ret
        = merkle_tree_update_serial_no_refresh(tree, serial, revoked);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return sparse_tree_refresh_root(tree);
}

sm2_ic_error_t merkle_tree_apply_delta_items(
    sm2_rev_tree_t *tree, const sm2_rev_delta_item_t *items, size_t item_count)
{
    if (!tree)
        return SM2_IC_ERR_PARAM;
    if (item_count > 0 && !items)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < item_count; i++)
    {
        sm2_ic_error_t ret = merkle_tree_update_serial_no_refresh(
            tree, items[i].serial_number, items[i].revoked);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    return sparse_tree_refresh_root(tree);
}

void merkle_tree_set_root_version(sm2_rev_tree_t *tree, uint64_t version)
{
    if (tree)
        tree->root_version = version;
}

sm2_ic_error_t merkle_tree_clone(
    const sm2_rev_tree_t *src, sm2_rev_tree_t **dst)
{
    if (!src || !dst)
        return SM2_IC_ERR_PARAM;

    sm2_rev_tree_t *copy = (sm2_rev_tree_t *)calloc(1, sizeof(*copy));
    if (!copy)
        return SM2_IC_ERR_MEMORY;

    copy->root_version = src->root_version;
    copy->leaf_count = src->leaf_count;
    memcpy(copy->root_hash, src->root_hash, SM2_REV_MERKLE_HASH_LEN);
    copy->root = sparse_node_clone(copy, src->root);
    if (src->root && !copy->root)
    {
        sparse_pool_release_all(copy);
        free(copy);
        return SM2_IC_ERR_MEMORY;
    }

    sm2_rev_tree_cleanup(dst);
    *dst = copy;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_tree_prove_member(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_member_proof_t *proof)
{
    if (!tree || !proof || serial_number == 0)
        return SM2_IC_ERR_PARAM;

    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = merkle_serial_key(serial_number, key);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (!sparse_find_node(tree->root, key, 0, NULL))
        return SM2_IC_ERR_VERIFY;

    memset(proof, 0, sizeof(*proof));
    proof->serial_number = serial_number;
    memcpy(proof->key, key, SM2_REV_MERKLE_HASH_LEN);
    ret = sparse_collect_member_siblings(tree->root, key, proof->sibling_depths,
        proof->sibling_hashes, proof->sibling_on_left, &proof->sibling_count);
    if (ret != SM2_IC_SUCCESS)
        memset(proof, 0, sizeof(*proof));
    return ret;
}

sm2_ic_error_t sm2_rev_tree_verify_member(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_member_proof_t *proof)
{
    if (!root_hash || !proof || proof->serial_number == 0)
        return SM2_IC_ERR_PARAM;

    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = merkle_serial_key(proof->serial_number, key);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (memcmp(key, proof->key, SM2_REV_MERKLE_HASH_LEN) != 0)
        return SM2_IC_ERR_VERIFY;

    uint8_t leaf_hash[SM2_REV_MERKLE_HASH_LEN];
    ret = merkle_hash_leaf(proof->serial_number, proof->key, leaf_hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return sparse_verify_compressed_path(root_hash, proof->key, leaf_hash,
        SM2_REV_MERKLE_MAX_DEPTH, proof->sibling_count, proof->sibling_depths,
        proof->sibling_hashes, proof->sibling_on_left);
}

sm2_ic_error_t sm2_rev_tree_prove_absence(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_absence_proof_t *proof)
{
    if (!tree || !proof || serial_number == 0)
        return SM2_IC_ERR_PARAM;

    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = merkle_serial_key(serial_number, key);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (sparse_find_node(tree->root, key, 0, NULL))
        return SM2_IC_ERR_VERIFY;

    memset(proof, 0, sizeof(*proof));
    proof->target_serial = serial_number;
    memcpy(proof->target_key, key, SM2_REV_MERKLE_HASH_LEN);
    proof->tree_empty = tree->leaf_count == 0;
    if (proof->tree_empty)
        return SM2_IC_SUCCESS;

    ret = sparse_collect_absence_path(tree->root, key, proof);
    if (ret != SM2_IC_SUCCESS)
        memset(proof, 0, sizeof(*proof));
    return ret;
}

sm2_ic_error_t sm2_rev_tree_verify_absence(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_absence_proof_t *proof)
{
    if (!root_hash || !proof || proof->target_serial == 0)
        return SM2_IC_ERR_PARAM;

    uint8_t key[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = merkle_serial_key(proof->target_serial, key);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (memcmp(key, proof->target_key, SM2_REV_MERKLE_HASH_LEN) != 0)
        return SM2_IC_ERR_VERIFY;

    if (proof->tree_empty)
    {
        if (proof->sibling_count != 0)
            return SM2_IC_ERR_VERIFY;
        uint8_t empty_root[SM2_REV_MERKLE_HASH_LEN];
        ret = merkle_hash_empty_subtree(0, empty_root);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        return memcmp(root_hash, empty_root, SM2_REV_MERKLE_HASH_LEN) == 0
            ? SM2_IC_SUCCESS
            : SM2_IC_ERR_VERIFY;
    }

    if (proof->terminal_depth == 0
        || proof->terminal_depth > SM2_REV_MERKLE_MAX_DEPTH)
    {
        return SM2_IC_ERR_VERIFY;
    }

    size_t base_depth = 0;
    if (proof->sibling_count > 0)
        base_depth
            = (size_t)proof->sibling_depths[proof->sibling_count - 1U] + 1U;
    if (proof->terminal_depth <= base_depth)
        return SM2_IC_ERR_VERIFY;
    if (!sparse_prefix_matches(
            proof->terminal_key, proof->target_key, 0, base_depth))
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (sparse_prefix_matches(proof->terminal_key, proof->target_key,
            base_depth, proof->terminal_depth))
    {
        return SM2_IC_ERR_VERIFY;
    }

    return sparse_verify_compressed_path(root_hash, proof->terminal_key,
        proof->terminal_hash, proof->terminal_depth, proof->sibling_count,
        proof->sibling_depths, proof->sibling_hashes, proof->sibling_on_left);
}

sm2_ic_error_t merkle_serialize_root_for_auth(
    const sm2_rev_root_record_t *root_record, uint8_t *output,
    size_t output_cap, size_t *output_len)
{
    static const uint8_t tag[] = "SM2REV_COMPRESSED_ROOT_V1";
    if (!root_record || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (root_record->authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
        return SM2_IC_ERR_PARAM;

    size_t need = (sizeof(tag) - 1U) + 8U + root_record->authority_id_len + 8U
        + SM2_REV_MERKLE_HASH_LEN + 8U + 8U;
    if (output_cap < need)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    memcpy(output + off, tag, sizeof(tag) - 1U);
    off += sizeof(tag) - 1U;
    merkle_u64_to_be((uint64_t)root_record->authority_id_len, output + off);
    off += 8U;
    memcpy(
        output + off, root_record->authority_id, root_record->authority_id_len);
    off += root_record->authority_id_len;
    merkle_u64_to_be(root_record->root_version, output + off);
    off += 8U;
    memcpy(output + off, root_record->root_hash, SM2_REV_MERKLE_HASH_LEN);
    off += SM2_REV_MERKLE_HASH_LEN;
    merkle_u64_to_be(root_record->valid_from, output + off);
    off += 8U;
    merkle_u64_to_be(root_record->valid_until, output + off);
    off += 8U;
    *output_len = off;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_root_sign_with_authority(const sm2_rev_tree_t *tree,
    const uint8_t *authority_id, size_t authority_id_len, uint64_t valid_from,
    uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_root_record_t *root_record)
{
    if (!tree || !sign_fn || !root_record)
        return SM2_IC_ERR_PARAM;
    if (!authority_id || authority_id_len == 0
        || authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN
        || valid_until < valid_from)
    {
        return SM2_IC_ERR_PARAM;
    }

    memset(root_record, 0, sizeof(*root_record));
    if (authority_id_len > 0)
        memcpy(root_record->authority_id, authority_id, authority_id_len);
    root_record->authority_id_len = authority_id_len;
    root_record->root_version = tree->root_version;
    memcpy(root_record->root_hash, tree->root_hash, SM2_REV_MERKLE_HASH_LEN);
    root_record->valid_from = valid_from;
    root_record->valid_until = valid_until;

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = merkle_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    size_t sig_len = sizeof(root_record->signature);
    ret = sign_fn(
        sign_user_ctx, auth_buf, auth_len, root_record->signature, &sig_len);
    if (ret != SM2_IC_SUCCESS || sig_len == 0
        || sig_len > sizeof(root_record->signature))
    {
        return SM2_IC_ERR_VERIFY;
    }
    root_record->signature_len = sig_len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_root_verify(const sm2_rev_root_record_t *root_record,
    uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!root_record || !verify_fn)
        return SM2_IC_ERR_PARAM;
    if (root_record->signature_len == 0
        || root_record->signature_len > sizeof(root_record->signature)
        || root_record->valid_until < root_record->valid_from
        || now_ts < root_record->valid_from || now_ts > root_record->valid_until
        || root_record->authority_id_len == 0
        || root_record->authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint8_t auth_buf[256];
    size_t auth_len = 0;
    sm2_ic_error_t ret = merkle_serialize_root_for_auth(
        root_record, auth_buf, sizeof(auth_buf), &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = verify_fn(verify_user_ctx, auth_buf, auth_len, root_record->signature,
        root_record->signature_len);
    return ret == SM2_IC_SUCCESS ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_rev_member_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_member_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx)
{
    sm2_ic_error_t ret
        = sm2_rev_root_verify(root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return sm2_rev_tree_verify_member(root_record->root_hash, proof);
}

sm2_ic_error_t sm2_rev_absence_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_absence_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx)
{
    sm2_ic_error_t ret
        = sm2_rev_root_verify(root_record, now_ts, verify_fn, verify_user_ctx);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return sm2_rev_tree_verify_absence(root_record->root_hash, proof);
}
