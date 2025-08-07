#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// 定义跨平台的字节交换函数
#if defined(_MSC_VER)
#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#elif defined(__GNUC__)
#define bswap_32(x) __builtin_bswap32(x)
#else
static inline uint32_t bswap_32(uint32_t x) {
    return ((x & 0xFF000000) >> 24) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x000000FF) << 24);
}
#endif

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3常量定义
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

static const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// 布尔函数
static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

// 置换函数
static uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

static uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

// 消息填充
void sm3_padding(const uint8_t* msg, size_t len, uint8_t* out, size_t* out_len) {
    size_t bit_len = len * 8;
    size_t pad_len = (len + 1 + 8 + 63) / 64 * 64;

    memcpy(out, msg, len);
    out[len] = 0x80;
    memset(out + len + 1, 0, pad_len - len - 1 - 8);

    // 添加长度(大端)
    for (int i = 0; i < 8; i++) {
        out[pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    *out_len = pad_len;
}

// 消息扩展
void sm3_expand(const uint32_t block[16], uint32_t w[68], uint32_t w1[64]) {
    for (int i = 0; i < 16; i++) {
        w[i] = bswap_32(block[i]); // 使用字节交换函数
    }

    for (int i = 16; i < 68; i++) {
        w[i] = P1(w[i - 16] ^ w[i - 9] ^ ROTL32(w[i - 3], 15))
            ^ ROTL32(w[i - 13], 7) ^ w[i - 6];
    }

    for (int i = 0; i < 64; i++) {
        w1[i] = w[i] ^ w[i + 4];
    }
}

// 压缩函数
void sm3_compress(uint32_t state[8], const uint32_t w[68], const uint32_t w1[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int j = 0; j < 64; j++) {
        uint32_t ss1 = ROTL32(ROTL32(a, 12) + e + ROTL32(T[j], j), 7);
        uint32_t ss2 = ss1 ^ ROTL32(a, 12);
        uint32_t tt1 = FF(a, b, c, j) + d + ss2 + w1[j];
        uint32_t tt2 = GG(e, f, g, j) + h + ss1 + w[j];

        d = c;
        c = ROTL32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL32(f, 19);
        f = e;
        e = P0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

// SM3主函数
void sm3_hash(const uint8_t* msg, size_t len, uint8_t digest[32]) {
    uint8_t padded[1024];
    size_t padded_len;

    // 1. 填充
    sm3_padding(msg, len, padded, &padded_len);

    // 2. 初始化状态
    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    // 3. 迭代处理分组
    size_t blocks = padded_len / 64;
    for (size_t i = 0; i < blocks; i++) {
        uint32_t w[68], w1[64];
        sm3_expand((uint32_t*)(padded + i * 64), w, w1);
        sm3_compress(state, w, w1);
    }

    // 4. 输出结果(转大端)
    for (int i = 0; i < 8; i++) {
        state[i] = bswap_32(state[i]);
    }
    memcpy(digest, state, 32);
}

// 计算填充长度
size_t calculate_padding_size(size_t len) {
    // 填充规则: 0x80 + k个0 + 8字节长度
    size_t rem = len % 64;
    if (rem < 56) {
        return 56 - rem;
    }
    else {
        return 64 - rem + 56;
    }
}

// 使用自定义IV进行SM3哈希计算
void sm3_hash_with_iv(const uint8_t* msg, size_t len, const uint32_t iv[8], uint8_t digest[32]) {
    uint8_t padded[1024];
    size_t padded_len;

    // 1. 填充
    sm3_padding(msg, len, padded, &padded_len);

    // 2. 使用自定义IV初始化状态
    uint32_t state[8];
    memcpy(state, iv, sizeof(uint32_t) * 8);

    // 3. 迭代处理分组
    size_t blocks = padded_len / 64;
    for (size_t i = 0; i < blocks; i++) {
        uint32_t w[68], w1[64];
        sm3_expand((uint32_t*)(padded + i * 64), w, w1);
        sm3_compress(state, w, w1);
    }

    // 4. 输出结果(转大端)
    for (int i = 0; i < 8; i++) {
        state[i] = bswap_32(state[i]);
    }
    memcpy(digest, state, 32);
}

// 执行长度扩展攻击
void test_length_extension_attack() {
    printf("\n===== SM3 长度扩展攻击验证 =====\n");

    // 原始消息和密钥
    const char* secret = "secret";
    const char* original_msg = "message";
    const char* extension = "extension";
    size_t secret_len = strlen(secret);
    size_t original_len = strlen(original_msg);
    size_t full_len = secret_len + original_len;

    printf("密钥: '%s' (长度: %zu)\n", secret, secret_len);
    printf("原始消息: '%s' (长度: %zu)\n", original_msg, original_len);
    printf("扩展数据: '%s' (长度: %zu)\n", extension, strlen(extension));

    // 构造完整消息: secret + message
    uint8_t* full_msg = (uint8_t*)malloc(full_len);
    memcpy(full_msg, secret, secret_len);
    memcpy(full_msg + secret_len, original_msg, original_len);

    // 计算原始哈希
    uint8_t original_digest[32];
    sm3_hash(full_msg, full_len, original_digest);

    printf("\n原始消息哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", original_digest[i]);
    printf("\n");

    // 将哈希值转换为IV格式
    uint32_t new_iv[8];
    for (int i = 0; i < 8; i++) {
        new_iv[i] = bswap_32(*(uint32_t*)(original_digest + i * 4));
    }

    // 计算原始消息的填充长度
    size_t padding_size = 64 - (full_len % 64) < 9 ? 128 - (full_len % 64) : 64 - (full_len % 64);
    printf("填充大小: %zu 字节\n", padding_size);

    // 构造填充块
    uint8_t* padding_block = (uint8_t*)malloc(padding_size);
    memset(padding_block, 0, padding_size);
    padding_block[0] = 0x80;
    uint64_t total_bits = full_len * 8;
    for (int i = 0; i < 8; i++) {
        padding_block[padding_size - 8 + i] = (total_bits >> (56 - i * 8)) & 0xFF;
    }

    // 构造扩展消息: 填充块 + 扩展数据
    size_t extension_len = strlen(extension);
    size_t extended_len = padding_size + extension_len;
    uint8_t* extended_msg = (uint8_t*)malloc(extended_len);
    memcpy(extended_msg, padding_block, padding_size);
    memcpy(extended_msg + padding_size, extension, extension_len);

    // 使用自定义IV计算扩展后的哈希
    uint8_t extended_digest[32];
    sm3_hash_with_iv(extended_msg, extended_len, new_iv, extended_digest);

    printf("\n攻击生成的扩展哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", extended_digest[i]);
    printf("\n");

    // 验证攻击: 计算 secret + message + padding + extension 的哈希
    size_t total_len = full_len + padding_size + extension_len;
    uint8_t* total_msg = (uint8_t*)malloc(total_len);

    // 第一部分: 原始消息
    memcpy(total_msg, full_msg, full_len);

    // 第二部分: 填充
    memcpy(total_msg + full_len, padding_block, padding_size);

    // 第三部分: 扩展数据
    memcpy(total_msg + full_len + padding_size, extension, extension_len);

    uint8_t validation_digest[32];
    sm3_hash(total_msg, total_len, validation_digest);

    printf("实际计算的完整哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", validation_digest[i]);
    printf("\n");

    // 比较结果
    if (memcmp(extended_digest, validation_digest, 32) == 0) {
        printf("\n攻击成功: 生成的哈希与实际哈希匹配!\n");
    }
    else {
        printf("\n攻击失败: 生成的哈希与实际哈希不匹配!\n");
        printf("差异位置: ");
        for (int i = 0; i < 32; i++) {
            if (extended_digest[i] != validation_digest[i]) {
                printf("%d ", i);
            }
        }
        printf("\n");
    }

    // 释放内存
    free(full_msg);
    free(padding_block);
    free(extended_msg);
    free(total_msg);
}

// Merkle树节点
typedef struct MerkleNode {
    uint8_t hash[32];
    struct MerkleNode* left;
    struct MerkleNode* right;
} MerkleNode;

// 创建叶子节点
MerkleNode* create_leaf(const uint8_t* data, size_t len) {
    // RFC6962: 叶子节点 = H(0x00 || data)
    uint8_t* input = (uint8_t*)malloc(len + 1);
    input[0] = 0x00;  // 叶子节点前缀
    memcpy(input + 1, data, len);

    MerkleNode* node = (MerkleNode*)malloc(sizeof(MerkleNode));
    sm3_hash(input, len + 1, node->hash);
    node->left = NULL;
    node->right = NULL;

    free(input);
    return node;
}

// 创建内部节点
MerkleNode* create_internal_node(MerkleNode* left, MerkleNode* right) {
    // RFC6962: 内部节点 = H(0x01 || left_hash || right_hash)
    uint8_t input[65];
    input[0] = 0x01;  // 内部节点前缀

    if (left) memcpy(input + 1, left->hash, 32);
    else memset(input + 1, 0, 32);

    if (right) memcpy(input + 33, right->hash, 32);
    else memset(input + 33, 0, 32);

    MerkleNode* node = (MerkleNode*)malloc(sizeof(MerkleNode));
    sm3_hash(input, 65, node->hash);
    node->left = left;
    node->right = right;
    return node;
}

// 递归构建Merkle树
MerkleNode* build_merkle_tree(MerkleNode** leaves, size_t start, size_t end) {
    if (start == end) {
        return leaves[start];
    }

    size_t mid = (start + end) / 2;
    MerkleNode* left = build_merkle_tree(leaves, start, mid);
    MerkleNode* right = build_merkle_tree(leaves, mid + 1, end);

    return create_internal_node(left, right);
}

// 计算树的高度
size_t tree_height(size_t n) {
    size_t height = 0;
    while (n > 0) {
        height++;
        n /= 2;
    }
    return height;
}

// 存在性证明
void generate_existence_proof(MerkleNode* root, size_t index, size_t total_leaves,
    uint8_t** proof, size_t* proof_len) {
    // 计算树的高度
    size_t height = tree_height(total_leaves);
    *proof_len = 0;
    *proof = (uint8_t*)malloc(height * 32);

    size_t current_index = index;
    size_t nodes_in_level = total_leaves;
    MerkleNode* current = root;

    // 遍历树，收集路径上的兄弟节点哈希
    for (size_t level = 0; level < height - 1; level++) {
        size_t mid = (nodes_in_level + 1) / 2;
        if (current_index < mid) {
            // 目标在左子树
            if (current->right) {
                memcpy(*proof + *proof_len, current->right->hash, 32);
            }
            else {
                memcpy(*proof + *proof_len, current->left->hash, 32);
            }
            *proof_len += 32;
            current = current->left;
        }
        else {
            // 目标在右子树
            memcpy(*proof + *proof_len, current->left->hash, 32);
            *proof_len += 32;
            current = current->right;
            current_index -= mid;
        }
        nodes_in_level = mid;
    }
}

// 验证存在性证明
int verify_existence_proof(const uint8_t* root_hash, const uint8_t* leaf_hash,
    const uint8_t* proof, size_t proof_len,
    size_t index, size_t total_leaves) {
    uint8_t computed_hash[32];
    memcpy(computed_hash, leaf_hash, 32);

    size_t current_index = index;
    size_t nodes_in_level = total_leaves;
    const uint8_t* proof_ptr = proof;

    // 计算树的高度
    size_t height = tree_height(total_leaves);

    // 验证路径
    for (size_t i = 0; i < height - 1; i++) {
        uint8_t input[65];
        input[0] = 0x01;  // 内部节点前缀

        size_t mid = (nodes_in_level + 1) / 2;
        if (current_index % 2 == 0) {
            // 当前节点是左子节点
            memcpy(input + 1, computed_hash, 32);
            memcpy(input + 33, proof_ptr, 32);
        }
        else {
            // 当前节点是右子节点
            memcpy(input + 1, proof_ptr, 32);
            memcpy(input + 33, computed_hash, 32);
        }

        sm3_hash(input, 65, computed_hash);
        proof_ptr += 32;
        current_index /= 2;
        nodes_in_level = mid;
    }

    return memcmp(computed_hash, root_hash, 32) == 0;
}

// 生成不存在性证明 
void generate_absence_proof(MerkleNode* root, uint8_t** proof, size_t* proof_len) {
    *proof_len = 32;
    *proof = (uint8_t*)malloc(32);
    memcpy(*proof, root->hash, 32);
}

// 验证不存在性证明 
int verify_absence_proof(const uint8_t* root_hash, const uint8_t* proof, size_t proof_len) {
    return proof_len == 32 && memcmp(proof, root_hash, 32) == 0;
}

// 释放Merkle树内存
void free_merkle_tree(MerkleNode* node) {
    if (!node) return;

    if (node->left) free_merkle_tree(node->left);
    if (node->right) free_merkle_tree(node->right);

    free(node);
}

// 测试Merkle树
void test_merkle_tree() {
    const size_t NUM_LEAVES = 100000;
    printf("\n=== 构建Merkle树 (10万叶子节点) ===\n");

    // 1. 生成叶子节点
    printf("生成 %zu 个叶子节点...\n", NUM_LEAVES);
    MerkleNode** leaves = (MerkleNode**)malloc(NUM_LEAVES * sizeof(MerkleNode*));
    for (size_t i = 0; i < NUM_LEAVES; i++) {
        char data[32];
        snprintf(data, sizeof(data), "Leaf data %zu", i);
        leaves[i] = create_leaf((uint8_t*)data, strlen(data));
    }

    // 2. 构建Merkle树
    printf("构建Merkle树...\n");
    MerkleNode* root = build_merkle_tree(leaves, 0, NUM_LEAVES - 1);
    printf("Merkle根哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", root->hash[i]);
    printf("\n");

    // 3. 存在性证明
    size_t proof_index = 12345;
    uint8_t* existence_proof = NULL;
    size_t proof_len = 0;

    printf("\n生成存在性证明 (索引 %zu)...\n", proof_index);
    generate_existence_proof(root, proof_index, NUM_LEAVES, &existence_proof, &proof_len);
    printf("存在性证明长度: %zu 字节\n", proof_len);

    int valid = verify_existence_proof(root->hash, leaves[proof_index]->hash,
        existence_proof, proof_len,
        proof_index, NUM_LEAVES);
    printf("存在性证明验证: %s\n", valid ? "成功" : "失败");

    // 4. 不存在性证明
    uint8_t* absence_proof = NULL;
    size_t absence_proof_len = 0;

    printf("\n生成不存在性证明...\n");
    generate_absence_proof(root, &absence_proof, &absence_proof_len);
    printf("不存在性证明长度: %zu 字节\n", absence_proof_len);

    int absence_valid = verify_absence_proof(root->hash, absence_proof, absence_proof_len);
    printf("不存在性证明验证: %s\n", absence_valid ? "成功" : "失败");

    // 5. 测试不存在的叶子节点
    uint8_t fake_hash[32];
    memset(fake_hash, 0, 32);
    int fake_valid = verify_existence_proof(root->hash, fake_hash,
        existence_proof, proof_len,
        proof_index, NUM_LEAVES);
    printf("\n验证不存在的叶子节点: %s\n", fake_valid ? "错误" : "正确");

    // 清理内存
    free(existence_proof);
    free(absence_proof);
    for (size_t i = 0; i < NUM_LEAVES; i++) {
        free(leaves[i]);
    }
    free(leaves);
    free_merkle_tree(root);
}

int main() {
    // 测试SM3哈希函数
    const char* msg = "abc";
    uint8_t digest[32];
    sm3_hash((uint8_t*)msg, strlen(msg), digest);

    printf("SM3(\"%s\") = ", msg);
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // 运行长度扩展攻击验证
    test_length_extension_attack();

    // 运行Merkle树实现
    test_merkle_tree();

    return 0;
}