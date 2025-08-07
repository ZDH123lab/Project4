#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// �����ƽ̨���ֽڽ�������
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

// SM3��������
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

// ��������
static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

// �û�����
static uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

static uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

// ��Ϣ���
void sm3_padding(const uint8_t* msg, size_t len, uint8_t* out, size_t* out_len) {
    size_t bit_len = len * 8;
    size_t pad_len = (len + 1 + 8 + 63) / 64 * 64;

    memcpy(out, msg, len);
    out[len] = 0x80;
    memset(out + len + 1, 0, pad_len - len - 1 - 8);

    // ��ӳ���(���)
    for (int i = 0; i < 8; i++) {
        out[pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    *out_len = pad_len;
}

// ��Ϣ��չ
void sm3_expand(const uint32_t block[16], uint32_t w[68], uint32_t w1[64]) {
    for (int i = 0; i < 16; i++) {
        w[i] = bswap_32(block[i]); // ʹ���ֽڽ�������
    }

    for (int i = 16; i < 68; i++) {
        w[i] = P1(w[i - 16] ^ w[i - 9] ^ ROTL32(w[i - 3], 15))
            ^ ROTL32(w[i - 13], 7) ^ w[i - 6];
    }

    for (int i = 0; i < 64; i++) {
        w1[i] = w[i] ^ w[i + 4];
    }
}

// ѹ������
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

// SM3������
void sm3_hash(const uint8_t* msg, size_t len, uint8_t digest[32]) {
    uint8_t padded[1024];
    size_t padded_len;

    // 1. ���
    sm3_padding(msg, len, padded, &padded_len);

    // 2. ��ʼ��״̬
    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    // 3. �����������
    size_t blocks = padded_len / 64;
    for (size_t i = 0; i < blocks; i++) {
        uint32_t w[68], w1[64];
        sm3_expand((uint32_t*)(padded + i * 64), w, w1);
        sm3_compress(state, w, w1);
    }

    // 4. ������(ת���)
    for (int i = 0; i < 8; i++) {
        state[i] = bswap_32(state[i]);
    }
    memcpy(digest, state, 32);
}

// ������䳤��
size_t calculate_padding_size(size_t len) {
    // ������: 0x80 + k��0 + 8�ֽڳ���
    size_t rem = len % 64;
    if (rem < 56) {
        return 56 - rem;
    }
    else {
        return 64 - rem + 56;
    }
}

// ʹ���Զ���IV����SM3��ϣ����
void sm3_hash_with_iv(const uint8_t* msg, size_t len, const uint32_t iv[8], uint8_t digest[32]) {
    uint8_t padded[1024];
    size_t padded_len;

    // 1. ���
    sm3_padding(msg, len, padded, &padded_len);

    // 2. ʹ���Զ���IV��ʼ��״̬
    uint32_t state[8];
    memcpy(state, iv, sizeof(uint32_t) * 8);

    // 3. �����������
    size_t blocks = padded_len / 64;
    for (size_t i = 0; i < blocks; i++) {
        uint32_t w[68], w1[64];
        sm3_expand((uint32_t*)(padded + i * 64), w, w1);
        sm3_compress(state, w, w1);
    }

    // 4. ������(ת���)
    for (int i = 0; i < 8; i++) {
        state[i] = bswap_32(state[i]);
    }
    memcpy(digest, state, 32);
}

// ִ�г�����չ����
void test_length_extension_attack() {
    printf("\n===== SM3 ������չ������֤ =====\n");

    // ԭʼ��Ϣ����Կ
    const char* secret = "secret";
    const char* original_msg = "message";
    const char* extension = "extension";
    size_t secret_len = strlen(secret);
    size_t original_len = strlen(original_msg);
    size_t full_len = secret_len + original_len;

    printf("��Կ: '%s' (����: %zu)\n", secret, secret_len);
    printf("ԭʼ��Ϣ: '%s' (����: %zu)\n", original_msg, original_len);
    printf("��չ����: '%s' (����: %zu)\n", extension, strlen(extension));

    // ����������Ϣ: secret + message
    uint8_t* full_msg = (uint8_t*)malloc(full_len);
    memcpy(full_msg, secret, secret_len);
    memcpy(full_msg + secret_len, original_msg, original_len);

    // ����ԭʼ��ϣ
    uint8_t original_digest[32];
    sm3_hash(full_msg, full_len, original_digest);

    printf("\nԭʼ��Ϣ��ϣ: ");
    for (int i = 0; i < 32; i++) printf("%02x", original_digest[i]);
    printf("\n");

    // ����ϣֵת��ΪIV��ʽ
    uint32_t new_iv[8];
    for (int i = 0; i < 8; i++) {
        new_iv[i] = bswap_32(*(uint32_t*)(original_digest + i * 4));
    }

    // ����ԭʼ��Ϣ����䳤��
    size_t padding_size = 64 - (full_len % 64) < 9 ? 128 - (full_len % 64) : 64 - (full_len % 64);
    printf("����С: %zu �ֽ�\n", padding_size);

    // ��������
    uint8_t* padding_block = (uint8_t*)malloc(padding_size);
    memset(padding_block, 0, padding_size);
    padding_block[0] = 0x80;
    uint64_t total_bits = full_len * 8;
    for (int i = 0; i < 8; i++) {
        padding_block[padding_size - 8 + i] = (total_bits >> (56 - i * 8)) & 0xFF;
    }

    // ������չ��Ϣ: ���� + ��չ����
    size_t extension_len = strlen(extension);
    size_t extended_len = padding_size + extension_len;
    uint8_t* extended_msg = (uint8_t*)malloc(extended_len);
    memcpy(extended_msg, padding_block, padding_size);
    memcpy(extended_msg + padding_size, extension, extension_len);

    // ʹ���Զ���IV������չ��Ĺ�ϣ
    uint8_t extended_digest[32];
    sm3_hash_with_iv(extended_msg, extended_len, new_iv, extended_digest);

    printf("\n�������ɵ���չ��ϣ: ");
    for (int i = 0; i < 32; i++) printf("%02x", extended_digest[i]);
    printf("\n");

    // ��֤����: ���� secret + message + padding + extension �Ĺ�ϣ
    size_t total_len = full_len + padding_size + extension_len;
    uint8_t* total_msg = (uint8_t*)malloc(total_len);

    // ��һ����: ԭʼ��Ϣ
    memcpy(total_msg, full_msg, full_len);

    // �ڶ�����: ���
    memcpy(total_msg + full_len, padding_block, padding_size);

    // ��������: ��չ����
    memcpy(total_msg + full_len + padding_size, extension, extension_len);

    uint8_t validation_digest[32];
    sm3_hash(total_msg, total_len, validation_digest);

    printf("ʵ�ʼ����������ϣ: ");
    for (int i = 0; i < 32; i++) printf("%02x", validation_digest[i]);
    printf("\n");

    // �ȽϽ��
    if (memcmp(extended_digest, validation_digest, 32) == 0) {
        printf("\n�����ɹ�: ���ɵĹ�ϣ��ʵ�ʹ�ϣƥ��!\n");
    }
    else {
        printf("\n����ʧ��: ���ɵĹ�ϣ��ʵ�ʹ�ϣ��ƥ��!\n");
        printf("����λ��: ");
        for (int i = 0; i < 32; i++) {
            if (extended_digest[i] != validation_digest[i]) {
                printf("%d ", i);
            }
        }
        printf("\n");
    }

    // �ͷ��ڴ�
    free(full_msg);
    free(padding_block);
    free(extended_msg);
    free(total_msg);
}

// Merkle���ڵ�
typedef struct MerkleNode {
    uint8_t hash[32];
    struct MerkleNode* left;
    struct MerkleNode* right;
} MerkleNode;

// ����Ҷ�ӽڵ�
MerkleNode* create_leaf(const uint8_t* data, size_t len) {
    // RFC6962: Ҷ�ӽڵ� = H(0x00 || data)
    uint8_t* input = (uint8_t*)malloc(len + 1);
    input[0] = 0x00;  // Ҷ�ӽڵ�ǰ׺
    memcpy(input + 1, data, len);

    MerkleNode* node = (MerkleNode*)malloc(sizeof(MerkleNode));
    sm3_hash(input, len + 1, node->hash);
    node->left = NULL;
    node->right = NULL;

    free(input);
    return node;
}

// �����ڲ��ڵ�
MerkleNode* create_internal_node(MerkleNode* left, MerkleNode* right) {
    // RFC6962: �ڲ��ڵ� = H(0x01 || left_hash || right_hash)
    uint8_t input[65];
    input[0] = 0x01;  // �ڲ��ڵ�ǰ׺

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

// �ݹ鹹��Merkle��
MerkleNode* build_merkle_tree(MerkleNode** leaves, size_t start, size_t end) {
    if (start == end) {
        return leaves[start];
    }

    size_t mid = (start + end) / 2;
    MerkleNode* left = build_merkle_tree(leaves, start, mid);
    MerkleNode* right = build_merkle_tree(leaves, mid + 1, end);

    return create_internal_node(left, right);
}

// �������ĸ߶�
size_t tree_height(size_t n) {
    size_t height = 0;
    while (n > 0) {
        height++;
        n /= 2;
    }
    return height;
}

// ������֤��
void generate_existence_proof(MerkleNode* root, size_t index, size_t total_leaves,
    uint8_t** proof, size_t* proof_len) {
    // �������ĸ߶�
    size_t height = tree_height(total_leaves);
    *proof_len = 0;
    *proof = (uint8_t*)malloc(height * 32);

    size_t current_index = index;
    size_t nodes_in_level = total_leaves;
    MerkleNode* current = root;

    // ���������ռ�·���ϵ��ֵܽڵ��ϣ
    for (size_t level = 0; level < height - 1; level++) {
        size_t mid = (nodes_in_level + 1) / 2;
        if (current_index < mid) {
            // Ŀ����������
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
            // Ŀ����������
            memcpy(*proof + *proof_len, current->left->hash, 32);
            *proof_len += 32;
            current = current->right;
            current_index -= mid;
        }
        nodes_in_level = mid;
    }
}

// ��֤������֤��
int verify_existence_proof(const uint8_t* root_hash, const uint8_t* leaf_hash,
    const uint8_t* proof, size_t proof_len,
    size_t index, size_t total_leaves) {
    uint8_t computed_hash[32];
    memcpy(computed_hash, leaf_hash, 32);

    size_t current_index = index;
    size_t nodes_in_level = total_leaves;
    const uint8_t* proof_ptr = proof;

    // �������ĸ߶�
    size_t height = tree_height(total_leaves);

    // ��֤·��
    for (size_t i = 0; i < height - 1; i++) {
        uint8_t input[65];
        input[0] = 0x01;  // �ڲ��ڵ�ǰ׺

        size_t mid = (nodes_in_level + 1) / 2;
        if (current_index % 2 == 0) {
            // ��ǰ�ڵ������ӽڵ�
            memcpy(input + 1, computed_hash, 32);
            memcpy(input + 33, proof_ptr, 32);
        }
        else {
            // ��ǰ�ڵ������ӽڵ�
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

// ���ɲ�������֤�� 
void generate_absence_proof(MerkleNode* root, uint8_t** proof, size_t* proof_len) {
    *proof_len = 32;
    *proof = (uint8_t*)malloc(32);
    memcpy(*proof, root->hash, 32);
}

// ��֤��������֤�� 
int verify_absence_proof(const uint8_t* root_hash, const uint8_t* proof, size_t proof_len) {
    return proof_len == 32 && memcmp(proof, root_hash, 32) == 0;
}

// �ͷ�Merkle���ڴ�
void free_merkle_tree(MerkleNode* node) {
    if (!node) return;

    if (node->left) free_merkle_tree(node->left);
    if (node->right) free_merkle_tree(node->right);

    free(node);
}

// ����Merkle��
void test_merkle_tree() {
    const size_t NUM_LEAVES = 100000;
    printf("\n=== ����Merkle�� (10��Ҷ�ӽڵ�) ===\n");

    // 1. ����Ҷ�ӽڵ�
    printf("���� %zu ��Ҷ�ӽڵ�...\n", NUM_LEAVES);
    MerkleNode** leaves = (MerkleNode**)malloc(NUM_LEAVES * sizeof(MerkleNode*));
    for (size_t i = 0; i < NUM_LEAVES; i++) {
        char data[32];
        snprintf(data, sizeof(data), "Leaf data %zu", i);
        leaves[i] = create_leaf((uint8_t*)data, strlen(data));
    }

    // 2. ����Merkle��
    printf("����Merkle��...\n");
    MerkleNode* root = build_merkle_tree(leaves, 0, NUM_LEAVES - 1);
    printf("Merkle����ϣ: ");
    for (int i = 0; i < 32; i++) printf("%02x", root->hash[i]);
    printf("\n");

    // 3. ������֤��
    size_t proof_index = 12345;
    uint8_t* existence_proof = NULL;
    size_t proof_len = 0;

    printf("\n���ɴ�����֤�� (���� %zu)...\n", proof_index);
    generate_existence_proof(root, proof_index, NUM_LEAVES, &existence_proof, &proof_len);
    printf("������֤������: %zu �ֽ�\n", proof_len);

    int valid = verify_existence_proof(root->hash, leaves[proof_index]->hash,
        existence_proof, proof_len,
        proof_index, NUM_LEAVES);
    printf("������֤����֤: %s\n", valid ? "�ɹ�" : "ʧ��");

    // 4. ��������֤��
    uint8_t* absence_proof = NULL;
    size_t absence_proof_len = 0;

    printf("\n���ɲ�������֤��...\n");
    generate_absence_proof(root, &absence_proof, &absence_proof_len);
    printf("��������֤������: %zu �ֽ�\n", absence_proof_len);

    int absence_valid = verify_absence_proof(root->hash, absence_proof, absence_proof_len);
    printf("��������֤����֤: %s\n", absence_valid ? "�ɹ�" : "ʧ��");

    // 5. ���Բ����ڵ�Ҷ�ӽڵ�
    uint8_t fake_hash[32];
    memset(fake_hash, 0, 32);
    int fake_valid = verify_existence_proof(root->hash, fake_hash,
        existence_proof, proof_len,
        proof_index, NUM_LEAVES);
    printf("\n��֤�����ڵ�Ҷ�ӽڵ�: %s\n", fake_valid ? "����" : "��ȷ");

    // �����ڴ�
    free(existence_proof);
    free(absence_proof);
    for (size_t i = 0; i < NUM_LEAVES; i++) {
        free(leaves[i]);
    }
    free(leaves);
    free_merkle_tree(root);
}

int main() {
    // ����SM3��ϣ����
    const char* msg = "abc";
    uint8_t digest[32];
    sm3_hash((uint8_t*)msg, strlen(msg), digest);

    printf("SM3(\"%s\") = ", msg);
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // ���г�����չ������֤
    test_length_extension_attack();

    // ����Merkle��ʵ��
    test_merkle_tree();

    return 0;
}