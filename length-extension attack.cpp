#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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
    // k = (56 - (len % 64) + 64) % 64
    // 因为len+1后需要满足 (len+1+k) % 64 = 56
    return (64 - (len % 64)) < 9 ? (128 - (len % 64)) : (64 - (len % 64));
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
void length_extension_attack() {
    printf("\n===== SM3 长度扩展攻击验证 =====\n");

    // 原始消息和密钥
    const char* secret = "secret";
    const char* original_msg = "message";
    const char* extension = "extension";
    size_t secret_len = strlen(secret);
    size_t original_len = strlen(original_msg);

    printf("密钥: '%s' (长度: %zu)\n", secret, secret_len);
    printf("原始消息: '%s' (长度: %zu)\n", original_msg, original_len);
    printf("扩展数据: '%s' (长度: %zu)\n", extension, strlen(extension));

    // 构造完整消息: secret + message
    size_t full_len = secret_len + original_len;
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

    // 计算填充长度
    size_t padding_size = calculate_padding_size(full_len);
    printf("\n填充大小: %zu 字节\n", padding_size);

    // 构造扩展消息: padding(secret + message) + extension
    size_t extended_len = padding_size + strlen(extension);
    uint8_t* extended_msg = (uint8_t*)malloc(extended_len);

    // 填充部分: 0x80 + 0s + length
    memset(extended_msg, 0, extended_len);
    extended_msg[0] = 0x80; // 填充起始标记

    // 写入原始消息的总比特长度 (大端序)
    uint64_t total_bits = full_len * 8;
    for (int i = 0; i < 8; i++) {
        extended_msg[padding_size - 8 + i] = (total_bits >> (56 - i * 8)) & 0xFF;
    }

    // 添加扩展部分
    memcpy(extended_msg + padding_size, extension, strlen(extension));

    // 使用自定义IV计算扩展后的哈希
    uint8_t extended_digest[32];
    sm3_hash_with_iv(extended_msg, extended_len, new_iv, extended_digest);

    printf("\n攻击生成的扩展哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", extended_digest[i]);
    printf("\n");

    // 验证攻击: 计算 secret + message + padding + extension 的哈希
    size_t total_len = full_len + padding_size + strlen(extension);
    uint8_t* total_msg = (uint8_t*)malloc(total_len);

    // 第一部分: 原始消息
    memcpy(total_msg, full_msg, full_len);

    // 第二部分: 填充
    memcpy(total_msg + full_len, extended_msg, padding_size);

    // 第三部分: 扩展数据
    memcpy(total_msg + full_len + padding_size, extension, strlen(extension));

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
    }

    // 释放内存
    free(full_msg);
    free(extended_msg);
    free(total_msg);
}

int main() {
    // 测试原始消息哈希计算
    const char* msg = "abc";
    uint8_t digest[32];
    sm3_hash((uint8_t*)msg, strlen(msg), digest);

    printf("SM3(\"%s\") = ", msg);
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // 执行长度扩展攻击验证
    length_extension_attack();

    return 0;
}