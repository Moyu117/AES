// modes.c
#include "aes.h"
#include <stdlib.h>

// 生成子密钥 K1 和 K2（用于 CMAC）
static void generate_subkeys(unsigned char *key, unsigned char *k1, unsigned char *k2, int nk) {
    unsigned char l[16];
    unsigned char zero[16] = {0};
    aes_encrypt(zero, key, l, nk); // 用全零块生成 L

    // 计算 K1：左移一位，若最高位为 1，则异或 0x87
    int carry = 0;
    for (int i = 15; i >= 0; i--) {
        int next_carry = (l[i] & 0x80) ? 1 : 0;
        k1[i] = (l[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry) k1[15] ^= 0x87;

    // 计算 K2：K1 再左移一位，若最高位为 1，则异或 0x87
    carry = 0;
    for (int i = 15; i >= 0; i--) {
        int next_carry = (k1[i] & 0x80) ? 1 : 0;
        k2[i] = (k1[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry) k2[15] ^= 0x87;
}

// ECB 加密
void ecb_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int len, int nk) {
    for (int i = 0; i < len; i += 16) {
        aes_encrypt(plaintext + i, key, ciphertext + i, nk);
    }
}

// ECB 解密（支持标准解密和等效逆密码解密）
void ecb_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int len, int nk, int use_eq) {
    for (int i = 0; i < len; i += 16) {
        if (use_eq) {
            aes_eq_decrypt(ciphertext + i, key, plaintext + i, nk); // 使用等效逆密码
        } else {
            aes_decrypt(ciphertext + i, key, plaintext + i, nk); // 使用标准逆密码
        }
    }
}

// CBC 加密
void cbc_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int len, int nk) {
    unsigned char temp[16];
    for (int i = 0; i < 16; i++) {
        temp[i] = iv[i]; // 初始化为 IV
    }
    for (int i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; j++) {
            temp[j] ^= plaintext[i + j]; // 与明文异或
        }
        aes_encrypt(temp, key, ciphertext + i, nk); // 加密
        for (int j = 0; j < 16; j++) {
            temp[j] = ciphertext[i + j]; // 更新 temp 为当前密文块
        }
    }
}

// CBC 解密（支持标准解密和等效逆密码解密）
void cbc_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int len, int nk, int use_eq) {
    unsigned char temp[16];
    unsigned char prev[16];
    for (int i = 0; i < 16; i++) {
        prev[i] = iv[i]; // 初始化为 IV
    }
    for (int i = 0; i < len; i += 16) {
        if (use_eq) {
            aes_eq_decrypt(ciphertext + i, key, temp, nk); // 使用等效逆密码
        } else {
            aes_decrypt(ciphertext + i, key, temp, nk); // 使用标准逆密码
        }
        for (int j = 0; j < 16; j++) {
            plaintext[i + j] = temp[j] ^ prev[j]; // 与前一块密文异或
            prev[j] = ciphertext[i + j]; // 更新 prev 为当前密文块
        }
    }
}

// CMAC 计算
void cmac(unsigned char *message, unsigned char *key, unsigned char *mac, int len, int nk) {
    unsigned char k1[16], k2[16];
    unsigned char iv[16] = {0}; // 全零 IV
    unsigned char temp[16];
    int i;

    // 生成子密钥 K1 和 K2
    generate_subkeys(key, k1, k2, nk);

    // 计算完整块数和最后一个块的长度
    int blocks = (len + 15) / 16; // 向上取整
    int last_block_len = len % 16;
    if (last_block_len == 0 && len > 0) last_block_len = 16;

    // 处理除最后一个块外的所有块
    for (i = 0; i < blocks - 1; i++) {
        for (int j = 0; j < 16; j++) {
            temp[j] = iv[j] ^ message[i * 16 + j];
        }
        aes_encrypt(temp, key, iv, nk);
    }

    // 处理最后一个块
    for (i = 0; i < 16; i++) {
        if (i < last_block_len) {
            temp[i] = message[(blocks - 1) * 16 + i];
        } else {
            temp[i] = (i == last_block_len) ? 0x80 : 0; // PKCS5/PKCS7 填充
        }
    }

    // 根据最后一个块是否完整选择 K1 或 K2
    if (last_block_len == 16) {
        for (i = 0; i < 16; i++) temp[i] ^= k1[i];
    } else {
        for (i = 0; i < 16; i++) temp[i] ^= k2[i];
    }

    // 与 IV 异或并加密得到 MAC
    for (i = 0; i < 16; i++) temp[i] ^= iv[i];
    aes_encrypt(temp, key, mac, nk);
}
