#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "modes.h"

// ECB 模式加密
void ecb_encrypt(unsigned char *in, unsigned char *out, int len) {
    for (int i = 0; i < len; i += 16) {
        cipher(in + i, out + i);
    }
}

// ECB 模式解密
void ecb_decrypt(unsigned char *in, unsigned char *out, int len) {
    for (int i = 0; i < len; i += 16) {
        inv_cipher(in + i, out + i);
    }
}

// CBC 模式加密
void cbc_encrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv) {
    unsigned char temp[16];
    memcpy(temp, iv, 16);  // 初始化向量
    for (int i = 0; i < len; i += 16) {
        // 输入与 IV 或前一密文块异或
        for (int j = 0; j < 16; j++) {
            temp[j] ^= in[i + j];
        }
        cipher(temp, out + i);
        memcpy(temp, out + i, 16);  // 更新 IV 为当前密文块
    }
}

// CBC 模式解密
void cbc_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv) {
    unsigned char temp[16];
    unsigned char prev_cipher[16];
    memcpy(prev_cipher, iv, 16);  // 初始化向量
    for (int i = 0; i < len; i += 16) {
        inv_cipher(in + i, temp);
        // 输出与 IV 或前一密文块异或
        for (int j = 0; j < 16; j++) {
            out[i + j] = temp[j] ^ prev_cipher[j];
        }
        memcpy(prev_cipher, in + i, 16);  // 更新前一密文块
    }
}

// CFB 模式加密（以 128 位为例）
void cfb_encrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv) {
    unsigned char temp[16];
    memcpy(temp, iv, 16);  // 初始化向量
    for (int i = 0; i < len; i += 16) {
        cipher(temp, temp);  // 加密 IV 或前一密文块
        // 异或生成密文
        for (int j = 0; j < 16; j++) {
            out[i + j] = in[i + j] ^ temp[j];
        }
        memcpy(temp, out + i, 16);  // 更新 IV 为当前密文块
    }
}

// CFB 模式解密（以 128 位为例）
void cfb_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv) {
    unsigned char temp[16];
    memcpy(temp, iv, 16);  // 初始化向量
    for (int i = 0; i < len; i += 16) {
        cipher(temp, temp);  // 加密 IV 或前一密文块
        // 异或恢复明文
        for (int j = 0; j < 16; j++) {
            out[i + j] = in[i + j] ^ temp[j];
        }
        memcpy(temp, in + i, 16);  // 更新 IV 为当前密文块
    }
}

// OFB 模式加密（OFB 加密和解密相同）
void ofb_encrypt_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv) {
    unsigned char temp[16];
    memcpy(temp, iv, 16);  // 初始化向量
    for (int i = 0; i < len; i += 16) {
        cipher(temp, temp);  // 加密 IV 或前一输出块
        // 异或生成密文或明文
        for (int j = 0; j < 16; j++) {
            out[i + j] = in[i + j] ^ temp[j];
        }
    }
}

int compare_blocks(unsigned char *block1, unsigned char *block2) {
    for (int i = 0; i < 16; i++) {
        if (block1[i] != block2[i]) {
            return 0;
        }
    }
    return 1;
}
