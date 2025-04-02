#include "aes.h"
#include <stdlib.h>
#include <string.h>

// ECB 模式加密：
// 输入参数：K（16 字节密钥）、P（num_blocks 个 16 字节明文块）、输出 C
void ECB_Encrypt(const unsigned char *K, const unsigned char *P, unsigned char *C, unsigned int num_blocks) {
    //nk = 4; // AES-128
    key_expansion((unsigned char *)K);
    for (unsigned int i = 0; i < num_blocks; i++) {
        cipher((unsigned char *)(P + i * 16), (unsigned char *)(C + i * 16));
    }
}

// ECB 模式解密：
void ECB_Decrypt(const unsigned char *K, const unsigned char *C, unsigned char *P, unsigned int num_blocks) {
    //nk = 4;
    key_expansion((unsigned char *)K);
    for (unsigned int i = 0; i < num_blocks; i++) {
        inv_cipher((unsigned char *)(C + i * 16), (unsigned char *)(P + i * 16));
    }
}

// CBC 模式加密：
void CBC_Encrypt(const unsigned char *K, const unsigned char *IV, const unsigned char *P, unsigned char *C, unsigned int num_blocks) {
    //nk = 4;
    key_expansion((unsigned char *)K);
    unsigned char prev[16];
    memcpy(prev, IV, 16);
    unsigned char block[16];
    for (unsigned int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 16; j++) {
            block[j] = P[i * 16 + j] ^ prev[j];
        }
        cipher(block, C + i * 16);
        memcpy(prev, C + i * 16, 16);
    }
}

// CBC 模式解密：
void CBC_Decrypt(const unsigned char *K, const unsigned char *IV, const unsigned char *C, unsigned char *P, unsigned int num_blocks) {
   // nk = 4;
    key_expansion((unsigned char *)K);
    unsigned char prev[16];
    memcpy(prev, IV, 16);
    unsigned char block[16];
    for (unsigned int i = 0; i < num_blocks; i++) {
        inv_cipher((unsigned char *)(C + i * 16), block);
        for (int j = 0; j < 16; j++) {
            P[i * 16 + j] = block[j] ^ prev[j];
        }
        memcpy(prev, C + i * 16, 16);
    }
}

// 内部函数：根据密钥 K 生成 CMAC 子密钥 K1 和 K2
// 对于 128 位块，Rb = {00...00 87}
static void SUBK(const unsigned char *K, unsigned char *K1, unsigned char *K2) {
    unsigned char L[16] = {0};
    unsigned char Z[16] = {0};  // 全零块
    //nk = 4;
    key_expansion((unsigned char *)K);
    cipher(Z, L);  // L = CIPHK(0^128)

    unsigned char Rb[16] = {0};
    Rb[15] = 0x87;

    // 生成 K1
    unsigned char carry = 0;
    for (int i = 15; i >= 0; i--) {
        unsigned char temp = L[i];
        K1[i] = (temp << 1) | carry;
        carry = (temp & 0x80) ? 1 : 0;
    }
    if (carry) {
        for (int i = 0; i < 16; i++) {
            K1[i] ^= Rb[i];
        }
    }

    // 生成 K2
    carry = 0;
    for (int i = 15; i >= 0; i--) {
        unsigned char temp = K1[i];
        K2[i] = (temp << 1) | carry;
        carry = (temp & 0x80) ? 1 : 0;
    }
    if (carry) {
        for (int i = 0; i < 16; i++) {
            K2[i] ^= Rb[i];
        }
    }
}

// CMAC 生成函数
// 输入：K（16 字节密钥）、消息 M，长度 Mlen（字节）、MAC 长度 Tlen（比特，须为 8 的倍数）
// 输出：T（至少 Tlen/8 字节的 MAC）
void CMAC(const unsigned char *K, const unsigned char *M, unsigned int Mlen, unsigned int Tlen, unsigned char *T) {
    unsigned char K1[16], K2[16];
    SUBK(K, K1, K2);

    // 块数 n
    unsigned int n;
    if (Mlen == 0)
        n = 1;
    else
        n = (Mlen + 15) / 16;

    // 处理最后一块
    unsigned char *M_last = (unsigned char *)malloc(16);
    if (!M_last) return;
    int complete = (Mlen != 0 && (Mlen % 16 == 0));
    if (complete) {
        memcpy(M_last, M + (n - 1) * 16, 16);
        for (int i = 0; i < 16; i++) {
            M_last[i] ^= K1[i];
        }
    } else {
        unsigned int rem = Mlen % 16;
        memset(M_last, 0, 16);
        if (rem > 0) {
            memcpy(M_last, M + (n - 1) * 16, rem);
        }
        M_last[rem] = 0x80;
        for (int i = 0; i < 16; i++) {
            M_last[i] ^= K2[i];
        }
    }

    // 执行 CBC-MAC（IV=0）
    unsigned char X[16] = {0};
    unsigned char block[16];
    for (unsigned int i = 0; i < n - 1; i++) {
        for (int j = 0; j < 16; j++) {
            block[j] = X[j] ^ M[i * 16 + j];
        }
        cipher(block, X);
    }
    // 最后一块
    for (int j = 0; j < 16; j++) {
        block[j] = X[j] ^ M_last[j];
    }
    cipher(block, X);
    free(M_last);

    // 截取 Tlen 位
    unsigned int T_bytes = Tlen / 8;
    memcpy(T, X, T_bytes);
}

// CMAC 验证函数
// 返回：1 表示验证通过，否则 0
int VER(const unsigned char *K, const unsigned char *M, unsigned int Mlen, unsigned int Tlen, const unsigned char *T_received) {
    unsigned char T_calc[16];
    CMAC(K, M, Mlen, Tlen, T_calc);
    unsigned int T_bytes = Tlen / 8;
    return (memcmp(T_calc, T_received, T_bytes) == 0) ? 1 : 0;
}
