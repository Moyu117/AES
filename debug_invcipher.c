#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

// 打印 state 数组的调试函数
static void debug_print_state(const char *label, unsigned char state[4][NB]) {
    printf("%s:\n", label);
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            printf("%02x ", state[r][c]);
        }
        printf("\n");
    }
    printf("\n");
}

// 调试版本的 inv_cipher（在每步后打印状态）
void inv_cipher_debug(unsigned char *in, unsigned char *out) {
    unsigned char state[4][NB];
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    // 初始化 state，从密文复制
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = in[r + c * 4];
        }
    }
    debug_print_state("Initial state (from ciphertext)", state);

    // 初始轮：使用最后一轮密钥（round = Nr）
    add_round_key(state, nr);
    debug_print_state("After AddRoundKey (round Nr)", state);

    // 主循环，从 round = Nr-1 到 1
    for (int round = nr - 1; round >= 1; round--) {
        inv_shift_rows(state);
        debug_print_state("After InvShiftRows", state);

        inv_sub_bytes(state);
        debug_print_state("After InvSubBytes", state);

        add_round_key(state, round);
        debug_print_state("After AddRoundKey", state);

        inv_mix_columns(state);
        {
            char buf[50];
            sprintf(buf, "After InvMixColumns (round %d)", round);
            debug_print_state(buf, state);
        }
    }

    // 最后一轮（不调用 inv_mix_columns）
    inv_shift_rows(state);
    debug_print_state("After final InvShiftRows", state);

    inv_sub_bytes(state);
    debug_print_state("After final InvSubBytes", state);

    add_round_key(state, 0);
    debug_print_state("After final AddRoundKey (round 0)", state);

    // 将 state 写入 out
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            out[r + c * 4] = state[r][c];
        }
    }
}

// 示例 main 函数，用来测试 debug 版本的 inv_cipher
int main(void) {
    // 示例数据：使用 NIST FIPS 197 附录B中 ECB 示例密文
    // 原明文（测试时应该为）：6bc1bee22e409f96e93d7e117393172a
    // 加密后的密文为：3ad77bb40d7a3660a89ecaf32466ef97
    unsigned char ciphertext[16] = {
        0x3a, 0xd7, 0x7b, 0xb4,
        0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3,
        0x24, 0x66, 0xef, 0x97
    };
    unsigned char decrypted[16] = {0};

    // 设置 AES-128 参数
    nk = 4; // AES-128，密钥扩展需要此全局变量
    // 使用示例密钥：2b7e151628aed2a6abf7158809cf4f3c
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    // 初始化轮密钥
    key_expansion(key);

    printf("==== Debug inv_cipher ====\n\n");
    inv_cipher_debug(ciphertext, decrypted);

    printf("Final decrypted output: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted[i]);
    }
    printf("\n");

    return 0;
}
