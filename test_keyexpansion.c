// test_key_expansion.c
#include <stdio.h>
#include "aes.h"

void print_word(unsigned char w[4][NB*(NR +1)], int i) {
    printf("%02x%02x%02x%02x", w[0][i], w[1][i], w[2][i], w[3][i]);
}

int main() {
    // 测试密钥
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    int nk = 4;
    int nr = 10; // AES-128
    unsigned char w[4][NB * (NR + 1)];

    // 执行密钥扩展
    key_expansion(key, w, nk);

    // 打印结果并验证
    printf("Key Expansion Test (Nk = 4):\n");
    for (int i = 0; i <= 4 * nr + 3; i++) {
        printf("w[%d] = ", i);
        print_word(w,i);
        printf("\n");
    }

    // 验证 w[4] 到 w[7]
    unsigned char expected_w4[4] = {0xa0, 0xfa, 0xfe, 0x17};
    unsigned char expected_w5[4] = {0x88, 0x54, 0x2c, 0xb1};
    unsigned char expected_w6[4] = {0x23, 0xa3, 0x39, 0x39};
    unsigned char expected_w7[4] = {0x2a, 0x6c, 0x76, 0x05};

    int pass = 1;
    for (int j = 0; j < 4; j++) {
        if (w[j][4] != expected_w4[j] || w[j][5] != expected_w5[j] ||
            w[j][6] != expected_w6[j] || w[j][7] != expected_w7[j]) {
            pass = 0;
            break;
        }
    }

    if (pass) {
        printf("Key Expansion Test PASSED\n");
    } else {
        printf("Key Expansion Test FAILED\n");
    }

    return 0;
}
