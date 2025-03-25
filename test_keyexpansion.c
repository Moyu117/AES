// test_key_expansion.c
#include <stdio.h>
#include "aes.h"

void print_word(int word) {
    // 使用 %08x 确保输出 8 位十六进制
    printf("%08x", word & 0xFFFFFFFF); // 确保无符号输出
}

int main() {
    // 测试密钥
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    int nk = 4;
    int nr = 10; // AES-128
    int w[NB * (NR + 1)];

    // 执行密钥扩展
    key_expansion(key, w, nk);

    // 打印结果并验证
    printf("Key Expansion Test (Nk = 4):\n");
    for (int i = 0; i <= 4 * nr + 3; i++) {
        printf("w[%d] = ", i);
        print_word(w[i]);
        printf("\n");
    }

    // 验证 w[4] 到 w[7]
    int expected_w4 = 0xa0fafe17;
    int expected_w5 = 0x88542cb1;
    int expected_w6 = 0x23a33939;
    int expected_w7 = 0x2a6c7605;

    int pass = 1;
    if (w[4] != expected_w4 || w[5] != expected_w5 ||
        w[6] != expected_w6 || w[7] != expected_w7) {
        pass = 0;
    }

    if (pass) {
        printf("Key Expansion Test PASSED\n");
    } else {
        printf("Key Expansion Test FAILED\n");
    }

    return 0;
}
