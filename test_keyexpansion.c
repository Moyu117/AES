// test_key_expansion.c
#include <stdio.h>
#include "aes.h"

int main() {
    // 测试密钥
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    nk = 4;
    key_expansion(key);

    // 打印结果并验证
    printf("Key Expansion Test (Nk = 4):\n");
    for (int i = 0; i < NB * (10 + 1); i++) {
        printf("w[%d] = %08x \n ", i, w[i]);
    }
    return 0;
}
