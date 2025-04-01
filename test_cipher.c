#include <stdio.h>
#include "aes.h"

void print_block(unsigned char *block) {
    for (int i = 0; i < 16; i++) {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

int main() {
    // FIPS 197 Appendix B 示例
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char in[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    unsigned char expected_out[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    unsigned char out[16];
    unsigned char decrypted[16];

    // 设置全局变量 nk
    nk = 4;  // AES-128

    // 测试加密
    key_expansion(key);  // 使用标准密钥扩展
    cipher(in, out);
    printf("Encrypted Output: ");
    print_block(out);

    int pass_encrypt = 1;
    for (int i = 0; i < 16; i++) {
        if (out[i] != expected_out[i]) {
            pass_encrypt = 0;
            break;
        }
    }
    printf("Encryption Test %s\n", pass_encrypt ? "PASSED" : "FAILED");

    // 测试解密（INVCIPHER）
    key_expansion(key);  // 重新生成标准轮密钥
    inv_cipher(out, decrypted);
    printf("Decrypted Output (INVCIPHER): ");
    print_block(decrypted);

    int pass_decrypt = 1;
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] != in[i]) {
            pass_decrypt = 0;
            break;
        }
    }
    printf("Decryption Test (INVCIPHER) %s\n", pass_decrypt ? "PASSED" : "FAILED");

    // 测试等价解密（EQINVCIPHER）
    key_expansion_eic(key);  // 使用等价密钥扩展
    eq_inv_cipher(out, decrypted);
    printf("Decrypted Output (EQINVCIPHER): ");
    print_block(decrypted);

    int pass_decrypt_eq = 1;
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] != in[i]) {
            pass_decrypt_eq = 0;
            break;
        }
    }
    printf("Decryption Test (EQINVCIPHER) %s\n", pass_decrypt_eq ? "PASSED" : "FAILED");

    return 0;
}
