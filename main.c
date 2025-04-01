#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "modes.h"

void print_block(unsigned char *block) {
    for (int i = 0; i < 16; i++) {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

int main() {
    // 明文（4 个 128 位块）
    unsigned char plaintext[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    unsigned char ciphertext[64];
    unsigned char decrypted[64];

    // === ECB-AES128 ===
    printf("=== ECB-AES128.Encrypt ===\n");
    unsigned char key_128[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char expected_ecb_128_encrypt[64] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
        0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
    };

    nk = 4;  // AES-128
    key_expansion(key_128);
    ecb_encrypt(plaintext, ciphertext, 64);
    for (int i = 0; i < 4; i++) {
        printf("Block #%d Ciphertext: ", i + 1);
        print_block(ciphertext + i * 16);
    }
    int pass_ecb_128_encrypt = 1;
    for (int i = 0; i < 4; i++) {
        if (!compare_blocks(ciphertext + i * 16, expected_ecb_128_encrypt + i * 16)) {
            pass_ecb_128_encrypt = 0;
            break;
        }
    }
    printf("ECB-AES128.Encrypt Test %s\n", pass_ecb_128_encrypt ? "PASSED" : "FAILED");

    printf("=== ECB-AES128.Decrypt ===\n");
    key_expansion(key_128);
    ecb_decrypt(ciphertext, decrypted, 64);
    for (int i = 0; i < 4; i++) {
        printf("Block #%d Decrypted: ", i + 1);
        print_block(decrypted + i * 16);
    }
    int pass_ecb_128_decrypt = 1;
    for (int i = 0; i < 4; i++) {
        if (!compare_blocks(decrypted + i * 16, plaintext + i * 16)) {
            pass_ecb_128_decrypt = 0;
            break;
        }
    }
    printf("ECB-AES128.Decrypt Test %s\n", pass_ecb_128_decrypt ? "PASSED" : "FAILED");

    // === ECB-AES192 ===
    printf("=== ECB-AES192.Encrypt ===\n");
    unsigned char key_192[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    unsigned char expected_ecb_192_encrypt[64] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
        0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
        0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
        0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
        0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
        0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
        0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e
    };

    nk = 6;  // AES-192
    key_expansion(key_192);
    ecb_encrypt(plaintext, ciphertext, 64);
    for (int i = 0; i < 4; i++) {
        printf("Block #%d Ciphertext: ", i + 1);
        print_block(ciphertext + i * 16);
    }
    int pass_ecb_192_encrypt = 1;
    for (int i = 0; i < 4; i++) {
        if (!compare_blocks(ciphertext + i * 16, expected_ecb_192_encrypt + i * 16)) {
            pass_ecb_192_encrypt = 0;
            break;
        }
    }
    printf("ECB-AES192.Encrypt Test %s\n", pass_ecb_192_encrypt ? "PASSED" : "FAILED");

    printf("=== ECB-AES192.Decrypt ===\n");
    key_expansion(key_192);
    ecb_decrypt(ciphertext, decrypted, 64);
    for (int i = 0; i < 4; i++) {
        printf("Block #%d Decrypted: ", i + 1);
        print_block(decrypted + i * 16);
    }
    int pass_ecb_192_decrypt = 1;
    for (int i = 0; i < 4; i++) {
        if (!compare_blocks(decrypted + i * 16, plaintext + i * 16)) {
            pass_ecb_192_decrypt = 0;
            break;
        }
    }
    printf("ECB-AES192.Decrypt Test %s\n", pass_ecb_192_decrypt ? "PASSED" : "FAILED");

    // === ECB-AES256 ===
    printf("=== ECB-AES256.Encrypt ===\n");
    unsigned char key_256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    unsigned char expected_ecb_256_encrypt[64] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
        0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
        0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
        0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
        0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
        0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
        0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
    };

    nk = 8;  // AES-256
    key_expansion(key_256);
    ecb_encrypt(plaintext, ciphertext, 64);
    for (int i = 0; i < 4; i++) {
        printf("Block #%d Ciphertext: ", i + 1);
        print_block(ciphertext + i * 16);
    }
    int pass_ecb_256_encrypt = 1;
    for (int i = 0; i < 4; i++) {
        if (!compare_blocks(ciphertext + i * 16, expected_ecb_256_encrypt + i * 16)) {
            pass_ecb_256_encrypt = 0;
            break;
        }
    }
    printf("ECB-AES256.Encrypt Test %s\n", pass_ecb_256_encrypt ? "PASSED" : "FAILED");

    printf("=== ECB-AES256.Decrypt ===\n");
    key_expansion(key_256);
    ecb_decrypt(ciphertext, decrypted, 64);
    for (int i = 0; i < 4; i++) {
        printf("Block #%d Decrypted: ", i + 1);
        print_block(decrypted + i * 16);
    }
    int pass_ecb_256_decrypt = 1;
    for (int i = 0; i < 4; i++) {
        if (!compare_blocks(decrypted + i * 16, plaintext + i * 16)) {
            pass_ecb_256_decrypt = 0;
            break;
        }
    }
    printf("ECB-AES256.Decrypt Test %s\n", pass_ecb_256_decrypt ? "PASSED" : "FAILED");

    // === CBC-AES128 ===
    printf("=== CBC-AES128.Encrypt ===\n");
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char expected_cbc_128_encrypt[48] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16
    };

    nk = 4;  // AES-128
    key_expansion(key_128);
    cbc_encrypt(plaintext, ciphertext, 48, iv);
    for (int i = 0; i < 3; i++) {
        printf("Block #%d Ciphertext: ", i + 1);
        print_block(ciphertext + i * 16);
    }
    int pass_cbc_128_encrypt = 1;
    for (int i = 0; i < 3; i++) {
        if (!compare_blocks(ciphertext + i * 16, expected_cbc_128_encrypt + i * 16)) {
            pass_cbc_128_encrypt = 0;
            break;
        }
    }
    printf("CBC-AES128.Encrypt Test %s\n", pass_cbc_128_encrypt ? "PASSED" : "FAILED");

    printf("=== CBC-AES128.Decrypt ===\n");
    key_expansion(key_128);
    cbc_decrypt(ciphertext, decrypted, 48, iv);
    for (int i = 0; i < 3; i++) {
        printf("Block #%d Decrypted: ", i + 1);
        print_block(decrypted + i * 16);
    }
    int pass_cbc_128_decrypt = 1;
    for (int i = 0; i < 3; i++) {
        if (!compare_blocks(decrypted + i * 16, plaintext + i * 16)) {
            pass_cbc_128_decrypt = 0;
            break;
        }
    }
    printf("CBC-AES128.Decrypt Test %s\n", pass_cbc_128_decrypt ? "PASSED" : "FAILED");

    // === CBC-AES192 ===
    printf("=== CBC-AES192.Encrypt ===\n");
    unsigned char expected_cbc_192_encrypt[48] = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
        0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
        0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
        0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
        0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
        0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0
    };

    nk = 6;  // AES-192
    key_expansion(key_192);
    cbc_encrypt(plaintext, ciphertext, 48, iv);
    for (int i = 0; i < 3; i++) {
        printf("Block #%d Ciphertext: ", i + 1);
        print_block(ciphertext + i * 16);
    }
    int pass_cbc_192_encrypt = 1;
    for (int i = 0; i < 3; i++) {
        if (!compare_blocks(ciphertext + i * 16, expected_cbc_192_encrypt + i * 16)) {
            pass_cbc_192_encrypt = 0;
            break;
        }
    }
    printf("CBC-AES192.Encrypt Test %s\n", pass_cbc_192_encrypt ? "PASSED" : "FAILED");

    printf("=== CBC-AES192.Decrypt ===\n");
    key_expansion(key_192);
    cbc_decrypt(ciphertext, decrypted, 48, iv);
    for (int i = 0; i < 3; i++) {
        printf("Block #%d Decrypted: ", i + 1);
        print_block(decrypted + i * 16);
    }
    int pass_cbc_192_decrypt = 1;
    for (int i = 0; i < 3; i++) {
        if (!compare_blocks(decrypted + i * 16, plaintext + i * 16)) {
            pass_cbc_192_decrypt = 0;
            break;
        }
    }
    printf("CBC-AES192.Decrypt Test %s\n", pass_cbc_192_decrypt ? "PASSED" : "FAILED");

    // === CBC-AES256 ===
    printf("=== CBC-AES256.Encrypt ===\n");
    unsigned char expected_cbc_256_encrypt[48] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
        0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
        0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61
    };

    nk = 8;  // AES-256
    key_expansion(key_256);
    cbc_encrypt(plaintext, ciphertext, 48, iv);
    for (int i = 0; i < 3; i++) {
        printf("Block #%d Ciphertext: ", i + 1);
        print_block(ciphertext + i * 16);
    }
    int pass_cbc_256_encrypt = 1;
    for (int i = 0; i < 3; i++) {
        if (!compare_blocks(ciphertext + i * 16, expected_cbc_256_encrypt + i * 16)) {
            pass_cbc_256_encrypt = 0;
            break;
        }
    }
    printf("CBC-AES256.Encrypt Test %s\n", pass_cbc_256_encrypt ? "PASSED" : "FAILED");

    printf("=== CBC-AES256.Decrypt ===\n");
    key_expansion(key_256);
    cbc_decrypt(ciphertext, decrypted, 48, iv);
    for (int i = 0; i < 3; i++) {
        printf("Block #%d Decrypted: ", i + 1);
        print_block(decrypted + i * 16);
    }
    int pass_cbc_256_decrypt = 1;
    for (int i = 0; i < 3; i++) {
        if (!compare_blocks(decrypted + i * 16, plaintext + i * 16)) {
            pass_cbc_256_decrypt = 0;
            break;
        }
    }
    printf("CBC-AES256.Decrypt Test %s\n", pass_cbc_256_decrypt ? "PASSED" : "FAILED");

    return 0;
}
