#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "modes.h"
#include "aes.h"
// 引入我们之前在 modes.c 中实现的函数原型
// 例如：
// void ECB_Encrypt(const unsigned char *K, const unsigned char *P, unsigned char *C, unsigned int num_blocks);
// void ECB_Decrypt(const unsigned char *K, const unsigned char *C, unsigned char *P, unsigned int num_blocks);
// void CBC_Encrypt(const unsigned char *K, const unsigned char *IV, const unsigned char *P, unsigned char *C, unsigned int num_blocks);
// void CBC_Decrypt(const unsigned char *K, const unsigned char *IV, const unsigned char *C, unsigned char *P, unsigned int num_blocks);
// void CMAC(const unsigned char *K, const unsigned char *M, unsigned int Mlen, unsigned int Tlen, unsigned char *T);
// int VER(const unsigned char *K, const unsigned char *M, unsigned int Mlen, unsigned int Tlen, const unsigned char *T_received);

// 辅助函数：打印 16 进制
static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 从十六进制字符串解析到二进制
static int parse_hex(const char *hexstr, unsigned char *out, size_t out_len) {
    // hexstr 长度应是 out_len*2
    size_t hex_len = strlen(hexstr);
    if (hex_len != out_len * 2) {
        return 0; // 长度不匹配
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int val;
        if (sscanf(hexstr + 2*i, "%2x", &val) != 1) {
            return 0; // 解析失败
        }
        out[i] = (unsigned char)val;
    }
    return 1;
}

// 简单示例：测试 ECB/AES-128（参考 NIST SP 800-38A F.1.1 中的一个块）
static void test_ecb_single_block() {
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Expected Ciphertext: 3ad77bb40d7a3660a89ecaf32466ef97

    const char *hex_key = "2b7e151628aed2a6abf7158809cf4f3c";
    const char *hex_pt  = "6bc1bee22e409f96e93d7e117393172a";
    const char *hex_ct_exp = "3ad77bb40d7a3660a89ecaf32466ef97";

    unsigned char K[16], PT[16], CT[16], CT_exp[16];
    parse_hex(hex_key, K, 16);
    parse_hex(hex_pt, PT, 16);
    parse_hex(hex_ct_exp, CT_exp, 16);

    // 加密
    memset(CT, 0, 16);
    ECB_Encrypt(K, PT, CT, 1);

    // 打印结果
    print_hex("ECB Enc Key", K, 16);
    print_hex("ECB Enc PT ", PT, 16);
    print_hex("ECB Enc CT ", CT, 16);
    printf("Expected    : %s\n\n", hex_ct_exp);

    // 对比
    if (memcmp(CT, CT_exp, 16) == 0) {
        printf("ECB single-block encrypt test: PASSED\n\n");
    } else {
        printf("ECB single-block encrypt test: FAILED\n\n");
    }

    // 解密测试
    unsigned char PT_dec[16];
    memset(PT_dec, 0, 16);
    ECB_Decrypt(K, CT, PT_dec, 1);
    print_hex("ECB Dec PT ", PT_dec, 16);
    // 对比原明文
    if (memcmp(PT_dec, PT, 16) == 0) {
        printf("ECB single-block decrypt test: PASSED\n\n");
    } else {
        printf("ECB single-block decrypt test: FAILED\n\n");
        print_hex("ECB PT ", PT, 16);
    }
}

// 简单示例：测试 CBC/AES-128（参考 NIST SP 800-38A F.2.1）
static void test_cbc_single_block() {
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // IV:  000102030405060708090a0b0c0d0e0f
    // Plaintext(1块): 6bc1bee22e409f96e93d7e117393172a
    // Expected Ciphertext(第1块): 7649abac8119b246cee98e9b12e9197d

    const char *hex_key = "2b7e151628aed2a6abf7158809cf4f3c";
    const char *hex_iv  = "000102030405060708090a0b0c0d0e0f";
    const char *hex_pt  = "6bc1bee22e409f96e93d7e117393172a";
    const char *hex_ct_exp = "7649abac8119b246cee98e9b12e9197d";

    unsigned char K[16], IV[16], PT[16], CT[16], CT_exp[16];
    parse_hex(hex_key, K, 16);
    parse_hex(hex_iv, IV, 16);
    parse_hex(hex_pt, PT, 16);
    parse_hex(hex_ct_exp, CT_exp, 16);

    memset(CT, 0, 16);
    CBC_Encrypt(K, IV, PT, CT, 1);

    print_hex("CBC Enc Key", K, 16);
    print_hex("CBC Enc IV ", IV, 16);
    print_hex("CBC Enc PT ", PT, 16);
    print_hex("CBC Enc CT ", CT, 16);
    printf("Expected    : %s\n\n", hex_ct_exp);

    if (memcmp(CT, CT_exp, 16) == 0) {
        printf("CBC single-block encrypt test: PASSED\n\n");
    } else {
        printf("CBC single-block encrypt test: FAILED\n\n");
    }

    unsigned char PT_dec[16];
    memset(PT_dec, 0, 16);
    CBC_Decrypt(K, IV, CT, PT_dec, 1);
    print_hex("CBC Dec PT ", PT_dec, 16);
    if (memcmp(PT_dec, PT, 16) == 0) {
        printf("CBC single-block decrypt test: PASSED\n\n");
    } else {
        printf("CBC single-block decrypt test: FAILED\n\n");
        print_hex("de",PT,16);
    }
}

// 简单示例：测试 CMAC/AES-128（可参考 NIST SP 800-38B中给出的示例）
// 这里只做一个单块消息测试，用户可自行扩展多块示例
static void test_cmac_single_block() {
    // 例：Key = 2b7e151628aed2a6abf7158809cf4f3c
    // M = 6bc1bee22e409f96e93d7e117393172a (16字节)
    // 假设期望 MAC 长度 Tlen=128 bits
    // 根据 SP 800-38B 附录D可能给出示例(省略)
    // 这里以某随机期望值替代

    const char *hex_key = "2b7e151628aed2a6abf7158809cf4f3c";
    const char *hex_m   = "6bc1bee22e409f96e93d7e117393172a";
    // 这里示例：期望MAC假设是 070a16b46b4d4144f79bdd9dd04a287c （但并非真实值，需要根据具体文档测试）
    const char *hex_mac_exp = "070a16b46b4d4144f79bdd9dd04a287c";

    unsigned char K[16], M[16], T[16], T_exp[16];
    parse_hex(hex_key, K, 16);
    parse_hex(hex_m, M, 16);
    parse_hex(hex_mac_exp, T_exp, 16);

    memset(T, 0, 16);
    CMAC(K, M, 16, 128, T);

    print_hex("CMAC Key", K, 16);
    print_hex("CMAC Msg", M, 16);
    print_hex("CMAC Val", T, 16);
    printf("Expected  : %s\n\n", hex_mac_exp);

    if (memcmp(T, T_exp, 16) == 0) {
        printf("CMAC single-block test: PASSED\n\n");
    } else {
        printf("CMAC single-block test: FAILED\n\n");
        printf("%s\n",T_exp);
    }

    // 验证
    int ok = VER(K, M, 16, 128, T_exp);
    printf("CMAC verification with T_exp => %s\n", ok ? "PASSED" : "FAILED");
}

int main() {
    printf("==== AES Mode Test (Based on NIST SP 800-38A/B) ====\n\n");
    nk=4;//pour tester
    // 测试 ECB
    test_ecb_single_block();

    // 测试 CBC
    test_cbc_single_block();

    // 测试 CMAC
    test_cmac_single_block();

    return 0;
}
