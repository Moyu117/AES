#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "modes.h"

// 辅助函数：以十六进制形式打印数据
static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 辅助函数：解析固定长度的十六进制字符串到二进制，要求输出长度为 out_len 字节
static int parse_hex(const char *hexstr, unsigned char *out, size_t out_len) {
    if (strlen(hexstr) != out_len * 2)
        return 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int val;
        if (sscanf(hexstr + 2*i, "%2x", &val) != 1)
            return 0;
        out[i] = (unsigned char)val;
    }
    return 1;
}

// 辅助函数：解析任意长度的十六进制字符串（动态分配内存，返回指针，并把长度保存到 binlen）
static unsigned char *parse_hex_dynamic(const char *hexstr, size_t *binlen) {
    size_t hexlen = strlen(hexstr);
    if (hexlen % 2 != 0) {
        return NULL;
    }
    *binlen = hexlen / 2;
    unsigned char *buf = (unsigned char*)malloc(*binlen);
    if (!buf) return NULL;
    for (size_t i = 0; i < *binlen; i++) {
        unsigned int val;
        if (sscanf(hexstr + 2*i, "%2x", &val) != 1) {
            free(buf);
            return NULL;
        }
        buf[i] = (unsigned char)val;
    }
    return buf;
}

static void usage() {
    printf("Usage:\n");
    printf("  ./aes_app mode operation key [iv] data\n");
    printf("\nModes:\n");
    printf("  ecb : ECB mode\n");
    printf("  cbc : CBC mode (需要额外指定 IV)\n");
    printf("  cmac: CMAC (即 CBC-MAC)\n");
    printf("\nOperations:\n");
    printf("  encrypt : 加密\n");
    printf("  decrypt : 解密\n");
    printf("  generate: 生成 CMAC\n");
    printf("  verify  : 校验 CMAC\n");
    printf("\nKey: 必须为 32/48/64 个 hex 字符，分别对应 128/192/256 位 AES\n");
    printf("For CBC: IV 必须为 32 个 hex 字符（16 字节）\n");
    printf("Data: 对于 ECB/CBC，加密/解密的数据长度必须是 16 字节的倍数（即 32 个 hex 字符的倍数）；\n");
    printf("      CMAC 的消息长度可任意，默认生成 128 位（16 字节）的 MAC。\n");
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        usage();
        return 1;
    }
    
    const char *mode = argv[1];       // "ecb", "cbc", "cmac"
    const char *operation = argv[2];  // "encrypt", "decrypt", "generate", "verify"
    const char *hex_key = argv[3];

    // 解析密钥，检查长度
    size_t key_len = strlen(hex_key) / 2;
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr, "Key length must be 16, 24 or 32 bytes (32, 48, or 64 hex chars).\n");
        return 1;
    }
    // 根据密钥长度设置全局变量 nk
    if (key_len == 16)
        nk = 4;
    else if (key_len == 24)
        nk = 6;
    else if (key_len == 32)
        nk = 8;
    
    unsigned char key[32]; // 最大支持32字节密钥
    if (!parse_hex(hex_key, key, key_len)) {
        fprintf(stderr, "Key parse error.\n");
        return 1;
    }
    
    if (strcmp(mode, "ecb") == 0) {
        if (argc != 5) {
            usage();
            return 1;
        }
        size_t data_len;
        unsigned char *data = parse_hex_dynamic(argv[4], &data_len);
        if (!data) {
            fprintf(stderr, "Data parse error.\n");
            return 1;
        }
        if (data_len % 16 != 0) {
            fprintf(stderr, "For ECB mode, data length must be a multiple of 16 bytes.\n");
            free(data);
            return 1;
        }
        unsigned char *outbuf = (unsigned char*)malloc(data_len);
        if (!outbuf) { free(data); return 1; }
        
        if (strcmp(operation, "encrypt") == 0) {
            ECB_Encrypt(key, data, outbuf, data_len / 16);
        } else if (strcmp(operation, "decrypt") == 0) {
            ECB_Decrypt(key, data, outbuf, data_len / 16);
        } else {
            usage();
            free(data); free(outbuf);
            return 1;
        }
        print_hex("Output", outbuf, data_len);
        free(data);
        free(outbuf);
    }
    else if (strcmp(mode, "cbc") == 0) {
        if (argc != 6) {
            usage();
            return 1;
        }
        const char *hex_iv = argv[4];
        if (strlen(hex_iv) != 32) {
            fprintf(stderr, "IV must be 16 bytes (32 hex chars).\n");
            return 1;
        }
        unsigned char iv[16];
        if (!parse_hex(hex_iv, iv, 16)) {
            fprintf(stderr, "IV parse error.\n");
            return 1;
        }
        size_t data_len;
        unsigned char *data = parse_hex_dynamic(argv[5], &data_len);
        if (!data) {
            fprintf(stderr, "Data parse error.\n");
            return 1;
        }
        if (data_len % 16 != 0) {
            fprintf(stderr, "For CBC mode, data length must be a multiple of 16 bytes.\n");
            free(data);
            return 1;
        }
        unsigned char *outbuf = (unsigned char*)malloc(data_len);
        if (!outbuf) { free(data); return 1; }
        
        if (strcmp(operation, "encrypt") == 0) {
            CBC_Encrypt(key, iv, data, outbuf, data_len / 16);
        } else if (strcmp(operation, "decrypt") == 0) {
            CBC_Decrypt(key, iv, data, outbuf, data_len / 16);
        } else {
            usage();
            free(data); free(outbuf);
            return 1;
        }
        print_hex("Output", outbuf, data_len);
        free(data);
        free(outbuf);
    }
    else if (strcmp(mode, "cmac") == 0) {
        if (strcmp(operation, "generate") == 0) {
            if (argc != 5) {
                usage();
                return 1;
            }
            size_t msg_len;
            unsigned char *msg = parse_hex_dynamic(argv[4], &msg_len);
            if (!msg) {
                fprintf(stderr, "Message parse error.\n");
                return 1;
            }
            unsigned char tag[16]; // 默认生成 128 位（16 字节）的 MAC
            CMAC(key, msg, msg_len, 128, tag);
            print_hex("CMAC", tag, 16);
            free(msg);
        } else if (strcmp(operation, "verify") == 0) {
            if (argc != 6) {
                usage();
                return 1;
            }
            size_t msg_len;
            unsigned char *msg = parse_hex_dynamic(argv[4], &msg_len);
            if (!msg) {
                fprintf(stderr, "Message parse error.\n");
                return 1;
            }
            if (strlen(argv[5]) != 32) {
                fprintf(stderr, "Tag must be 16 bytes (32 hex chars).\n");
                free(msg);
                return 1;
            }
            unsigned char tag[16];
            if (!parse_hex(argv[5], tag, 16)) {
                fprintf(stderr, "Tag parse error.\n");
                free(msg);
                return 1;
            }
            int valid = VER(key, msg, msg_len, 128, tag);
            printf("CMAC verify => %s\n", valid ? "OK" : "FAIL");
            free(msg);
        } else {
            usage();
            return 1;
        }
    }
    else {
        usage();
        return 1;
    }
    
    return 0;
}
