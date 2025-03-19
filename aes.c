// aes.c
#include "aes.h"
#define NB 4 // 状态的列数，固定为 4

// S 盒和逆 S 盒（这里只列出开头部分，需完整填充）
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, /* ... 完整 S 盒表，参考 FIPS 197 */
    // 请从 FIPS 197 获取完整表
};

static const unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, /* ... 完整逆 S 盒表 */
    // 请从 FIPS 197 获取完整表
};

// 轮常数（支持最多 14 轮，256 位密钥）
static const unsigned char rcon[14] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d
};

// 获取某位（辅助函数）
static int getBit(unsigned char n, int pos) {
    return (n >> pos) & 1;
}

// xtime 函数（Galois 域乘 2）
static unsigned char xtime(unsigned char n) {
    if (getBit(n, 7) == 1) {
        n = n << 1;
        n ^= 0x1b; // 约化多项式 x^8 + x^4 + x^3 + x + 1
    } else {
        n = n << 1;
    }
    return n;
}

// RotWord：循环左移 1 字节
static void rot_word(unsigned char *word) {
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

// SubWord：对 4 字节字应用 S 盒
static void sub_word(unsigned char *word) {
    word[0] = sbox[word[0]];
    word[1] = sbox[word[1]];
    word[2] = sbox[word[2]];
    word[3] = sbox[word[3]];
}

// KEYEXPANSION()：密钥扩展
void key_expansion(unsigned char *key, unsigned char w[4][NB * (NR + 1)], int nk) {
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14; // 根据密钥长度确定轮数
    unsigned char temp[4];
    int i = 0;

    // 初始化前 Nk 个字
    while (i <= nk - 1) {
        w[0][i] = key[4 * i];
        w[1][i] = key[4 * i + 1];
        w[2][i] = key[4 * i + 2];
        w[3][i] = key[4 * i + 3];
        i = i + 1;
    }

    // 生成剩余字
    while (i <= 4 * nr + 3) {
        temp[0] = w[0][i - 1];
        temp[1] = w[1][i - 1];
        temp[2] = w[2][i - 1];
        temp[3] = w[3][i - 1];

        if (i % nk == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= rcon[i / nk - 1];
        } else if (nk > 6 && i % nk == 4) {
            sub_word(temp);
        }

        w[0][i] = w[0][i - nk] ^ temp[0];
        w[1][i] = w[1][i - nk] ^ temp[1];
        w[2][i] = w[2][i - nk] ^ temp[2];
        w[3][i] = w[3][i - nk] ^ temp[3];
        i = i + 1;
    }
}

// SUBBYTES()
void sub_bytes(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = sbox[state[r][c]];
        }
    }
}

// SHIFTROWS()
void shift_rows(unsigned char state[4][NB]) {
    unsigned char temp[4][NB];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            temp[r][c] = state[r][(c + r) % NB];
        }
    }
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            state[r][c] = temp[r][c];
        }
    }
}

// MIXCOLUMNS()
void mix_columns(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        unsigned char s0 = state[0][c],
                      s1 = state[1][c],
                      s2 = state[2][c],
                      s3 = state[3][c];
        unsigned char s0p = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3,
                      s1p = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3,
                      s2p = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3,
                      s3p = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
        state[0][c] = s0p;
        state[1][c] = s1p;
        state[2][c] = s2p;
        state[3][c] = s3p;
    }
}

// ADDROUNDKEY()
void add_round_key(unsigned char state[4][NB], unsigned char *round_key) {
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= round_key[r + c * 4];
        }
    }
}

// INVSUBBYTES()
void inv_sub_bytes(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = inv_sbox[state[r][c]];
        }
    }
}

// INVSHIFTROWS()
void inv_shift_rows(unsigned char state[4][NB]) {
    unsigned char temp[4][NB];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            temp[r][c] = state[r][(c - r + NB) % NB];
        }
    }
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            state[r][c] = temp[r][c];
        }
    }
}

// INVMIXCOLUMNS()
void inv_mix_columns(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        unsigned char s0 = state[0][c],
                      s1 = state[1][c],
                      s2 = state[2][c],
                      s3 = state[3][c];
        unsigned char s0_2 = xtime(s0),
                      s0_4 = xtime(s0_2),
                      s0_8 = xtime(s0_4);
        unsigned char s1_2 = xtime(s1),
                      s1_4 = xtime(s1_2),
                      s1_8 = xtime(s1_4);
        unsigned char s2_2 = xtime(s2),
                      s2_4 = xtime(s2_2),
                      s2_8 = xtime(s2_4);
        unsigned char s3_2 = xtime(s3),
                      s3_4 = xtime(s3_2),
                      s3_8 = xtime(s3_4);
        unsigned char s0p = s0_8 ^ s0_4 ^ s0_2 ^ s0 ^ s1_8 ^ s1_2 ^ s1 ^ s2_8 ^ s2_4 ^ s2 ^ s3_8 ^ s3,
                      s1p = s0_8 ^ s0 ^ s1_8 ^ s1_4 ^ s1_2 ^ s1 ^ s2_8 ^ s2_2 ^ s2 ^ s3_8 ^ s3_4 ^ s3,
                      s2p = s0_8 ^ s0_2 ^ s0 ^ s1_8 ^ s1 ^ s2_8 ^ s2_4 ^ s2_2 ^ s2 ^ s3_8 ^ s3_4 ^ s3,
                      s3p = s0_8 ^ s0_4 ^ s0 ^ s1_8 ^ s1_4 ^ s1 ^ s2_8 ^ s2 ^ s3_8 ^ s3_2 ^ s3;
        state[0][c] = s0p;
        state[1][c] = s1p;
        state[2][c] = s2p;
        state[3][c] = s3p;
    }
}

// CIPHER()：加密函数
void cipher(unsigned char *in, unsigned char *out, int nr, unsigned char w[4][NB * (NR + 1)]) {
    unsigned char state[4][NB];
    int r, c;

    // 初始化状态
    for (c = 0; c < NB; c++) {
        for (r = 0; r < 4; r++) {
            state[r][c] = in[r + c * 4];
        }
    }

    // 初始轮
    add_round_key(state, &w[0][0]);

    // 主循环
    for (int round = 1; round <= nr - 1; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &w[0][4 * round]);
    }

    // 最后一轮
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &w[0][4 * nr]);

    // 输出结果
    for (c = 0; c < NB; c++) {
        for (r = 0; r < 4; r++) {
            out[r + c * 4] = state[r][c];
        }
    }
}

// INVCIPHER()：解密函数
void inv_cipher(unsigned char *in, unsigned char *out, int nr, unsigned char w[4][NB * (NR + 1)]) {
    unsigned char state[4][NB];
    int r, c;

    // 初始化状态
    for (c = 0; c < NB; c++) {
        for (r = 0; r < 4; r++) {
            state[r][c] = in[r + c * 4];
        }
    }

    // 初始轮
    add_round_key(state, &w[0][4 * nr]);

    // 主循环
    for (int round = nr - 1; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &w[0][4 * round]);
        inv_mix_columns(state);
    }

    // 最后一轮
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &w[0][0]);

    // 输出结果
    for (c = 0; c < NB; c++) {
        for (r = 0; r < 4; r++) {
            out[r + c * 4] = state[r][c];
        }
    }
}

// AES-128、AES-192、AES-256 加密接口
void aes_encrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk) {
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    unsigned char w[4][NB * (NR + 1)];
    key_expansion(key, w, nk);
    cipher(in, out, nr, w);
}

// AES-128、AES-192、AES-256 解密接口
void aes_decrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk) {
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    unsigned char w[4][NB * (NR + 1)];
    key_expansion(key, w, nk);
    inv_cipher(in, out, nr, w);
}
