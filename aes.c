// aes.c
#include "aes.h"
#define NB 4

int nk;
unsigned int w[60];

static const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
      0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
      0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
      0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
      0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
      0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
      0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
      0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
      0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
      0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
      0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
      0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
      0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
      0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
      0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
      0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// 逆S盒（用于解密的InvSubBytes）
static const unsigned char inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38, 0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
      0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87, 0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
      0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D, 0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
      0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2, 0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
      0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16, 0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
      0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA, 0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
      0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A, 0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
      0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02, 0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
      0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA, 0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
      0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85, 0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
      0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89, 0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
      0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20, 0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
      0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31, 0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
      0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D, 0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
      0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0, 0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
      0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26, 0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// 轮常数（支持最多 14 轮，256 位密钥）
static const unsigned char rcon[14] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d
};

static int getBit(unsigned char n, int pos);
static unsigned char xtime(unsigned char n);
static int rot_word(int word);
static int sub_word(int word);
static void sub_bytes(unsigned char state[4][NB]);
static void shift_rows(unsigned char state[4][NB]);
static void mix_columns(unsigned char state[4][NB]);
static void add_round_key(unsigned char state[4][NB], int round);
static void inv_sub_bytes(unsigned char state[4][NB]);
static void inv_shift_rows(unsigned char state[4][NB]);
static void inv_mix_columns(unsigned char state[4][NB]);


// 获取某位（辅助函数）
static int getBit(unsigned char n, int pos) {
    return (n >> pos) & 1;
}

// xtime 函数（Galois 域乘 2）
static unsigned char xtime(unsigned char n) {
    if (getBit(n, 7) == 1) {
        n = n << 1;
        n ^= 27; // 0x1b
    } else {
        n = n << 1;
    }
    return n;
}

// RotWord：循环左移 1 字节
static int rot_word(int word) {
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF);
}

// SubWord：对 4 字节字应用 S 盒
static int sub_word(int word) {
    unsigned char bytes[4];
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;
    return (sbox[bytes[0]] << 24) | (sbox[bytes[1]] << 16) | (sbox[bytes[2]] << 8) | sbox[bytes[3]];
}

// KEYEXPANSION()：标准密钥扩展 unsigned int
void key_expansion(unsigned char *key) {
    int temp;
    int i;
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    // 初始化前 Nk 个字
    for(i = 0;i < nk; i++){
        w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }
    // 生成剩余字
    for (i = nk; i < NB * (nr + 1); i++) {
            int temp = w[i - 1];
            if (i % nk == 0) {
                temp = sub_word(rot_word(temp)) ^ (rcon[i / nk - 1] << 24);
            } else if (nk > 6 && i % nk == 4) {
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
}

// KEYEXPANSIONEIC()：等效逆密码的密钥扩展
void key_expansion_eic(unsigned char *key) {
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    int i;
    
    // 第一步：执行标准密钥扩展（与 key_expansion 相同）
    for (i = 0; i < nk; i++) {
        w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }
    
    for (i = nk; i < NB * (nr + 1); i++) {
        int temp = w[i - 1];
        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ (rcon[i / nk - 1] << 24);
        } else if (nk > 6 && i % nk == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }
    
    // 第二步：对 w[NB] 到 w[(Nr-1)*NB] 应用 InvMixColumns
    for (int round = 1; round < nr; round++) {
        unsigned char temp_state[4][NB] = {{0}};
        // 将当前轮的 4 个字转换为状态数组
        for (int c = 0; c < NB; c++) {
            unsigned int word = (unsigned int)w[round * NB + c];
            temp_state[0][c] = (word >> 24) & 0xFF;
            temp_state[1][c] = (word >> 16) & 0xFF;
            temp_state[2][c] = (word >> 8) & 0xFF;
            temp_state[3][c] = word & 0xFF;
        }
        // 应用 InvMixColumns
        inv_mix_columns(temp_state);
        // 将结果写回 w
        for (int c = 0; c < NB; c++) {
            w[round * NB + c] = (temp_state[0][c] << 24) | (temp_state[1][c] << 16) | (temp_state[2][c] << 8) | temp_state[3][c];
        }
    }
}

// SUBBYTES()
static void sub_bytes(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = sbox[state[r][c]];
        }
    }
}

// SHIFTROWS()
static void shift_rows(unsigned char state[4][NB]) {
    unsigned char temp;
    // 第 1 行：左移 1 字节
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // 第 2 行：左移 2 字节
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第 3 行：左移 3 字节（等价于右移 1 字节）
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// MIXCOLUMNS()
static void mix_columns(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        unsigned char s0 = state[0][c];
        unsigned char s1 = state[1][c];
        unsigned char s2 = state[2][c];
        unsigned char s3 = state[3][c];

        unsigned char t0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;  // 02*s0 + 03*s1 + 01*s2 + 01*s3
        unsigned char t1 = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;  // 01*s0 + 02*s1 + 03*s2 + 01*s3
        unsigned char t2 = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);  // 01*s0 + 01*s1 + 02*s2 + 03*s3
        unsigned char t3 = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);  // 03*s0 + 01*s1 + 01*s2 + 02*s3

        state[0][c] = t0;
        state[1][c] = t1;
        state[2][c] = t2;
        state[3][c] = t3;
    }
}

// ADDROUNDKEY()
static void add_round_key(unsigned char state[4][NB], int round) {
    for (int c = 0; c < NB; c++) {
        unsigned int word = (unsigned int)w[round * NB + c];
        state[0][c] ^= (word >> 24) & 0xFF;
        state[1][c] ^= (word >> 16) & 0xFF;
        state[2][c] ^= (word >> 8) & 0xFF;
        state[3][c] ^= word & 0xFF;
    }
}

// INVSUBBYTES()
static void inv_sub_bytes(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = inv_sbox[state[r][c]];
        }
    }
}

// INVSHIFTROWS()
static void inv_shift_rows(unsigned char state[4][NB]) {
    unsigned char temp;
    // 第 1 行：右移 1 字节
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // 第 2 行：右移 2 字节
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第 3 行：右移 3 字节（等价于左移 1 字节）
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// INVMIXCOLUMNS()
static void inv_mix_columns(unsigned char state[4][NB]) {
    for (int c = 0; c < NB; c++) {
        unsigned char s0 = state[0][c];
        unsigned char s1 = state[1][c];
        unsigned char s2 = state[2][c];
        unsigned char s3 = state[3][c];

        unsigned char s0_2 = xtime(s0);
        unsigned char s0_4 = xtime(s0_2);
        unsigned char s0_8 = xtime(s0_4);
        unsigned char s1_2 = xtime(s1);
        unsigned char s1_4 = xtime(s1_2);
        unsigned char s1_8 = xtime(s1_4);
        unsigned char s2_2 = xtime(s2);
        unsigned char s2_4 = xtime(s2_2);
        unsigned char s2_8 = xtime(s2_4);
        unsigned char s3_2 = xtime(s3);
        unsigned char s3_4 = xtime(s3_2);
        unsigned char s3_8 = xtime(s3_4);

        unsigned char t0 = (s0_8 ^ s0_4 ^ s0_2) ^ (s1_8 ^ s1_2 ^ s1) ^ (s2_8 ^ s2_4 ^ s2) ^ (s3_8 ^ s3);
        unsigned char t1 = (s0_8 ^ s0) ^ (s1_8 ^ s1_4 ^ s1_2) ^ (s2_8 ^ s2_2 ^ s2) ^ (s3_8 ^ s3_4 ^ s3);
        unsigned char t2 = (s0_8 ^ s0_2 ^ s0) ^ (s1_8 ^ s1) ^ (s2_8 ^ s2_4 ^ s2_2) ^ (s3_8 ^ s3_4 ^ s3);
        unsigned char t3 = (s0_8 ^ s0_4 ^ s0) ^ (s1_8 ^ s1_4 ^ s1) ^ (s2_8 ^ s2) ^ (s3_8 ^ s3_2 ^ s3);

        state[0][c] = t0;
        state[1][c] = t1;
        state[2][c] = t2;
        state[3][c] = t3;
    }
}

// CIPHER()：加密函数
void cipher(unsigned char *in, unsigned char *out) {
    unsigned char state[4][NB];
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;

    // 初始化状态
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = in[r + c * 4];
        }
    }
    // 初始轮
    add_round_key(state, 0);

    // 主循环
    for (int round = 1; round <= nr; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round);
    }
    // 最后一轮
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, nr);

    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            out[r + c * 4] = state[r][c];
        }
    }
}

// INVCIPHER()：解密函数
void inv_cipher(unsigned char *in, unsigned char *out) {
    unsigned char state[4][NB];
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    // 初始化状态
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = in[r + c * 4];
        }
    }

    // 初始轮
    add_round_key(state, nr);

    // 主循环
    for (int round = nr - 1; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round);
        inv_mix_columns(state);
    }

    // 最后一轮
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, 0);

    // 输出结果
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            out[r + c * 4] = state[r][c];
        }
    }
}

// EQINVCIPHER()：等效逆密码
void eq_inv_cipher(unsigned char *in, unsigned char *out) {
    unsigned char state[4][NB];
    int nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    
    // 输入到状态
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = in[r + c * 4];
        }
    }
    
    // 初始轮密钥加（使用最后一轮密钥）
    add_round_key(state, nr);
    
    // 主轮（省略 InvMixColumns，因为已合并到轮密钥中）
    for (int round = nr - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round);  // 使用等价轮密钥
    }
    
    // 最后一轮
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, 0);
    
    // 状态到输出
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            out[r + c * 4] = state[r][c];
        }
    }
}
