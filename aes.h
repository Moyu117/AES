#ifndef AES_H
#define AES_H
#define NB 4
#define NR 14 // 最大轮数（256 位密钥）

void key_expansion(unsigned char *key, unsigned char w[4][NB * (NR + 1)], int nk);
void cipher(unsigned char *in, unsigned char *out, int nr, unsigned char w[4][NB * (NR + 1)]);
void inv_cipher(unsigned char *in, unsigned char *out, int nr, unsigned char w[4][NB * (NR + 1)]);
void aes_encrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk);
void aes_decrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk);

#endif
