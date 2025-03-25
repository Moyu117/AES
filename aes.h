// aes.h
#ifndef AES_H
#define AES_H
#define NB 4
#define NR 14 // 最大轮数（256 位密钥）

void key_expansion(unsigned char *key, int w[NB * (NR + 1)], int nk);
void key_expansion_eic(unsigned char *key, int dw[NB * (NR + 1)], int nk);
void cipher(unsigned char *in, unsigned char *out, int nr, int w[NB * (NR + 1)]);
void inv_cipher(unsigned char *in, unsigned char *out, int nr, int w[NB * (NR + 1)]);
void eq_inv_cipher(unsigned char *in, unsigned char *out, int nr, int dw[NB * (NR + 1)]);
void aes_encrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk);
void aes_decrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk);
void aes_eq_decrypt(unsigned char *in, unsigned char *key, unsigned char *out, int nk);

#endif
