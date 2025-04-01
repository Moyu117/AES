// aes.h
#ifndef AES_H
#define AES_H

#define NB 4

extern int nk;
extern unsigned int w[60];
void key_expansion(unsigned char *key);
void key_expansion_eic(unsigned char *key);
void cipher(unsigned char *in, unsigned char *out);
void inv_cipher(unsigned char *in, unsigned char *out);
void eq_inv_cipher(unsigned char *in, unsigned char *out);

#endif
