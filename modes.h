// modes.h
#ifndef MODES_H
#define MODES_H

#define NB 4
int nk;
unsigned int w[60];

void ecb_encrypt(unsigned char *in, unsigned char *out, int len);
void ecb_decrypt(unsigned char *in, unsigned char *out, int len);
void cbc_encrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv);
void cbc_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv);
void cfb_encrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv);
void cfb_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv);
void ofb_encrypt_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char *iv);
int compare_blocks(unsigned char *block1, unsigned char *block2);

#endif
