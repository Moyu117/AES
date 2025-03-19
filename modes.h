// modes.h
#ifndef MODES_H
#define MODES_H

void ecb_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int len, int nk);
void ecb_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int len, int nk, int use_eq);
void cbc_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int len, int nk);
void cbc_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int len, int nk, int use_eq);
void cmac(unsigned char *message, unsigned char *key, unsigned char *mac, int len, int nk);

#endif
