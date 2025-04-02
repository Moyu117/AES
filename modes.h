#ifndef MODES_H
#define MODES_H

#include <stddef.h>

// 这里放置对外可见的函数声明
void ECB_Encrypt(const unsigned char *K, const unsigned char *P, unsigned char *C, unsigned int num_blocks);
void ECB_Decrypt(const unsigned char *K, const unsigned char *C, unsigned char *P, unsigned int num_blocks);
void CBC_Encrypt(const unsigned char *K, const unsigned char *IV, const unsigned char *P, unsigned char *C, unsigned int num_blocks);
void CBC_Decrypt(const unsigned char *K, const unsigned char *IV, const unsigned char *C, unsigned char *P, unsigned int num_blocks);
void CMAC(const unsigned char *K, const unsigned char *M, unsigned int Mlen, unsigned int Tlen, unsigned char *T);
int VER(const unsigned char *K, const unsigned char *M, unsigned int Mlen, unsigned int Tlen, const unsigned char *T_received);

#endif
