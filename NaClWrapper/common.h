#include <errno.h>
#include <stdlib.h>
#include <string.h>

void* allocate_mem(unsigned long size, unsigned long flag);
void release_mem(void *ptr);

int
genkey(unsigned char **pk, unsigned char **sk);

int
encrypt(unsigned char *sender_sk, unsigned char *receiver_pk, 
        unsigned char *m, unsigned long *plength, 
        unsigned char **nonce, unsigned char **ciphertext);

int
decrypt(unsigned char *sender_pk, unsigned char *receiver_sk,
        unsigned char *nonce, unsigned char *ciphertext, 
        unsigned long len,
        unsigned char **message);

        