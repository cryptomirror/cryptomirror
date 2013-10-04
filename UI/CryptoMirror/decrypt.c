#include "common.h"
#include "nacl.h"

int
nacl_decrypt(unsigned char *sender_pk, unsigned char *receiver_sk,
        unsigned char *nonce, unsigned char *ciphertext, 
        unsigned long len,
        unsigned char **message)
{
    unsigned int i;
    //
    // Verify that the first crypto_box_BOXZEROBYTES of ciphertext are 0
    //
    for (i = 0; i < crypto_box_BOXZEROBYTES; i++)
    {
        if (ciphertext[i] != 0)
        {
            return -1;
        }
    }
    
    *message = allocate_mem(len, 0);
    if (*message == NULL)
    {
        return ENOMEM;
    }

#ifdef DMPDECRYPT
    printf("DECRYPTED NONCE: ");
    for (i = 0; i <  crypto_box_NONCEBYTES; i++)
    {
        printf("%.2x ", (nonce)[i]&0xff);
    }
    printf("\n");
    printf("DECRYPTED CIPHERTEXT: ");
    for (i = 0; i <  len; i++)
    {
        printf("%.2x ", (ciphertext)[i]&0xff);
    }
    printf("\n");
#endif
    return crypto_box_open(*message, ciphertext, len, nonce, sender_pk, receiver_sk);
}