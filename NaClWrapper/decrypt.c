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
    
    return crypto_box_open(*message, ciphertext, len, nonce, sender_pk, receiver_sk);
}