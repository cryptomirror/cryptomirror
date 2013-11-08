#include "common.h"
#include "nacl.h"

/*
*/
int
nacl_encrypt(unsigned char *sender_sk, unsigned char *receiver_pk,
        unsigned char *m, unsigned long *plength, 
        unsigned char **nonce, unsigned char **ciphertext)
{
    unsigned char *message;
    int ret;
    unsigned long cLen, length = *plength;
    unsigned char *ciphered;
    
    if (length > (1<<30LL))
    {
        //
        // Too long
        // 
        return -1;
    }

    cLen = length + crypto_box_ZEROBYTES;

    ciphered = allocate_mem(cLen, 0);
    if (ciphered == NULL)
    {
        return ENOMEM;
    }
    
    *nonce = allocate_mem(crypto_box_NONCEBYTES, 0);
    if (*nonce == NULL)
    {
        release_mem(ciphered);
        ciphered = NULL;
        return ENOMEM;
    }

    randombytes(*nonce, crypto_box_NONCEBYTES);

    //
    // "the first crypto_box_ZEROBYTES bytes of the message m are all 0"
    //
    message = allocate_mem(cLen, 0);
    if (message == NULL)
    {
        release_mem(*nonce);
        release_mem(ciphered);
        *nonce = ciphered = NULL;
        return ENOMEM;        
    }
    
    memcpy(message + crypto_box_ZEROBYTES, m, length);

    ret = crypto_box(ciphered, message, cLen, *nonce, receiver_pk, sender_sk);

    release_mem(message);

    if (ret == 0)
    {
        //
        // Skip the first crypto_box_BOXZEROBYTES.
        // The wrapper will add them back in.
        //
        int i;
        for (i = 0; i < crypto_box_BOXZEROBYTES; i++)
        {
            if (ciphered[i] != 0)
            {
                abort();
            }
        }
        *ciphertext = allocate_mem(cLen - crypto_box_BOXZEROBYTES, 0);
        if (ciphertext == NULL)
        {
            ret = ENOMEM;
        }
        else
        {
            memcpy(*ciphertext,
                   ciphered + crypto_box_BOXZEROBYTES,
                   cLen - crypto_box_BOXZEROBYTES);
            *plength = cLen - crypto_box_BOXZEROBYTES;
        }
    }
    
    release_mem(ciphered);
    
    return ret;
}
