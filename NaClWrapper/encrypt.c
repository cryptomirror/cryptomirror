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
    unsigned long length = *plength;
    
    if (length > (1<<30LL))
    {
        //
        // Too long
        // 
        return -1;
    }

    *plength = length + crypto_box_ZEROBYTES;

    *ciphertext = allocate_mem(*plength, 0);
    if (*ciphertext == NULL)
    {
        return ENOMEM;
    }
    
    *nonce = allocate_mem(crypto_box_NONCEBYTES, 0);
    if (*nonce == NULL)
    {
        release_mem(*ciphertext);
        *ciphertext = NULL;
        return ENOMEM;
    }

    randombytes(*nonce, crypto_box_NONCEBYTES);

    //
    // "the first crypto_box_ZEROBYTES bytes of the message m are all 0"
    //
    message = allocate_mem(*plength, 0);
    if (message == NULL)
    {
        release_mem(*nonce);
        release_mem(*ciphertext);
        *nonce = *ciphertext = NULL;
        return ENOMEM;        
    }
    
    memcpy(message + crypto_box_ZEROBYTES, m, length);

    ret = crypto_box(*ciphertext, message, *plength, *nonce, receiver_pk, sender_sk);

    release_mem(message);
    
    return ret;
}
