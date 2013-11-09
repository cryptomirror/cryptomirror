#include "common.h"
#include "nacl.h"

int
nacl_decrypt(unsigned char *sender_pk, unsigned char *receiver_sk,
        unsigned char *nonce, unsigned char *ciphertext, 
        unsigned long len,
        unsigned char **message)
{
    unsigned int ret;
    unsigned char *ciphered;
    unsigned long cLen;
    
    cLen = len + crypto_box_BOXZEROBYTES;
    
    ciphered = allocate_mem(cLen, 0);
    if (ciphered == NULL)
    {
        return ENOMEM;
    }
    
    //
    // Add back in crypto_box_BOXZEROBYTES of NUL
    // bytes at the start
    //    
    memcpy(ciphered + crypto_box_BOXZEROBYTES, ciphertext, len);
    
    *message = allocate_mem(cLen, 0);
    if (*message == NULL)
    {
        release_mem(ciphered);
        return ENOMEM;
    }
    
    ret = crypto_box_open(*message, ciphered, cLen, nonce, sender_pk, receiver_sk);
    
    release_mem(ciphered);
    
    return ret;
}