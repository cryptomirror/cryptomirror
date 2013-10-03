#include <stdio.h>
#include "common.h"
#include "nacl.h"

unsigned char pk[crypto_box_PUBLICKEYBYTES];
unsigned char sk[crypto_box_SECRETKEYBYTES];

/*
 Generate a keypair ; return 0 on success.
 
 Caller must take care to store the secret key securely
 and then release the memory 
*/
int
genkey(unsigned char **pk, unsigned char **sk)
{
    int ret;
    
    *pk = allocate_mem(crypto_box_PUBLICKEYBYTES, 0);
    if (*pk == NULL)
    {
        return ENOMEM;
    }

    *sk = allocate_mem(crypto_box_SECRETKEYBYTES, 0);
    if (*sk == NULL)
    {
        release_mem(*pk);
        *pk = NULL;
        return ENOMEM;
    }

    ret = crypto_box_keypair(*pk,*sk);
    if (ret != 0)
    {
        release_mem(*sk);
        release_mem(*pk);
        *sk = *pk = NULL;
        return -1;
    }

#ifdef DUMPKEYS
    int i;
    printf("sec = %d\n", crypto_box_SECRETKEYBYTES);
    for(i = 0; i < crypto_box_SECRETKEYBYTES; i++)
    {
        printf("%.2x ", (*sk)[i] & 0xff);
    }
    printf("\n");
    printf("pub = %d\n", crypto_box_PUBLICKEYBYTES);
    for(i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
    {
        printf("%.2x ", (*pk)[i] & 0xff);
    }
    printf("\n");
#endif
    
    return ret;    
}

#ifdef GENTEST
int main(int argc, char *argv[])
{
    unsigned char *pk, *sk;
    genkey(&pk, &sk);
    release_mem(pk);
    release_mem(sk);
}
#endif