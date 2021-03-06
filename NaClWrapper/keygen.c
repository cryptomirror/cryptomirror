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

#ifdef STANDALONE
#include <unistd.h>
#include <fcntl.h>

void usage()
{
    printf("./program -p public_key_output_path -s secret_key_output_path\n");
    exit(0);
}
int main(int argc, char *argv[])
{
    int fd, ch;
    char *pubkey = "cryptobox.publickey";
    char *seckey = "cryptobox.secretkey";
    unsigned char *pk, *sk;
    genkey(&pk, &sk);
     
    while ((ch = getopt(argc, argv, "p:s:")) != -1) {
         switch (ch) {
         case 'p':
                 pubkey = optarg;
                 break;
         case 's':
                 seckey = optarg;
                 break;
         case '?':
         default:
                 usage();
         }
    }
    
    fd = open(pubkey, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "Could not open pubkey output file: %s\n", pubkey);
        return 1;
    }
    write(fd, pk, crypto_box_PUBLICKEYBYTES);    
    close(fd);

    fd = open(seckey, O_CREAT|O_TRUNC|O_WRONLY, 0600);
    if (fd == -1)
    {
        fprintf(stderr, "Could not open seckey output file: %s\n", seckey);
        return 2;
    }
    write(fd, sk, crypto_box_SECRETKEYBYTES);    
    close(fd);
    
    release_mem(pk);
    release_mem(sk);

    return 0;
}
#endif