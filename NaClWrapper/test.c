#include "nacl.h"
#include "common.h"

#ifdef ENCTEST
#include <assert.h>

#include <stdio.h>
#include "crypto_box.h"
void doit()
{

unsigned char alicesk[crypto_box_SECRETKEYBYTES];
unsigned char alicepk[crypto_box_PUBLICKEYBYTES];
unsigned char bobsk[crypto_box_SECRETKEYBYTES];
unsigned char bobpk[crypto_box_PUBLICKEYBYTES];
unsigned char n[crypto_box_NONCEBYTES];
unsigned char m[10000];
unsigned char c[10000];
unsigned char m2[10000];

{
  int mlen;
  int i;

  for (mlen = 0;mlen < 1000 && mlen + crypto_box_ZEROBYTES < sizeof m;++mlen) {
    crypto_box_keypair(alicepk,alicesk);
    crypto_box_keypair(bobpk,bobsk);
    randombytes(n,crypto_box_NONCEBYTES);
    randombytes(m + crypto_box_ZEROBYTES,mlen);
    crypto_box(c,m,mlen + crypto_box_ZEROBYTES,n,bobpk,alicesk);
    if (crypto_box_open(m2,c,mlen + crypto_box_ZEROBYTES,n,alicepk,bobsk) == 0) {
      for (i = 0;i < mlen + crypto_box_ZEROBYTES;++i)
        if (m2[i] != m[i]) {
	  printf("[-] bad decryption\n");
	  break;
	}
    } else {
      printf("[-] ciphertext fails verification\n");
    }
  }
}
}

int main()
{
    unsigned char *pk1, *pk2, *sk1, *sk2;
    int ret;
    
    doit();
    
    //
    // Generate two private keys
    //
    ret = genkey(&pk1, &sk1);
    assert(ret == 0);
    ret = genkey(&pk2, &sk2);
    assert(ret == 0);

    //
    //  Encrypt a message from keypair 1 to keypair 2
    //
    unsigned char *msg = (unsigned char*)"hello secret world";
    unsigned char *nonce, *ciphered;
    unsigned long clen;

    clen = strlen((char *)msg);
    ret = encrypt(sk1, pk2, msg, &clen, &nonce, &ciphered);
    assert(ret == 0);

    //
    // Decrypt the message 
    //
    unsigned char *plain;
    ret = decrypt(pk1, sk2, nonce, ciphered, clen, &plain);
    assert(ret == 0);

    //
    // Verify they match
    //
    if (!strcmp((char *)plain, (char *)msg))
    {
        printf("%s vs %s\n", plain, msg);
    }
    else
    {    
        printf("[+] Matched plaintext\n");
    }

} 
#endif