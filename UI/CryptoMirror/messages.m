#include "nacl.h"
#include "common.h"
#include "messages.h"
#include "blobber.h"


char *
create_pubkey_message(char *sender_nickname, unsigned char *pubkey)
{
    char *blob;
    unsigned char *raw;
    unsigned int *len;
    char *name;
    unsigned int alloc_size;
    
    blob = NULL;
    raw = NULL;
    
    //
    // [V|T][Nick Len][Nickname\0][PubLen][PubKey]
    //
    alloc_size = sizeof(unsigned int)*2 + strlen(sender_nickname) + 1 + 1 + crypto_box_PUBLICKEYBYTES;
    raw = malloc(alloc_size);
    if (raw == NULL)
    {
        goto End;
    }
    len = (unsigned int *)raw;
    //
    // Message type 0 is only a public key
    //
    *len = (0<<16) | (publicKeyOnly & 0xffff);
    len++;
    
    //
    // Nickname length
    //
    *len = (unsigned int) strlen(sender_nickname);
    name = (char *)(len + 1);
    //
    // Write the nickname with the NUL byte there too
    //
    strlcpy(name, sender_nickname, strlen(sender_nickname) + 1);

    //
    // Set the pubkey size
    //
    raw[alloc_size - crypto_box_PUBLICKEYBYTES - 1] = crypto_box_PUBLICKEYBYTES;

    //
    // Copy the pubkey at the end
    //
    memcpy(raw + alloc_size - crypto_box_PUBLICKEYBYTES, pubkey, crypto_box_PUBLICKEYBYTES);
    
    blob = make_blob_string(raw, alloc_size);
    
End:
    return blob;
}

char *
create_encrypted_message(char *sender_nickname, unsigned char *sender_pubkey,
                         unsigned char *sender_secretkey, unsigned char *dest_publickey,
                         unsigned char *message, unsigned int msgSize)
{
    char *blob;
    unsigned char *raw, *next;
    unsigned int *len;
    char *name;
    unsigned int alloc_size;
    unsigned long cipherTextSize;
    unsigned char *nonce, *ciphertext;
    int ret;
    
    blob = NULL;
    raw = NULL;
    
    //
    // Prepare the encrypted message for starters
    //
    cipherTextSize = msgSize;
    ret = nacl_encrypt(sender_secretkey, dest_publickey,
                       message, &cipherTextSize, &nonce, &ciphertext);
    if (ret != 0)
    {
        NSLog(@"Encryption failure");
        goto End;
    }
    
    //
    // [V|T][Nick Len][Nickname\0][SndrPubLen][SndrPubKey][RcvrPubLen][RcvrPubKey][NonceLen][Nonce][CipherLen][Cipher]
    //
    alloc_size = sizeof(unsigned int)*2 + strlen(sender_nickname) + 1 + 1*2 + crypto_box_PUBLICKEYBYTES*2;
    alloc_size += 1 + crypto_box_NONCEBYTES + sizeof(unsigned int) + cipherTextSize;
    raw = malloc(alloc_size);
    if (raw == NULL)
    {
        goto End;
    }
    len = (unsigned int *)raw;
    
    //
    // Message type 1 is a whole encrypted message
    //
    *len = (0<<16) | (encryptedWholeMessage & 0xffff);
    len++;
    
    //
    // Nickname length
    //
    *len = (unsigned int)strlen(sender_nickname);
    name = (char *)(len + 1);
    //
    // Write the nickname with the NUL byte there too
    //
    strlcpy(name, sender_nickname, strlen(sender_nickname) + 1);
    
    next = (unsigned char *)(name + strlen(sender_nickname) + 1);

    //
    // Set the sender pub key len and value
    //
    next[0] = crypto_box_PUBLICKEYBYTES;
    memcpy(next + 1, sender_pubkey, crypto_box_PUBLICKEYBYTES);

    next = next + 1 + crypto_box_PUBLICKEYBYTES;

    //
    // Set the rcvr pub key len and value
    //
    next[0] = crypto_box_PUBLICKEYBYTES;
    memcpy(next + 1, dest_publickey, crypto_box_PUBLICKEYBYTES);
    next = next + 1 + crypto_box_PUBLICKEYBYTES;

    //
    // Copy the nonce length and value
    //
    next[0] = crypto_box_NONCEBYTES;
    memcpy(next + 1, nonce, crypto_box_NONCEBYTES);
    next = next + 1 + crypto_box_NONCEBYTES;
    
    //
    // Copy the ciphertext length and value
    //
    len = (unsigned int *)next;
    *len = (unsigned int)cipherTextSize;
    memcpy(next + sizeof(unsigned int), ciphertext, cipherTextSize);

    //
    // Print out the raw blob from ciphertext on
    //
    /*
    printf("nonce + ciphertext sent =\n");
    int i;
    for (i = 0; i < cipherTextSize + crypto_box_NONCEBYTES; i++)
    {
        printf("%.2x ", next[i - crypto_box_NONCEBYTES]&0xff);
    }
    printf("\n");
     */

    next = next + sizeof(unsigned int) + cipherTextSize;
    if (next != (raw + alloc_size))
    {
        printf("SIZE MISMATCH %ld vs %d\n", next-raw, alloc_size);
    }
    
    blob = make_blob_string(raw, alloc_size);
    
End:
    return blob;
}

//
// Parse a mirror blob to import a key or decrypt an encrypted message
// or both at the same time.
//
int
parse_message(char *msg_in, char **sender_nickname, unsigned char **sender_publickey, unsigned char **receiver_publickey, unsigned char **sender_ciphertext, unsigned long *cipherlen)
{
    int messageType;
    unsigned char *next;
    unsigned char *decoded;
    unsigned int size;
    unsigned int *len;
    int ret;
    unsigned short version, type;
    unsigned int nickLen;
    unsigned char *end;
    unsigned char *nonce;
    unsigned int cipherTextSize;
    
    messageType = -1;

    ret = decode_blob_string(msg_in, &decoded, &size);
    if (ret != 0)
    {
        goto End;
    }
    
    end = decoded + size;
    next = decoded;
    len = (unsigned int *)next;
    
    //
    // Get version & type
    //
    version = len[0] >> 16;
    type = len[0] & 0xffff;
    
    if (version != 0)
    {
        goto End;
    }
    if ((type != publicKeyOnly) && (type != encryptedWholeMessage))
    {
        goto End;
    }
    //
    // Grab the nickname
    //
    nickLen = len[1];
    if ((nickLen == 0) || (nickLen > BLOB_SIZE_LIMIT))
    {
        goto End;
    }
    next = (unsigned char *)(&len[2]);
    if (next + nickLen > end)
    {
        goto End;
    }

    *sender_nickname = malloc(nickLen + 1);
    if (*sender_nickname == NULL)
    {
        goto End;
    }

    strlcpy(*sender_nickname, (char *)next, nickLen + 1);
    
    next = next + nickLen + 1;
    //
    // Grab the sender's public key
    //
    if ((next + 1 + crypto_box_PUBLICKEYBYTES) > end)
    {
        goto End;
    }
    if (next[0] != crypto_box_PUBLICKEYBYTES)
    {
        goto End;
    }
    *sender_publickey = malloc(crypto_box_PUBLICKEYBYTES);
    if(!*sender_publickey) goto End;
    memcpy(*sender_publickey, next + 1, crypto_box_PUBLICKEYBYTES);
    next = next + 1 + crypto_box_PUBLICKEYBYTES;
    
    //
    // If type 'encryptedWholeMessage', more data should be available.
    //
    if (type != encryptedWholeMessage)
    {
        messageType = type;
        goto End;
    }

    //
    // Grab the sender's public key
    //
    if ((next + 1 + crypto_box_PUBLICKEYBYTES) > end)
    {
        goto End;
    }
    if (next[0] != crypto_box_PUBLICKEYBYTES)
    {
        goto End;
    }
    *receiver_publickey = malloc(crypto_box_PUBLICKEYBYTES);
    if(!*receiver_publickey) goto End;
    memcpy(*receiver_publickey, next + 1, crypto_box_PUBLICKEYBYTES);
    next = next + 1 + crypto_box_PUBLICKEYBYTES;

    //
    // Grab the nonce
    //
    if ((next + 1 + crypto_box_NONCEBYTES) > end)
    {
        goto End;
    }
    if (next[0] != crypto_box_NONCEBYTES)
    {
        goto End;
    }
    nonce = &next[1];
    next = next + 1 + crypto_box_NONCEBYTES;
    
    //
    // Grab the ciphertext
    //
    len = (unsigned int *)next;
    next = (unsigned char *) (len+1);
    cipherTextSize = *len + crypto_box_NONCEBYTES;
    *sender_ciphertext = malloc(cipherTextSize);
    if (!*sender_ciphertext) goto End;
    
    memcpy(*sender_ciphertext, nonce, crypto_box_NONCEBYTES);
    memcpy(*sender_ciphertext + crypto_box_NONCEBYTES, next, *len);
    *cipherlen = cipherTextSize;
    
    // [V|T][Nick Len][Nickname\0][SndrPubLen][SndrPubKey][RcvrPubLen][RcvrPubKey][NonceLen][Nonce][CipherLen][Cipher]
    
    
    messageType = type;
    
End:
    return messageType;
}

