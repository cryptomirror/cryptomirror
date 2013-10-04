#ifndef __MESSAGES_H
#define __MESSAGES_H
enum MessageType
{
    publicKeyOnly,
    encryptedWholeMessage,
    //
    // These are gonna be todos
    //
    encryptedMultiPartHeader,
    encryptedMultiPartChain,
    encryptedMultiPartTrailer
};

//
// Given a sender nickname and a public key, create a pubkey posting message
// which allows other people to import a key.
//
char *
create_pubkey_message(char *sender_nickname, unsigned char *pubkey);

//
// Given a sender nickname, a sender secret key, a destination public key, and a message,
// create an encrypted message blob (that also has the nickname and the pubkey of the sender)
// for importing/message passing
//
char *
create_encrypted_message(char *sender_nickname, unsigned char *sender_pubkey,
                         unsigned char *sender_secretkey, unsigned char *dest_publickey,
                         unsigned char *message, unsigned int msgSize);

//
// Parse a mirror blob to import a key or decrypt an encrypted message
// or both at the same time.
//
int
parse_message(char *msg_in, char **sender_nickname, unsigned char **sender_publickey, unsigned char **receiver_publickey, unsigned char **sender_ciphertext, unsigned long *cipherlen);
#endif
