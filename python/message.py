#!/usr/bin/python
VERSION = 0
publicKeyOnly = 0
encryptedWholeMessage = 1
import struct
import nacl

def create_pubkey_message(sender_nickname, sender_pubkey):
  """
  Create and return a pubkey message
  [V|T][Nick Len][Nickname\0][PubLen][PubKey]
  """
  tag = (VERSION<<16) | publicKeyOnly
  
  out = struct.pack("<LL", tag, len(sender_nickname)) + sender_nickname
  out += struct.pack("<L", len(sender_pubkey)) + sender_pubkey
  
  return out

def create_encrypted_message(sender_nickname,
                             sender_pubkey,
                             sender_secretkey,
                             dest_pubkey,
                             message):
  """
  Create and return an encrypted message
    [V|T][Nick Len][Nickname\0][SndrPubLen][SndrPubKey]
     [RcvrPubLen][RcvrPubKey][NonceLen][Nonce][CipherLen][Cipher]
  """
  nonce, cipher = nacl.nacl_encrypt(sender_secretkey, 
                                    dest_pubkey, 
                                    message)
  
  tag = (VERSION<<16) | encryptedWholeMessage
  
  out = struct.pack("<LL", tag, len(sender_nickname)) + sender_nickname
  out += struct.pack("<L", len(sender_pubkey)) + sender_pubkey
  out += struct.pack("<L", len(dest_pubkey)) + dest_pubkey

  out += struct.pack("<L", len(nonce)) + nonce
  out += struct.pack("<L", len(cipher)) + cipher
  
  return out


def parse_message(msg):
  """
  Parses a message and returns sender nick, 
      sender pubkey, rcv pubkey, a nonce, and a ciphertext
    
  [V|T][Nick Len][Nickname\0][SndrPubLen][SndrPubKey]
   [RcvrPubLen][RcvrPubKey][NonceLen][Nonce][CipherLen][Cipher]
  
  """
  idx = 8
  tag, nickLen = struct.unpack("<LL", msg[:idx])
  if VERSION != (tag>>16):
    raise Exception("Wrong version")
  sender_nickname = msg[idx:idx+nickLen]
  idx += nickLen
  
  length = struct.unpack("<L", msg[idx:idx+4])[0]
  idx += 4
  sender_pubkey = msg[idx:idx+length]
  idx += length

  length = struct.unpack("<L", msg[idx:idx+4])[0]
  idx += 4
  dest_pubkey = msg[idx:idx+length]
  idx += length

  length = struct.unpack("<L", msg[idx:idx+4])[0]
  idx += 4
  nonce = msg[idx:idx+length]
  idx += length

  length = struct.unpack("<L", msg[idx:idx+4])[0]
  idx += 4
  cipher = msg[idx:idx+length]
  idx += length
  
  return sender_nickname, sender_pubkey, dest_pubkey, nonce, cipher

if __name__ == "__main__":
  pk1, sk1 = nacl.gen_keypair()
  pk2, sk2 = nacl.gen_keypair()
  msg = create_encrypted_message("bob", pk1, sk1, pk2, "Hello world")

  ret = parse_message(msg)
  sender_nickname, sender_pubkey, recv_pubkey, nonce, cipher = ret
  
  plaintext = nacl.nacl_decrypt(pk2, sk1, nonce, cipher)
  
  