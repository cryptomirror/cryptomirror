#!/usr/bin/python
import ctypes

"""
compile randombytes.o and all the objects from
the libnacl.a  that dont have wrapper in 
the name
"""
LIB = ctypes.CDLL("libnacl.dylib")
LIB.crypto_box_keypair = LIB.crypto_box_curve25519xsalsa20poly1305_ref_keypair
LIB.crypto_box = LIB.crypto_box_curve25519xsalsa20poly1305_ref
LIB.crypto_box_open = LIB.crypto_box_curve25519xsalsa20poly1305_ref_open
PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES = 32
SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_ref_SECRETKEYBYTES = 32
BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_ref_BEFORENMBYTES = 32
NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_ref_NONCEBYTES = 24
ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ref_ZEROBYTES = 32
BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ref_BOXZEROBYTES = 16

BUF = lambda x : ctypes.create_string_buffer(x)

def nacl_encrypt(sender_secret,
                receiver_public,
                message):
  """
  Returns nonce, ciphertext
  """
  
  #create nonce
  nonce = BUF(NONCEBYTES)
  ret = LIB.randombytes(nonce, NONCEBYTES)
  if ret != NONCEBYTES:
    raise Exception("Expected random bytes: %d"%NONCEBYTES)
  
  #prepare encryption buffer with crypto_box_ZEROBYTES 
  #leading NUL bytes
  #
  _message_padded = "\x00"*ZEROBYTES + message
  cLen = len(_message_padded)
  _ciphertext = BUF(cLen)
  ret = LIB.crypto_box(_ciphertext, 
                       _message_padded, 
                       cLen, 
                       nonce, 
                       receiver_public, 
                       sender_secret)
  if ret != 0:
    raise Exception("Encryption failure")
  return nonce[:], _ciphertext[BOXZEROBYTES:]

def nacl_decrypt(sender_public,
                receiver_secret,
                nonce,
                ciphertext):
  """
  Returns plaintext
  """
  _ciphertext_padded = "\x00"*BOXZEROBYTES + ciphertext
  cLen = len(_ciphertext_padded)
  message = BUF(cLen)
  ret = LIB.crypto_box_open(message,
                            _ciphertext_padded, 
                            cLen, 
                            nonce,
                            sender_public,
                            receiver_secret)
  if ret != 0:
    raise Exception("Decryption failure")
  return message[ZEROBYTES:]

def gen_keypair():
  """
  returns pk, sk
  """
  pubkey_buf = BUF(PUBLICKEYBYTES)
  seckey_buf = BUF(SECRETKEYBYTES)
  ret = LIB.crypto_box_keypair(pubkey_buf, seckey_buf)
  if ret != 0:
    raise Exception("Key generation failed")
  return pubkey_buf.raw, seckey_buf.raw

if __name__ == "__main__":
  pk1, sk1 = gen_keypair()
  pk2, sk2 = gen_keypair()
  nonce, ciphertext = nacl_encrypt(sk1, pk2, "Hello World!")
  ret1 = nacl_decrypt(pk1, sk2, nonce, ciphertext)

  nonce, ciphertext = nacl_encrypt(sk2, pk1, "Ehllo World!")
  ret2 = nacl_decrypt(pk2, sk1, nonce, ciphertext)
  
  print ret1
  print ret2

