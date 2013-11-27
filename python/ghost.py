#!/usr/bin/python
import message

ID_LEN = message.nacl.STREAM_KEYSIZE

def gen_id(size=ID_LEN):
  nonce = message.nacl.BUF(size)
  ret = message.nacl.LIB.randombytes(nonce, size)
  if ret != size:
    raise Exception("Expected random bytes: %d"%size)
  return nonce[:]

def read_key(name):
  try:
      data = open("%s.keys"%name).read(64)
      pk1, sk1 = data[:32], data[32:]
  except:
    pk1, sk1 = message.make_keypair()
    open("%s.keys"%name,'w').write(pk1+sk1)

  return pk1, sk1
  

"""
0. Two parties have keys

Initial contact between A and B
1. Set up anonymous ECDH channel
2. Generate identity keys
3. Transmit public keys, nicknames, and secret IDs over anonymous ECDH channel

The Secret ID can be thought of as an edge between A and B, it is a unique
matching to the identity reserved for A and B only. B to A likewise is a different ID.
(Could consider combining into one, but why?)

Subsequent communication between A and B
1. Sender posts nonce, F(nonce, key). nonce_poly_2, encrypted poly-salsa msg
2. Receiver reads nonce, compares F(nonce, key) against all known keys, 
    then if match->decrypts msg

Q: why not just have receiver decrypt everything? maybe not a bad idea...
    
    
""" 
if __name__ == "__main__":
  #these are the persistent identities
  alice_pk1, alice_sk1 = read_key("alice")
  alice_name = "alice"
  
  bob_pk2, bob_sk2 = read_key("bob")
  bob_name = "bob"
  
  #create alice's anon pairing and ID for alice->bob
  anon_pk1, anon_sk1 = message.make_keypair()
  ID_alice_to_bob = gen_id()

  #create bob's anon pairing and ID for bob->alice
  anon_pk2, anon_sk2 = message.make_keypair()
  ID_bob_to_alice = gen_id()
  
  ### somehow anon_pk1 & anon_pk2 are exchanged ###
  
  #alice sends bob true pubkey and ID key
  stage2_0 = message.create_encrypted_message(alice_name,
                                              alice_pk1, 
                                              alice_sk1, 
                                              bob_pk2, 
                                              ID_alice_to_bob + alice_name)

  stage1_2 = message.create_encrypted_message("",
                                              anon_pk1,
                                              anon_sk1,
                                              anon_pk2,
                                              stage2_0)

  #bob sends alice true pubkey and ID key
  stage2_1 = message.create_encrypted_message(bob_name,
                                              bob_pk2, 
                                              bob_sk2, 
                                              alice_pk1, 
                                              ID_bob_to_alice + bob_name)

  stage1_3 = message.create_encrypted_message("",
                                              anon_pk2,
                                              anon_sk2,
                                              anon_pk1,
                                              stage2_1)

  ### somehow stage1_2 and stage1_3 are exchanged
  
  #alice decrypts anon stage 1 from bob
  s_nick, s_pub, r_pub, nonce, cipher = message.parse_message(stage1_3)
  stage2_plain = message.nacl.nacl_decrypt(s_pub, anon_sk1, nonce, cipher)
  real_nick, sender_pub, my_pub, nonce, cipher = message.parse_message(stage2_plain)
  assert(my_pub == alice_pk1)
  ID_bob = message.nacl.nacl_decrypt(sender_pub, alice_sk1, nonce, cipher)
  alice_knows_bobs_id = ID_bob[:ID_LEN]
  alice_knows_bobs_nick = ID_bob[ID_LEN:]
  assert(real_nick == alice_knows_bobs_nick)

  #bob decrypts anon stage 1 from alice
  s_nick, s_pub, r_pub, nonce, cipher = message.parse_message(stage1_2)
  stage2_plain = message.nacl.nacl_decrypt(s_pub, anon_sk2, nonce, cipher)
  real_nick, sender_pub, my_pub, nonce, cipher = message.parse_message(stage2_plain)
  assert(my_pub == bob_pk2)
  ID_alice = message.nacl.nacl_decrypt(sender_pub, bob_sk2, nonce, cipher)
  bob_knows_alices_id = ID_alice[:ID_LEN]
  bob_knows_alices_nick = ID_alice[ID_LEN:]
  assert(real_nick == bob_knows_alices_nick)

  ###
  ### At this point Alice and Bob know each others IDs. These
  ### need to be secret to protect identity
  ###
  
  # Alice posts a message to bob
  poly_nonce, ciphertext = message.nacl.nacl_encrypt(alice_sk1,
                                                     bob_pk2,
                                                     "Hello anonymous world")
  nonce, f_nonce = message.nacl.nacl_symmetric(8, alice_knows_bobs_id)
  

  # bob verifies f_nonce and decrypts message
  # sidenote: @ 1,000,000 users this becomes too slow. 
  # a server would want to partition users by generating
  # multiple identities to hand , and cross-signing the
  # identities.
  #
  n2, f1_nonce = message.nacl.nacl_symmetric(8, ID_bob_to_alice, nonce)
  if f_nonce == f1_nonce:
    pass
  else:
    raise Exception("mismatch")
  
  plaintext = message.nacl.nacl_decrypt(alice_pk1, bob_sk2, poly_nonce, ciphertext)
  print plaintext
  
  