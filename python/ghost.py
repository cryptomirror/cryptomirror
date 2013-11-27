#!/usr/bin/python
import message
import nacl

ID_LEN = nacl.STREAM_KEYSIZE
PK_LEN = nacl.PUBLICKEYBYTES
PN_LEN = nacl.STREAM_NONCEBYTES

def gen_id(size=ID_LEN):
  nonce = nacl.BUF(size)
  ret = nacl.LIB.randombytes(nonce, size)
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
  
def create_anon_channel_pair():
  """
  Create a keypair and an ID for an anonymous ECDH channel
  """
  #create alice's anon pairing and ID for alice->bob
  anon_pk1, anon_sk1 = message.make_keypair()
  ID_to_send = gen_id()
  return anon_pk1, anon_sk1, ID_to_send

def send_identity_over_channel(channel_sender_pk,
                               channel_sender_sk,
                               channel_receiver_pk,
                               sender_pk,
                               nickname):
  """
  Create a pubkey + nickname message over the anon ECDH channel
  """
  #alice sends bob true pubkey and ID key
  stage2 = sender_pk + nickname

  stage1 = message.create_encrypted_message("",
                                            channel_sender_pk,
                                            channel_sender_sk,
                                            channel_receiver_pk,
                                            stage2)
  return stage1

def get_identity_from_channel(stage1,
                              channel_sk):
  """
  Extract nickname and pubkey from an identity channel
  """
  #alice decrypts anon stage 1 from bob
  s_nick, s_pub, r_pub, nonce, cipher = message.parse_message(stage1)
  stage2_plain = nacl.nacl_decrypt(s_pub, channel_sk, nonce, cipher)
  
  sender_pub = stage2_plain[:PK_LEN]
  known_nick = stage2_plain[PK_LEN + ID_LEN:]
  return sender_pub, known_nick

def send_id_key_over_channel(channel_sender_pk,
                             channel_sender_sk,
                             channel_receiver_pk,
                             sender_pk,
                             sender_sk,
                             receiver_pk,
                             nickname,
                             ID):
  """
  Send Secret ID key over persistent keys over ECDH channel
  Note: This ID is unique for this communication pairing.
  """
  #alice sends bob true pubkey and ID key
  stage2 = message.create_encrypted_message(nickname,
                                            sender_pk,
                                            sender_sk,
                                            receiver_pk,
                                            ID + nickname)

  stage1 = message.create_encrypted_message("",
                                            channel_sender_pk,
                                            channel_sender_sk,
                                            channel_receiver_pk,
                                            stage2)
  return stage1

def get_id_key_from_channel(stage1,
                            channel_sk,
                            receiver_sk):
  """
  Extract an id key and nickname from an id key message
  """
  #bob decrypts anon stage 1 from alice
  s_nick, s_pub, r_pub, nonce, cipher = message.parse_message(stage1)
  stage2_plain = nacl.nacl_decrypt(s_pub, channel_sk, nonce, cipher)
  
  real_nick, sender_pub, my_pub, nonce, cipher = message.parse_message(stage2_plain)
  ID_alice = nacl.nacl_decrypt(sender_pub, receiver_sk, nonce, cipher)
  new_id = ID_alice[:ID_LEN]
  nick = ID_alice[ID_LEN:]
  return new_id, nick

def send_ghost_message(target_id,
                       sender_sk,
                       receiver_pk,
                       msg):  
  """
  Send a message over the ECDH established by the identity-key pairings,
  and a nonce + challenge answer using the Secret ID key of the target  
  """
  poly_nonce, ciphertext = nacl.nacl_encrypt(sender_sk,
                                             receiver_pk,
                                             msg)
  nonce, f_nonce = nacl.nacl_symmetric(8, target_id)
  return nonce, f_nonce, poly_nonce + ciphertext

def verify_sender(nonce,
                  answer,
                  id_to_verify):
  """
  Verify the nonce and answer with the a given id
  """
  n2, f1_nonce = nacl.nacl_symmetric(8, id_to_verify, nonce)
  if answer == f1_nonce:
    return True
  else:
    return False  

def get_ghost_message(sender_pk,
                      receiver_sk,
                      nonce,
                      answer,
                      ciphertext):
  """
  Decrypt a message from the known sender
  """
  poly_nonce, ciphertext = ciphertext[:PN_LEN], ciphertext[PN_LEN:]
  plaintext = nacl.nacl_decrypt(sender_pk, receiver_sk, poly_nonce, ciphertext)
  return plaintext

"""
0. Two parties have keys

Initial contact between A and B
1. Set up anonymous ECDH channel
2. Transmit nicknames and pub keys through channel
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
  
  #0. Pub keys are established
  
  #these are the persistent identities
  alice_pk1, alice_sk1 = read_key("alice")
  alice_name = "alice"
  
  bob_pk2, bob_sk2 = read_key("bob")
  bob_name = "bob"
  
  #1. Set up anonymous ECDH channel

  #create alice's anon pairing and ID for alice->bob
  anon_pk1, anon_sk1, ID_alice_to_bob = create_anon_channel_pair()

  #create bob's anon pairing and ID for bob->alice
  anon_pk2, anon_sk2, ID_bob_to_alice = create_anon_channel_pair()
  
  ### somehow anon_pk1 & anon_pk2 are exchanged ###
  
  # 2. Transmit nicknames and pub keys through channel
  
  #alice sends bob true pubkey and ID key
  stage1_0 = send_identity_over_channel(anon_pk1,
                                        anon_sk1,
                                        anon_pk2,
                                        alice_pk1,
                                        alice_name)

  #bob sends alice true pubkey and ID key
  stage1_1 = send_identity_over_channel(anon_pk2,
                                        anon_sk2,
                                        anon_pk1,
                                        bob_pk2,
                                        bob_name)

  ### somehow stage1_0 and stage 1_1 are exchanged ###

  #3. Transmit public keys, nicknames, and secret IDs over anonymous ECDH channel

  #alice decrypts anon stage 1 from bob
  bob_pub, bob_nick = get_identity_from_channel(stage1_1, anon_sk1)

  #bob does the same
  alice_pub, alice_nick = get_identity_from_channel(stage1_0, anon_sk2)
  
  #alice sends bob ID key over channel + pub key
  stage1_2 = send_id_key_over_channel(anon_pk1,
                                      anon_sk1,
                                      anon_pk2,
                                      alice_pk1,
                                      alice_sk1,
                                      bob_pk2,
                                      alice_name,
                                      ID_alice_to_bob)
                                      
  #bob sends alice ID key over channel + pub key
  stage1_3 = send_id_key_over_channel(anon_pk2,
                                      anon_sk2,
                                      anon_pk1,
                                      bob_pk2,
                                      bob_sk2,
                                      alice_pk1,
                                      bob_name,
                                      ID_bob_to_alice)
                                      
  ### somehow stage1_2 and stage1_3 are exchanged  
  
  #alice gets id from bob
  result = get_id_key_from_channel(stage1_3, anon_sk1, alice_sk1)
  alice_knows_bobs_id, alice_knows_bobs_nick = result
  
  #bob gets id from alice
  result = get_id_key_from_channel(stage1_3, anon_sk1, alice_sk1)
  bob_knows_alices_id, bob_knows_alices_nick = result

  ###
  ### At this point Alice and Bob know each others IDs. These
  ### need to be secret to protect identity
  ###
  
  # Alice posts a message to bob
  nonce, f_nonce, ciphertext = send_ghost_message(alice_knows_bobs_id,
                                                  alice_sk1, 
                                                  bob_pk2, 
                                                  "Hello anonymous world")  
  
  identities = {ID_bob_to_alice: alice_pk1}
  for ident in identities.keys():
    print ident, k  ey
  # sidenote: @ 1,000,000 users this becomes too slow. 
  # a server would want to partition users by generating
  # multiple identities to hand, and cross-signing the
  # identities.
  #
  # bob verifies f_nonce and decrypts message
  result = verify_sender(nonce, f_nonce, ID_bob_to_alice)
  if result:
    pass
  else:
    raise Exception("Unknown sender")
  plaintext = get_ghost_message(alice_pk1, bob_sk2, nonce, f_nonce, ciphertext)
  print plaintext
  
  