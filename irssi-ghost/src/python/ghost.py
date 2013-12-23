import ghostlib
import blobber
import sys
from binascii import hexlify

global PendingMessages, PendingDebugMessages
PendingMessages = []
PendingDebugMessages = []

def debug(msg, nick=None):
    if nick:
        PendingDebugMessages.append("%s: %s"%(nick, msg))
    else:
        PendingDebugMessages.append(msg)

class CryptoState:
    """
    """
    INIT = 0
    ANON_START = 1
    ANON_FINISHED = 2
    PUBKEY_SENT = 4
    PUBKEY_RECEIVED = 8
    PUBKEYS_KNOWN_AND_READY = 12
    TRUSTED_AUTHENTICATED_PARTNER = 16

    def __init__(self, nickname):
        self.state = CryptoState.INIT

        self.nickname = nickname
        self.peername = None
        
        self.ident_pk1, self.ident_sk1 = ghostlib.read_key(nickname)
        self.peer_pk2 = None

        self.ID_incoming = None
        self.ID_outgoing = None
        
        self.pending_send = 0

    def print_peer_identity(self):
        if self.peername and self.peer_pk2:
            return "nick: %s key: %s" % (self.peername, hexlify(self.peer_pk2))
        else:
            return "UNKNOWN PEER!"

    def next_in(self, message):
        """
        A message is received
        """
        # Is there a trusted pairing yet?
        if self.state == CryptoState.TRUSTED_AUTHENTICATED_PARTNER or \
           self.state == CryptoState.PUBKEYS_KNOWN_AND_READY:
            try:
                rawmsg = blobber.decode_blob_string(message)
                nonce = rawmsg[:ghostlib.PN_LEN]
                f_nonce = rawmsg[ghostlib.PN_LEN: ghostlib.PN_LEN + 8]
                ciphertext = rawmsg[ghostlib.PN_LEN + 8:]
                
                #
                # TODO Switch to PFS and verify sender using ID keys 
                #

                plaintext = ghostlib.get_ghost_message(self.peer_pk2, 
                                                       self.ident_sk1,
                                                       nonce, f_nonce, ciphertext)

                return 0, plaintext, ""
            except Exception, e:
                return 1, ">Invalid message received #1<" + str(e) + "::" + message, ""

        elif self.state == CryptoState.INIT:
            #
            # Establish the anonymous channel
            # 
            
            #check if the message which came is a proper crypto message
            try:
                self.anon_pk2 = blobber.decode_blob_string(message)
            except:
                return 1, ">Invalid message received #2<" + message, ""
            
            if len(self.anon_pk2) != ghostlib.PK_LEN:
                return 1, ">Invalid pubkey received<", ""
            
            pairing = ghostlib.create_anon_channel_pair()
            self.anon_pk1, self.anon_sk1, self.ID_outgoing = pairing
            
            #
            # send the public part of the anon channel
            #
            self.set_state(CryptoState.ANON_FINISHED)
            return 0, "[Ghost] Initializing anonymous channel", blobber.make_blob_string(self.anon_pk1)

        elif self.state == CryptoState.ANON_START:
            #
            # Finalize anon channel
            #
            try:
                self.anon_pk2 = blobber.decode_blob_string(message)
            except:
                return 1, ">Invalid message received #3<" + message, ""
            
            if len(self.anon_pk2) != ghostlib.PK_LEN:
                return 1, ">Invalid pubkey received<", ""

            #
            # Send identity information over anon channel
            #
            stage1_1 = ghostlib.send_identity_over_channel(self.anon_pk1,
                                                           self.anon_sk1,
                                                           self.anon_pk2,
                                                           self.ident_pk1,
                                                           self.nickname)

            self.set_state(CryptoState.ANON_FINISHED | CryptoState.PUBKEY_SENT)

            self.pending_send = 1
            return 0, "[Ghost] Exchanging identities]", blobber.make_blob_string(stage1_1)
        
        elif self.state & CryptoState.ANON_FINISHED:
            #
            # Get identity information from peer
            #
            rawmsg = blobber.decode_blob_string(message)
            try:
                bob_pub, bob_nick = ghostlib.get_identity_from_channel(rawmsg, self.anon_sk1)
            except:
                return 1, ">Invalid message received #4<"+message, ""

            self.peer_pk2 = bob_pub
            self.peername = bob_nick

            #
            # Check for mismatch
            #
            global trusted_keys
            mismatched_key = False
            known_key = False
            if self.peername in trusted_keys:
                if self.peer_pk2 == trusted_keys[self.peername]:
                    known_key = True
                else:
                    mismatched_key = True
                    
            if (self.state & CryptoState.PUBKEY_SENT):
                #no need to send pubkey again
                if known_key:
                    self.set_state(CryptoState.TRUSTED_AUTHENTICATED_PARTNER)
                    return 0, "Established session with known peer: %s"%(self.print_peer_identity()), ""
                else:                    
                    self.set_state(CryptoState.PUBKEY_SENT | CryptoState.PUBKEY_RECEIVED)
                    if mismatched_key:
                        return 0, "*WARNING* Key mismatch from unknown peer: %s\n"%(self.print_peer_identity()) + \
                                  "Use /ghost add to override", ""
                    else:
                        return 0, "Established session from unknown peer: %s\n"%(self.print_peer_identity()) + \
                                  "Use /ghost add to add this user", ""
            #
            # Send identity if not already sent
            #
            stage1_1 = ghostlib.send_identity_over_channel(self.anon_pk1,
                                                           self.anon_sk1,
                                                           self.anon_pk2,
                                                           self.ident_pk1,
                                                           self.nickname)
            if known_key:
                self.set_state(CryptoState.TRUSTED_AUTHENTICATED_PARTNER)
            else:
                # XXX
                # XXX want to display message. requires refactoring pending_send -> 3 params?
                # XXX
                self.set_state(CryptoState.PUBKEY_SENT | CryptoState.PUBKEY_RECEIVED)
                            
            self.pending_send = 1
            return 0, "[Ghost] Exhanging identity with requesting peer %s"%self.peername, blobber.make_blob_string(stage1_1)
        return 1, 'rcv unhandled %d'%self.state, ""
    
    def next_out(self, message):
        """
        A message is sent
        """
        if message:
            message = "(Ghost) " + message
        
        if self.state == CryptoState.TRUSTED_AUTHENTICATED_PARTNER:
            nonce, f_nonce, ciphertext = ghostlib.send_ghost_message(self.ID_outgoing,
                                                                     self.ident_sk1,
                                                                     self.peer_pk2,
                                                                     message)
            return 0, blobber.make_blob_string(nonce + f_nonce + ciphertext)

        elif self.state == CryptoState.PUBKEYS_KNOWN_AND_READY:
            #
            # Want to send a message, but this person is not trusted yet!
            #        
            return 1, "Identities exchanged, but you haven't trusted this peer"

        elif self.state == CryptoState.INIT:
            #
            # Establish the anonymous channel
            #

            pairing = ghostlib.create_anon_channel_pair()
            self.anon_pk1, self.anon_sk1, self.ID_outgoing = pairing
            #send the public part of the anon channel

            self.set_state(CryptoState.ANON_START)
            return 0, blobber.make_blob_string(self.anon_pk1)
        
        return 1, 'send unhandled %d'%self.state

    def set_state(self, state):
        self.state = state
        debug('%s went to state %d'%(self.nickname, state))
    
    def trust_key(self):
        #
        # Set state. Normally conflict resolution needs to happen
        # here or earlier.
        #
        if self.state == CryptoState.TRUSTED_AUTHENTICATED_PARTNER:
            #nothing to do
            pass
        if self.state != CryptoState.PUBKEYS_KNOWN_AND_READY:
            debug("Error: tried to trust but pubkeys were not exchanged")
        else:
            #
            # Add peername to trusted keys
            #
            global trusted_keys
            trusted_keys[self.peername] = self.peer_pk2
            self.set_state(CryptoState.TRUSTED_AUTHENTICATED_PARTNER)



global users
global trusted_keys
users = {}
trusted_keys = {}

def get_crypto_state(my_nick, target):
    global users
    if my_nick not in users:
        users[my_nick] = {}

    if target not in users[my_nick]:
        users[my_nick][target] = CryptoState(my_nick)

    crypto_state = users[my_nick][target]        

    return crypto_state

def reset_crypto_state(my_nick, target):
    users[my_nick][target] = CryptoState(my_nick)

def send_private(server, my_nick, target, msg):
    try:
        """
        This transforms what is being sent. 
        """
        crypto_state = get_crypto_state(my_nick, target)
        try:
            ret, msg_out = crypto_state.next_out(msg)
        except Exception, e:
            debug('> fail send priv8 with exception <'+str(e))
            ret = 13
            msg_out = ""

        if ret != 0:
            debug("err: %d> "%ret + my_nick + "rcv @ %d"%crypto_state.state + " " + msg_out, my_nick)
    
        if ret == 0:
            debug("send (%d) returning: %s" % (crypto_state.state, msg_out), my_nick)
            return ret, msg_out
        else:
            #
            # TODO how to display a message to current screen on send error?
            #
            return ret, "[GHOST] failed with error (%d): "%ret + msg_out
            
    except Exception, e:
        debug("horrible fail send"+ str(e))
        return 99

def receive_private(server, my_nick, sender, msg):
    """
    This transforms what is being received
    """
    #
    # TODO Consider prompting user before creating a crypto state
    #        with a peer
    #
    try:
        crypto_state = get_crypto_state(my_nick, sender)
    
        readyState = crypto_state.state
    
        try:
            ret, msg_in, msg_out = crypto_state.next_in(msg)
        except Exception, e:
            debug('> fail rcv priv8 with exception <'+str(e))
            ret = 12
            msg_in = ""

        if ret == 0:
            #put in msg_out into the queue for sending
            if msg_out:
                debug("rcv (%d) queueing: %s" % (crypto_state.state, msg_out), my_nick)
                PendingMessages.append(msg_out)

            debug("rcv returning: %s" % msg_in)
            return ret, msg_in
        else:
            debug("err: %d> "%ret + my_nick + "rcv @ %d"%crypto_state.state + " " + msg_out, my_nick)
            return 0, "[GHOST] Failed with error (%d): "%ret+msg_in
    except Exception, e:
        debug("horrible fail rcv"+ str(e))
        return 99

def send_public(server, my_nick, channel, msg):
    return 0

def receive_public(server, my_nick, channel, sender, msg):
    return 0

def close_private(*args):
    debug(str(args))
    debug('close private')

def pending_messages(*args):
    global PendingMessages
    #print "Sending pending messages", PendingMessages, args
    ret = tuple(PendingMessages)
    PendingMessages = []
    return ret 

def pending_debug_messages(*args):
    global PendingDebugMessages
    #print "Sending pending messages", PendingMessages, args
    ret = tuple(PendingDebugMessages)
    PendingDebugMessages = []
    return ret 

def ghost_query_command(server, my_nick, query_target, msg):
    if ' ' in msg:
        cmd, rest = msg.split(' ', 1)
    else:
        cmd = msg
        
    result = ""
    if cmd in ['init', 'rekey', 'reset']:
        #
        # Reset the anonymous channel + crypto state
        #
        reset_crypto_state(my_nick, query_target)
        result = "Reset state:"

    elif cmd == 'add':
        #
        # Add this pubkey to known keys
        #
        crypto_state = get_crypto_state(my_nick, query_target)
        result = crypto_state.trust_key()
    else:
        debug("Unknown ghost cmd %s ...."%msg)
            
    return 0, result + "(Ghost command received: my_nick=%s query_target=%s msg=%s)"%(my_nick, query_target, msg)

def ghost_command(server, my_nick, data):
    print 'got ghost cmd'
    return 0, "Ghost command received: my_nick=%s msg=%s"%(my_nick, data)

if __name__ == "__main__":
    a = CryptoState("alice")
    b = CryptoState("bob")
    
    #
    # Q: How to automate the sending? how about pending messages?
    #
    
    #setup anon channel
    ret, msg_out = a.next_out(None)               # A -> B
    ret, msg_in, msg_out = b.next_in(msg_out)     # B -> A
    ret, msg_in, msg_out = a.next_in(msg_out)
    
    assert(a.state & a.ANON_FINISHED)
    assert(b.state & a.ANON_FINISHED)
    
    assert(a.anon_pk1 == b.anon_pk2)
    assert(a.anon_pk2 == b.anon_pk1)
    
    print 'exchange pubkeys now'
    #exchange pubkeys
    ret, msg_in, msg_out = b.next_in(msg_out)            # A -> B
    ret, msg_in, msg_out = a.next_in(msg_out)            # B -> A
    
    assert(a.peer_pk2 == b.ident_pk1)
    assert(b.peer_pk2 == a.ident_pk1)
    assert(a.state == a.PUBKEYS_KNOWN_AND_READY)
    assert(b.state == a.PUBKEYS_KNOWN_AND_READY)

    a.trust_key()
    b.trust_key()
    
    # excercise trust_key(), re-exchange w/ new anon channel
    a = CryptoState("alice")
    b = CryptoState("bob")
    ret, msg_out = a.next_out(None)                   # A -> B
    ret, msg_in, msg_out = b.next_in(msg_out)         # B -> A
    ret, msg_in, msg_out = a.next_in(msg_out)
    
    assert(a.state & a.ANON_FINISHED)
    assert(b.state & a.ANON_FINISHED)
    
    assert(a.anon_pk1 == b.anon_pk2)
    assert(a.anon_pk2 == b.anon_pk1)
    
    #exchange pubkeys
    ret, msg_in, msg_out = b.next_in(msg_out)            # A -> B
    ret, msg_in, msg_out = a.next_in(msg_out)            # B -> A
    
    assert(a.peer_pk2 == b.ident_pk1)
    assert(b.peer_pk2 == a.ident_pk1)
    ######
    
    # don't need to trust again
    assert(a.state == a.TRUSTED_AUTHENTICATED_PARTNER)
    assert(b.state == a.TRUSTED_AUTHENTICATED_PARTNER)

    #Once the handshake is done, it is pretty easy

    print 'start data communication now'
    ret, msg_out = a.next_out("Hi there bob") #get pending message
    assert(ret == 0)
    ret, msg_in, msg_out = b.next_in(msg_out)
    assert(ret == 0)
    
    print "BOB READS:", msg_in

    ret, msg_out = b.next_out("Hi there alice") #get pending message
    assert(ret == 0)
    ret, msg_in, msg_out = a.next_in(msg_out)
    assert(ret == 0)
    print "ALICE READS:", msg_in