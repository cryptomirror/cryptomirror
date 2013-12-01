import ghostlib
import blobber
import sys

global PendingMessages
PendingMessages = []

global debugfile
debugfile = None
def debug(msg, nick="none"):
    pass
    """
    global debugfile
    if not debugfile:
        debugfile = open("/tmp/debug_%s" % nick, 'w')
    debugfile.write(msg + '\n')
    debugfile.flush()
    """

class CryptoState:
    """
    """
    INIT = 0
    ANON_START = 1
    ANON_FINISHED = 2
    PUBKEY_SENT = 4
    PUBKEY_RECEIVED = 8
    IDS_KNOWN_AND_READY = 12

    def __init__(self, nickname):
        self.nickname = nickname
        self.peername = None
        self.state = CryptoState.INIT
        
        self.ident_pk1, self.ident_sk1 = ghostlib.read_key(nickname)
        self.peer_pk2 = None

        self.ID_incoming = None
        self.ID_outgoing = None

    def next_in(self, message):
        """
        A message is received
        """
        # Is there a pairing yet?
        if self.state == CryptoState.IDS_KNOWN_AND_READY:
            try:
                rawmsg = blobber.decode_blob_string(message)
                nonce = rawmsg[:ghostlib.PN_LEN]
                f_nonce = rawmsg[ghostlib.PN_LEN: ghostlib.PN_LEN + 8]
                ciphertext = rawmsg[ghostlib.PN_LEN + 8:]

                plaintext = ghostlib.get_ghost_message(self.peer_pk2, 
                                                       self.ident_sk1,
                                                       nonce, f_nonce, ciphertext)
                return 0, plaintext
            except OSError:
                return 1, ">Invalid message received #1<" + message

        #establish a pairing
        elif self.state == CryptoState.INIT:
            
            #check if the message which came is a proper crypto message
            try:
                self.anon_pk2 = blobber.decode_blob_string(message)
            except:
                return 1, ">Invalid message received #2<" + message
            
            if len(self.anon_pk2) != ghostlib.PK_LEN:
                return 1, ">Invalid pubkey received<"
            
            pairing = ghostlib.create_anon_channel_pair()
            self.anon_pk1, self.anon_sk1, self.ID_outgoing = pairing
            
            self.set_state(CryptoState.ANON_FINISHED)
            #send the public part of the anon channel
            return 0, blobber.make_blob_string(self.anon_pk1)

        elif self.state == CryptoState.ANON_START:
            try:
                self.anon_pk2 = blobber.decode_blob_string(message)
            except:
                return 1, ">Invalid message received #3<" + message
            
            if len(self.anon_pk2) != ghostlib.PK_LEN:
                return 1, ">Invalid pubkey received<"

            stage1_1 = ghostlib.send_identity_over_channel(self.anon_pk1,
                                                           self.anon_sk1,
                                                           self.anon_pk2,
                                                           self.ident_pk1,
                                                           self.nickname)

            self.set_state(CryptoState.ANON_FINISHED | CryptoState.PUBKEY_SENT)
            return 0, blobber.make_blob_string(stage1_1)            
        
        elif self.state & CryptoState.ANON_FINISHED:
            rawmsg = blobber.decode_blob_string(message)
            try:
                bob_pub, bob_nick = ghostlib.get_identity_from_channel(rawmsg, self.anon_sk1)
            except:
                return 1, ">Invalid message received #4<"+message
            self.peer_pk2 = bob_pub

            if (self.state & CryptoState.PUBKEY_SENT):
                #no need to send pubkey again
                self.set_state(CryptoState.PUBKEY_SENT | CryptoState.PUBKEY_RECEIVED)
                return 0, ""
                
            stage1_1 = ghostlib.send_identity_over_channel(self.anon_pk1,
                                                           self.anon_sk1,
                                                           self.anon_pk2,
                                                           self.ident_pk1,
                                                           self.nickname)
            self.set_state(CryptoState.PUBKEY_SENT | CryptoState.PUBKEY_RECEIVED)
            
            return 0, blobber.make_blob_string(stage1_1)
        return 1, 'rcv unhandled %d'%self.state
    
    def next_out(self, message):
        """
        A message is sent
        """
        if message:
            message = "(Ghost) " + message
        
        if self.state == CryptoState.IDS_KNOWN_AND_READY:
            nonce, f_nonce, ciphertext = ghostlib.send_ghost_message(self.ID_outgoing,
                                                                     self.ident_sk1,
                                                                     self.peer_pk2,
                                                                     message)
            return 0, blobber.make_blob_string(nonce + f_nonce + ciphertext)
        elif self.state == CryptoState.INIT:
            #save plaintext for later
            self.pending_plaintext = message
            #blah

            pairing = ghostlib.create_anon_channel_pair()
            self.anon_pk1, self.anon_sk1, self.ID_outgoing = pairing
            #send the public part of the anon channel

            self.set_state(CryptoState.ANON_START)
            return 0, blobber.make_blob_string(self.anon_pk1)
        
        return 1, 'send unhandled %d'%self.state

    def set_state(self, state):
        self.state = state
        print '%s went to state %d'%(self.nickname, state)

global users
users = {}

def get_crypto_state(my_nick, target):
    global users
    if my_nick not in users:
        users[my_nick] = {}

    if target not in users[my_nick]:
        users[my_nick][target] = CryptoState(my_nick)

    crypto_state = users[my_nick][target]        

    return crypto_state

def send_private(server, my_nick, target, msg):
    """
    This transforms what is being sent. 
    """
    crypto_state = get_crypto_state(my_nick, target)
    try:
        ret, msg2 = crypto_state.next_out(msg)
    except Exception, e:
        print '> fail send priv8 with exception <'+e
        ret = 13
        msg2 = ""
    #print >> sys.stderr, my_nick, "send @", crypto_state.state, msg2, ":( :( :()))"
    #print "send_private", ret, msg

    if ret != 0:
        debug("err: %d> "%ret + my_nick + "rcv @ %d"%crypto_state.state + " " + msg2, my_nick)
    
    if ret == 0:
        debug("send (%d) returning: %s" % (crypto_state.state, msg2), my_nick)
        return ret, msg2
    else:
        return ret

def receive_private(server, my_nick, sender, msg):
    """
    This transforms what is being received
    """
    crypto_state = get_crypto_state(my_nick, sender)
    
    readyState = crypto_state.state
    
    try:
        ret, msg2 = crypto_state.next_in(msg)
    except Exception, e:
        print '> fail rcv priv8 with exception <'+e
        ret = 12
        msg2 = ""

    if ret != 0:
        debug("err: %d> "%ret + my_nick + "rcv @ %d"%crypto_state.state + " " + msg2, my_nick)
    #print "receive_private", ret, msg

    if ret == 0:
        #put in msg2 into the queue for sending
        if msg2:
            if readyState == CryptoState.IDS_KNOWN_AND_READY:
                toReceive = msg2
            else:
                debug("rcv (%d) queueing: %s" % (crypto_state.state, msg2), my_nick)
                PendingMessages.append(msg2)
                toReceive = ""
            
            debug("rcv returning: %s" % toReceive)
            return ret, toReceive

    return ret

def send_public(server, my_nick, channel, msg):
    return 0

def receive_public(server, my_nick, channel, sender, msg):
    return 0

def close_private(*args):
    print args
    print 'close private'

def pending_messages(*args):
    global PendingMessages
    #print "Sending pending messages", PendingMessages, args
    ret = tuple(PendingMessages)
    PendingMessages = []
    return ret 

if __name__ == "__main__":
    a = CryptoState("alice")
    b = CryptoState("bob")

    #
    # Q: How to automate the sending? how about pending messages?
    #
    
    #setup anon channel
    ret, msg = a.next_out(None)           # A -> B
    ret, msg = b.next_in(msg)             # B -> A
    ret, msg = a.next_in(msg)
    
    assert(a.state & a.ANON_FINISHED)
    assert(b.state & a.ANON_FINISHED)
    
    assert(a.anon_pk1 == b.anon_pk2)
    assert(a.anon_pk2 == b.anon_pk1)
    
    print 'exchange pubkeys now'
    #exchange pubkeys
    ret, msg = b.next_in(msg)            # A -> B
    ret, msg = a.next_in(msg)            # B -> A
    
    assert(a.peer_pk2 == b.ident_pk1)
    assert(b.peer_pk2 == a.ident_pk1)
    assert(a.state == a.IDS_KNOWN_AND_READY)
    assert(b.state == a.IDS_KNOWN_AND_READY)

    #Once handshake, it is pretty easy

    print 'start data communication now'
    ret, msg = a.next_out("Hi there bob") #get pending message
    ret, msg = b.next_in(msg)
    
    print msg

    ret, msg = b.next_out("Hi there alice") #get pending message
    ret, msg = a.next_in(msg)
    print msg