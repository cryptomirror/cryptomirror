#import "MainMenuWindowController.h"
#import "UIElementUtilities.h"
#import "AppDelegate.h"
#import "common.h"
#import "blobber.h"
#import "messages.h"
#import "nacl.h"
#import "ReadWindowController.h"
#import <Carbon/Carbon.h>

@implementation MainMenuWindowController


- (void)setReadWindow:(ReadWindowController*)rw {
    _readWindow = rw;
}

- (void)awakeFromNib {
    
    //
    // Empty out things from the nib
    //
    
    [identityList removeAllItems];
    [cryptoPalsList removeAllItems];
    [cryptoPalsList2 removeAllItems];

    _identities = [[NSMutableDictionary alloc] init];
    _cryptopals = [[NSMutableDictionary alloc] init];
    _sk = _pk = NULL;
    _nick = NULL;
}

- (void)refreshIdentityList:(NSMutableDictionary*)dict {
    [identityList removeAllItems];
    [identityList addItemsWithTitles:[dict allKeys]];
}

- (void)refreshCryptoPalsList:(NSMutableDictionary*)dict {
    
    [cryptoPalsList removeAllItems];
    [cryptoPalsList addItemsWithTitles:[dict allKeys]];
}

- (void)generateIdentityWithName:(NSString*)name
{
    struct crypto_self_identity *ident;
    unsigned char *pk, *sk;
    int ret;
    
    //
    // Check if the name is already known
    //
    
    ident = NULL;
    pk = sk = NULL;
    
    ret = genkey(&pk, &sk);
    if (ret != 0)
    {
        //
        // XXX prompt about key generation failure here
        //
        return;
    }
    
    ident = calloc(1, sizeof(*ident));
    ident->nickname = strdup([name cStringUsingEncoding:NSUTF8StringEncoding]);
    ident->pubkey = pk;
    ident->seckey = sk;
    ident->flags = 0;
    pk = NULL;
    sk = NULL;
    
    [_identities setValue:[NSValue valueWithPointer:ident] forKey:name];
    [self refreshIdentityList:_identities];
    
End:
    if (sk != NULL)
    {
        release_mem(sk);
    }
    
    if (pk != NULL)
    {
        release_mem(pk);
    }
    
}


- (NSString*)toHex:(char*)cstr withLen:(int)len
{
    NSMutableString *hexStr = [[NSMutableString alloc] init];
    
    int i;
    for(i = 0; i < len; i++)
    {
        [hexStr appendFormat:@"%.2x", (cstr[i]&0xff)];
    }
    
    return [NSString stringWithString:hexStr];
}

- (void)updateInfoForUIElement:(AXUIElementRef)uiElement {

    NSString * description = [UIElementUtilities descriptionForUIElement:uiElement attribute:@"AXValue" beingVerbose:false];
    
    NSMutableString *decoded_output = nil;

    if (description)
    {
        //
        // do replacement
        //
//        AXError status = AXUIElementSetAttributeValue(uiElement, kAXValueAttribute , @"SUP");
        /*
        AXError status = AXUIElementSetAttributeValue(uiElement, kAXRoleAttribute , kAXTextAreaRole);
        printf("Status of set attribute was %d\n", status);
        status = AXUIElementSetAttributeValue(uiElement, kAXValueAttribute , @"SUP");
        printf("Status of set attribute was %d\n", status);
         */
//        AXUIElementPerformAction(uiElement, kAXConfirmAction);
        
        struct blobs *b;
        b = extract_blobs(description);
        if (b != NULL)
        {
            int i;
            for (i = 0; i < b->count; i++)
            {
                //printf("Blob %d = %s\n", i, b->blob[i]);
                int msgType;
                char *senderNick;
                unsigned char *senderPubkey = NULL;
                unsigned char *receiverPubkey = NULL;
                unsigned char *senderCiphertext = NULL;
                unsigned long cipherLen = 0;

                //
                // Extract the crypto mirror blob
                //
                msgType = parse_message(b->blob[i], &senderNick, &senderPubkey, &receiverPubkey, &senderCiphertext, &cipherLen);

//                printf("msgType = %d\n", msgType);
                
                NSString *nickname = nil;
                NSString *hexPubKey = nil;

                if (senderNick)
                {                    
                    nickname = [[NSString alloc] initWithCString:senderNick encoding:NSUTF8StringEncoding];
                }
                
                switch (msgType)
                {
                    case publicKeyOnly:
                    case encryptedWholeMessage:
                        if (!senderPubkey) return;
                        if (!nickname) return;
                        //
                        // Check if the name already exists.
                        //
                        NSValue *value = [_cryptopals objectForKey:nickname];
                        struct crypto_pal_identity *pal;
                        if (value != NULL)
                        {
                            pal = [value pointerValue];
                            //
                            // If it does and the public keys collide prompt about it
                            //
                            if (memcmp(pal->pubkey, senderPubkey, crypto_box_PUBLICKEYBYTES) != 0)
                            {
                                //
                                // Mismatch, prompt and abort
                                //
                                NSAlert *alert = [[[NSAlert alloc] init] autorelease];
                                
                                [alert setAlertStyle:NSWarningAlertStyle];
                                [alert setMessageText:@"Warning"];
                                [alert setInformativeText:@"Theres a pubkey mismatch for this nickname"];
                                [alert addButtonWithTitle:@"Yes"];
                                [alert addButtonWithTitle:@"No"];
                                
                                NSInteger alertResult = [alert runModal];
                            }
                        }
                        else
                        {
                            //
                            // Otherwise, add the pubkey as a crypto pal
                            //
                            pal = malloc(sizeof (struct crypto_pal_identity));
                            if (pal == NULL)
                            {
                                return;
                            }
                            
                            pal->nickname = strdup(senderNick);
                            if (pal->nickname == NULL) return;
                            pal->pubkey = malloc(crypto_box_PUBLICKEYBYTES);
                            if (pal->pubkey == NULL) return;
                            memcpy(pal->pubkey, senderPubkey, crypto_box_PUBLICKEYBYTES);
                            pal->flags = 0;
                            
                            [_cryptopals setValue:[NSValue valueWithPointer:pal] forKey:nickname];
                            [self refreshCryptoPalsList:_cryptopals];
                        }


                        
                        //
                        // Display the nickname and pubkey in hex
                        //

                        //
                        // Convert pubkey to hex
                        //
                        hexPubKey = [self toHex:senderPubkey withLen:32];
                        if (decoded_output != nil)
                        {
                            [decoded_output appendFormat:@"Public Key from %@ : %@\n",
                                              nickname, hexPubKey];
                        }
                        else
                        {
                            decoded_output = [NSMutableString stringWithFormat:@"Public Key from %@ : %@\n",
                                              nickname, hexPubKey];
                        }

                        if (msgType != encryptedWholeMessage)
                        {
                            break;
                        }
                        
                        //
                        // Falling through now to try to decrypt the message too...
                        //
                        if (!receiverPubkey) return;
                        if (!senderCiphertext) return;
                        
                        //
                        // If the receiver pub key matches our pubkey then decrypt it
                        //
                        [self selectActiveIdentity:nil];
                        
                        
                        if (_pk && (memcmp(_pk, receiverPubkey, crypto_box_PUBLICKEYBYTES) == 0))
                        {
                            int ret;
                            unsigned char *plaintext = NULL;
                            
                            unsigned char *ciphered;
                            ciphered = allocate_mem(cipherLen + crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES, 0);

                            memcpy(ciphered + crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES,
                                   senderCiphertext + crypto_box_NONCEBYTES,
                                   cipherLen - crypto_box_NONCEBYTES);

                            ret = nacl_decrypt(senderPubkey, _sk,
                                             senderCiphertext,
                                             ciphered + crypto_box_NONCEBYTES,
                                             cipherLen - crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES,
                                             &plaintext);
                            release_mem(ciphered);
                            if (ret != 0)
                            {
                                NSLog(@"Failed to decrypt!!! Ouch");
                            }
                            else
                            {
                                int i;
                                plaintext += crypto_box_PUBLICKEYBYTES;
                                
                                NSString *decryptedMessage = [[NSString alloc] initWithCString:plaintext encoding:NSUTF8StringEncoding];

                                plaintext -= crypto_box_PUBLICKEYBYTES;

                                //
                                // TODO, all of these strings that display plaintext will need
                                // safe memory backings that actually wipe strings from memory.
                                // UI might be a big PITA for this...
                                //
                                if (decoded_output != nil)
                                {
                                    [decoded_output appendFormat:@"Received message from %@ :: \"%@\"\n",nickname, decryptedMessage]                         ;
                                }
                                else
                                {
                                    decoded_output = [NSMutableString stringWithFormat:@"Received message from %@ :: \"%@\"\n",nickname, decryptedMessage];                                }

                                release_mem(plaintext);
                            }
                        }
                        else
                        {
                            //
                            // Message was for someone else
                            //
                            
                        }
                        
                        
                        break;
                    default:
                        break;
                }
                
            }
            release_blobs(b);
        }
        /*
        else
        {
            
            NSColor *textColor = [description isEqualToString:UIElementUtilitiesNoDescription] ? [NSColor grayColor] : [NSColor whiteColor];
            
            [descriptionField setTextColor:textColor];
            
            [descriptionField setStringValue:description];
        }
         */
    }

    if (decoded_output)
    {
        [descriptionField setStringValue:decoded_output];
        [_readWindow UpdateText: decoded_output];
    }
    else
    {
        [descriptionField setTextColor:[NSColor grayColor]];
        [descriptionField setStringValue:UIElementUtilitiesNoDescription];
    }
}
- (void)windowWillClose:(NSNotification *)note {
    [NSApp performSelector:@selector(terminate:) withObject:nil afterDelay:0];
}

- (IBAction)generateIdentityAction:(id)sender
{
    //
    // Grab the name from the field
    //
    NSString *nickname;
    nickname = [newIdentityNameField stringValue];

    /*
    NSString *prompt = [NSString stringWithFormat:@"Would you like to generate a new identity with nickname `%@`?", nickname];
    
    NSAlert *alert = [[[NSAlert alloc] init] autorelease];

    [alert setAlertStyle:NSWarningAlertStyle];
    [alert setMessageText:@"Generate key"];
    [alert setInformativeText:prompt];
    [alert addButtonWithTitle:@"Yes"];
    [alert addButtonWithTitle:@"No"];

    NSInteger alertResult = [alert runModal];
    
    switch (alertResult) {
        case NSAlertFirstButtonReturn:
            NSLog(@"Generate with %@", nickname);
            */
            [self generateIdentityWithName:nickname];
            [self selectActiveIdentity:nil];
    /*
            break;
            
        case NSAlertSecondButtonReturn: // just continue
        default:
            break;
            
        case NSAlertThirdButtonReturn:
            [NSApp terminate:self];
            return;
            break;
    }
     */

}

- (NSString*)prepareEncryptedMessage:(NSString *)myString
{
    char *rawblob = NULL;
    unsigned char *dst_pk;
    dst_pk = NULL;

    //
    // prime the secret key & pubkey
    //
    [self selectActiveIdentity:nil];

    //
    // Get the pubkey of the receiver
    //
    NSMenuItem *item = [cryptoPalsList selectedItem];
    if (item)
    {
        NSString *key = [item title];
        if (key)
        {
            NSValue *value = [_cryptopals objectForKey:key];
            if (value)
            {
                //NSLog(@"Value %@", value);
                struct crypto_pal_identity *pal;
                pal = [value pointerValue];
                dst_pk = pal->pubkey;
            }
        }
    }
    
    if (!dst_pk) return nil;

    
    if ((_nick == NULL) || (_pk == NULL) || (_sk == NULL))
    {
        //
        // Bail and maybe alert that an identity is needed
        //
        return nil;
    }
    
    //
    // Create the encrypted message blob for the target
    //

    //    NSString *myString = [messageField stringValue];
    char *cstr = [myString cStringUsingEncoding:NSUTF8StringEncoding];
    
    rawblob = create_encrypted_message(_nick, _pk, _sk, dst_pk,
                            cstr, strlen(cstr));
    if (rawblob == NULL)
    {
        //
        // Bail and maybe warn that something failed
        //
        return nil;
    }
    NSString *cryptoblob = [[NSString alloc] initWithCString:rawblob encoding:NSUTF8StringEncoding];
    
    free(rawblob);
    rawblob = NULL;

    return cryptoblob;
}
    
- (IBAction)copyEncryptedMsgToClipboard:(id)sender
{
    NSString *myString = [messageField stringValue];
    NSString *cryptoblob = [self prepareEncryptedMessage:myString];

    NSPasteboard *pasteBoard = [NSPasteboard generalPasteboard];
    [pasteBoard declareTypes:[NSArray arrayWithObjects:NSStringPboardType, nil] owner:nil];
    [pasteBoard setString:cryptoblob forType:NSStringPboardType];

}

- (IBAction)copyPubkeyToClipboard:(id)sender
{
    char *rawblob = NULL;

    [self selectActiveIdentity:nil];
    
    if ((_nick == NULL) || (_pk == NULL))
    {
        //
        // Bail and maybe alert that an identity is needed
        //
        return;
    }
    
    rawblob = create_pubkey_message(_nick, _pk);
    if (rawblob == NULL)
    {
        //
        // Bail and maybe warn that something failed
        //
        return;
    }
    NSString *cryptoblob = [[NSString alloc] initWithCString:rawblob encoding:NSUTF8StringEncoding];
    
    free(rawblob);
    rawblob = NULL;
    

    NSPasteboard *pasteBoard = [NSPasteboard generalPasteboard];
    [pasteBoard declareTypes:[NSArray arrayWithObjects:NSStringPboardType, nil] owner:nil];
    [pasteBoard setString:cryptoblob forType:NSStringPboardType];
}

- (IBAction)selectActiveIdentity:(id)sender;
{
    NSMenuItem *item = [identityList selectedItem];
    if (item)
    {
        NSString *key = [item title];
        if (key)
        {
            NSValue *value = [_identities objectForKey:key];
            if (value)
            {
                struct crypto_self_identity *identity;
                identity = [value pointerValue];
                _pk = identity->pubkey;
                _sk = identity->seckey;
                _nick = identity->nickname;
                //printf("%s\n", identity->nickname);
            }
        }
    }
}

extern BOOL g_LookingForOutputTarget;
- (IBAction)selectOutputChannel:(id)sender
{
    g_LookingForOutputTarget = TRUE;
}

- (void)setOutputTarget:(AXUIElementRef)uiElement
{
    pid_t pid;
    pid = [UIElementUtilities processIdentifierOfUIElement:_outputTarget];
    [(id)_outputTarget autorelease];
    _outputTarget = (AXUIElementRef)[(id)uiElement retain];
    _outputApplication = AXUIElementCreateApplication(pid);
}

- (void) appendAXWriteableOutput:(NSString*) input
{
    //
    // Copy the current value and append the input string
    //
    NSMutableString *str = [[NSMutableString alloc] init];
    
    NSString * description = [UIElementUtilities descriptionForUIElement:_outputTarget attribute:@"AXValue" beingVerbose:false];
    
    [str appendFormat:@"%@%@", input, description];
    [self setAxWriteableOutput: [NSString stringWithString:str]];
}

- (void) setAxWriteableOutput:(NSString*) input
{
    /*
      TODO: check writeable and check role, StaticText role won't work and neither will read only
     */
    AXError status;
    //
    // XXX: could replace this with copy to clipboard & paste.... 
    //
    status = AXUIElementSetAttributeValue(_outputTarget, kAXValueAttribute, input);
    
    /*
    //
    //paste
    //
    
     //
     // Notes.app, etc that do fail also fail this with kAXErrorFailure
     // May need to switch to CGPostEvent and change focus...
     //
     //
     //
    status = AXUIElementPostKeyboardEvent(_outputApplication, (CGCharCode)0, kVK_Command, true ); // Command down
    NSLog(@"Status %d\n", status);
    usleep(100);
    status = AXUIElementPostKeyboardEvent(_outputApplication, (CGCharCode)'v', kVK_ANSI_V, true ); // V down
    usleep(100);
    NSLog(@"Status %d\n", status);
    status = AXUIElementPostKeyboardEvent(_outputApplication, (CGCharCode)'v', kVK_ANSI_V, false ); //  V up
    usleep(100);
    NSLog(@"Status %d\n", status);
    status = AXUIElementPostKeyboardEvent(_outputApplication, (CGCharCode)0, kVK_Command, false ); // Command up
    usleep(100);
    NSLog(@"Status %d\n", status);
//     */
    
    status = AXUIElementPostKeyboardEvent(_outputApplication,
                                          0,
                                          kVK_Return,
                                          TRUE);
    usleep(100);
    status = AXUIElementPostKeyboardEvent(_outputApplication,
                                          0,
                                          kVK_Return,
                                          FALSE);
}

- (IBAction) sendWrite:(id)sender
{
    NSString *val = [messageField stringValue];
    if ([val length] > 0)
    {
        [self appendAXWriteableOutput:[self prepareEncryptedMessage:val]];
        [messageField setStringValue:@""];
    }
}
@end
