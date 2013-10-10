/*
     File: DescriptionInspectorWindowController.h 
 Abstract: The Description Inspector window controller.
  
  Version: 1.4 
  
 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple 
 Inc. ("Apple") in consideration of your agreement to the following 
 terms, and your use, installation, modification or redistribution of 
 this Apple software constitutes acceptance of these terms.  If you do 
 not agree with these terms, please do not use, install, modify or 
 redistribute this Apple software. 
  
 In consideration of your agreement to abide by the following terms, and 
 subject to these terms, Apple grants you a personal, non-exclusive 
 license, under Apple's copyrights in this original Apple software (the 
 "Apple Software"), to use, reproduce, modify and redistribute the Apple 
 Software, with or without modifications, in source and/or binary forms; 
 provided that if you redistribute the Apple Software in its entirety and 
 without modifications, you must retain this notice and the following 
 text and disclaimers in all such redistributions of the Apple Software. 
 Neither the name, trademarks, service marks or logos of Apple Inc. may 
 be used to endorse or promote products derived from the Apple Software 
 without specific prior written permission from Apple.  Except as 
 expressly stated in this notice, no other rights or licenses, express or 
 implied, are granted by Apple herein, including but not limited to any 
 patent rights that may be infringed by your derivative works or by other 
 works in which the Apple Software may be incorporated. 
  
 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE 
 MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION 
 THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS 
 FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND 
 OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS. 
  
 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL 
 OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, 
 MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED 
 AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE), 
 STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE 
 POSSIBILITY OF SUCH DAMAGE. 
  
 Copyright (C) 2010 Apple Inc. All Rights Reserved. 
  
 */

#import <Cocoa/Cocoa.h>


/*
  It's stupid to work with structs,  these need to be switched to interfaces.
*/
struct crypto_pal_identity {
    char *nickname;
    char *pubkey;
    unsigned int flags;
} ;

struct crypto_self_identity {
    char *nickname;
    unsigned char *pubkey;
    unsigned char *seckey;
    unsigned int flags;
};


@class ReadWindowController;

@interface MainMenuWindowController : NSWindowController {

    IBOutlet NSTextField *descriptionField;
    IBOutlet NSTextField *messageField;
    IBOutlet NSWindow *myWindow;

    IBOutlet NSButton *generateIdentityButton;
    IBOutlet NSTextField *newIdentityNameField;
    IBOutlet NSPopUpButton *identityList;
    IBOutlet NSPopUpButton *cryptoPalsList;
    IBOutlet NSPopUpButton *cryptoPalsList2;

    char *_nick;
    unsigned char *_pk, *_sk;
    NSMutableDictionary *_identities;
    NSMutableDictionary *_cryptopals;
    
    AXUIElementRef _outputTarget;
    AXUIElementRef _outputApplication;
    ReadWindowController *_readWindow;
}
//
// Helpers
//
- (NSString*)toHex:(char*)str withLen:(int)len;
- (void)setReadWindow:(ReadWindowController*)rw;


//
// Pals view
//
- (IBAction)generateIdentityAction:(id)sender;
- (IBAction)copyPubkeyToClipboard:(id)sender;
- (IBAction)selectActiveIdentity:(id)sender;
- (void)updateInfoForUIElement:(AXUIElementRef)uiElement;
- (void)refreshIdentityList:(NSMutableDictionary*)dict;
- (void)refreshCryptoPalsList:(NSMutableDictionary*)dict;
- (void)generateIdentityWithName:(NSString*)name;
- (void)setOutputTarget:(AXUIElementRef)uiElement;


//
// Send view
//
- (IBAction)copyEncryptedMsgToClipboard:(id)sender;
- (IBAction)selectOutputChannel:(id)sender;
- (IBAction) sendWrite:(id)sender;
- (void) appendAXWriteableOutput:(NSString*) input;
- (void) setAxWriteableOutput:(NSString*) input;
- (NSString*) prepareEncryptedMessage:(NSString *)myString;


//
// Read view
//


@end
