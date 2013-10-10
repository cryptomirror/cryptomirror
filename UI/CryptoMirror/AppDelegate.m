/*
 File: AppDelegate.m
 Abstract: This is the header for the AppDelegate class that handles the bulk of the real
 accessibility work of finding out what is under the cursor.  The InspectorWindowController and
 InteractionWindowController classes handle the display and interaction with the accessibility information.
 
 This sample demonstrates the Accessibility API introduced in Mac OS X 10.2.
 
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
#import <AppKit/NSAccessibility.h>
#import <Carbon/Carbon.h>
#import "AppDelegate.h"
#import "MainMenuWindowController.h"
#import "ReadWindowController.h"

AppDelegate* g_AppDelegate;
BOOL g_LookingForOutputTarget;

@interface AppDelegate (Private)
- (BOOL)isInteractionWindowVisible;
@end

#pragma mark Hot Key Registration And Handler

EventHotKeyRef	gMyHotKeyRef;

// -------------------------------------------------------------------------------
//	LockUIElementHotKeyHandler:
//
//	We only register for one hotkey, so if we get here we know the hotkey combo was pressed
//	and we should go ahead and lock/unlock the current UIElement as needed
// -------------------------------------------------------------------------------
OSStatus LockUIElementHotKeyHandler(EventHandlerCallRef nextHandler,EventRef theEvent, void *userData)
{
    return noErr;
}

// -------------------------------------------------------------------------------
//	RegisterLockUIElementHotKey:
//
//	Encapsulate registering a hot key in one location
//	and we should go ahead and lock/unlock the current UIElement as needed
// -------------------------------------------------------------------------------
static OSStatus RegisterLockUIElementHotKey(void *userInfo) {
    
    EventTypeSpec eventType = { kEventClassKeyboard, kEventHotKeyReleased };
    InstallApplicationEventHandler(NewEventHandlerUPP(LockUIElementHotKeyHandler), 1, &eventType,(void *)userInfo, NULL);
    
    EventHotKeyID hotKeyID = { 'lUIk', 1 }; // we make up the ID
    return RegisterEventHotKey(kVK_F7, cmdKey, hotKeyID, GetApplicationEventTarget(), 0, &gMyHotKeyRef); // Cmd-F7 will be the key to hit
    
}

#pragma mark -


@implementation AppDelegate

- (id)init {
    if (self = [super init]) {
        g_AppDelegate = self;
    }
    return self;
}

- (void)dealloc {
    [_mainMenuWindowController release];
    if (_systemWideElement) CFRelease(_systemWideElement);
    if (_currentUIElement) CFRelease(_currentUIElement);
    [super dealloc];
}

- (void)applicationDidFinishLaunching:(NSNotification *)note {
    
    // We first have to check if the Accessibility APIs are turned on.  If not, we have to tell the user to do it (they'll need to authenticate to do it).  If you are an accessibility app (i.e., if you are getting info about UI elements in other apps), the APIs won't work unless the APIs are turned on.
    if (!AXAPIEnabled())
    {
        
        NSAlert *alert = [[[NSAlert alloc] init] autorelease];
        
        [alert setAlertStyle:NSWarningAlertStyle];
        [alert setMessageText:@"UI Element Inspector requires that the Accessibility API be enabled."];
        [alert setInformativeText:@"Would you like to launch System Preferences so that you can turn on \"Enable access for assistive devices\"?"];
        [alert addButtonWithTitle:@"Open System Preferences"];
        [alert addButtonWithTitle:@"Continue Anyway"];
        [alert addButtonWithTitle:@"Quit UI Element Inspector"];
        
        NSInteger alertResult = [alert runModal];
        
        switch (alertResult) {
            case NSAlertFirstButtonReturn: {
                NSArray *paths = NSSearchPathForDirectoriesInDomains(NSPreferencePanesDirectory, NSSystemDomainMask, YES);
                if ([paths count] == 1) {
                    NSURL *prefPaneURL = [NSURL fileURLWithPath:[[paths objectAtIndex:0] stringByAppendingPathComponent:@"UniversalAccessPref.prefPane"]];
                    [[NSWorkspace sharedWorkspace] openURL:prefPaneURL];
                }
            }
                break;
                
            case NSAlertSecondButtonReturn: // just continue
            default:
                break;
                
            case NSAlertThirdButtonReturn:
                [NSApp terminate:self];
                return;
                break;
        }
    }
    
    _systemWideElement = AXUIElementCreateSystemWide();
    
    // Pass self in for userInfo, gives us a pointer to ourselves in handler function
    RegisterLockUIElementHotKey((void *)self);

    _readWindowController = [[ReadWindowController alloc] initWithWindowNibName:@"ReadWindow"];
    [_readWindowController setWindowFrameAutosaveName:@"ReadWindow"];
    [_readWindowController showWindow:nil];

    _mainMenuWindowController = [[MainMenuWindowController alloc] initWithWindowNibName:@"MainMenu"];
    [_mainMenuWindowController setReadWindow:_readWindowController];
    [_mainMenuWindowController setWindowFrameAutosaveName:@"MainMenu"];
    [_mainMenuWindowController showWindow:nil];

    [self performTimerBasedUpdate];
}

#pragma mark -

// -------------------------------------------------------------------------------
//	setCurrentUIElement:uiElement
// -------------------------------------------------------------------------------
- (void)setCurrentUIElement:(AXUIElementRef)uiElement
{
    [(id)_currentUIElement autorelease];
    _currentUIElement = (AXUIElementRef)[(id)uiElement retain];
}

// -------------------------------------------------------------------------------
//	currentUIElement:
// -------------------------------------------------------------------------------
- (AXUIElementRef)currentUIElement
{
    return _currentUIElement;
}


#pragma mark -

// -------------------------------------------------------------------------------
//	performTimerBasedUpdate:
//
//	Timer to continually update the current uiElement being examined.
// -------------------------------------------------------------------------------
- (void)performTimerBasedUpdate
{
    [self updateCurrentUIElement];
    
    [NSTimer scheduledTimerWithTimeInterval:0.1 target:self selector:@selector(performTimerBasedUpdate) userInfo:nil repeats:NO];
}


- (void)updateUIElementInfoWithAnimation:(BOOL)flag {
    AXUIElementRef element = [self currentUIElement];
    [_mainMenuWindowController updateInfoForUIElement:element];
}



// -------------------------------------------------------------------------------
//	updateCurrentUIElement:
// -------------------------------------------------------------------------------
- (void)updateCurrentUIElement
{
    if (1 /* should update */) {
        // The current mouse position with origin at top right.
        NSPoint cocoaPoint = [NSEvent mouseLocation];
        NSUInteger buttonsDown = [NSEvent pressedMouseButtons];
        
        // Only ask for the UIElement under the mouse if has moved since the last check.
        //if (!NSEqualPoints(cocoaPoint, _lastMousePoint) || (g_LookingForOutputTarget && (buttonsDown & 1)))
        {

            NSScreen *foundScreen = nil;
            CGPoint thePoint;
            
            for (NSScreen *screen in [NSScreen screens]) {
                if (NSPointInRect(cocoaPoint, [screen frame])) {
                    foundScreen = screen;
                }
            }
            
            if (foundScreen) {
                CGFloat screenHeight = [foundScreen frame].size.height;
                
                thePoint = CGPointMake(cocoaPoint.x, screenHeight - cocoaPoint.y - 1);
            } else {
                thePoint = CGPointMake(0.0, 0.0);
            }

            
            CGPoint pointAsCGPoint = thePoint;
            
            AXUIElementRef newElement = NULL;
            
            // Ask Accessibility API for UI Element under the mouse
            // And update the display if a different UIElement
            if (AXUIElementCopyElementAtPosition( _systemWideElement, pointAsCGPoint.x, pointAsCGPoint.y, &newElement ) == kAXErrorSuccess
                && newElement) {

                if (buttonsDown & 1)
                {
                    if (g_LookingForOutputTarget)
                    {
                        [self setOutputTarget:newElement];
                        g_LookingForOutputTarget = FALSE;
                    }
                }

                //if([self currentUIElement] == NULL || ! CFEqual( [self currentUIElement], newElement ))
                {
                    [self setCurrentUIElement:newElement];
                    [self updateUIElementInfoWithAnimation:NO];
                }
            }
            
            _lastMousePoint = cocoaPoint;
        }
    }
}

#pragma mark -

// -------------------------------------------------------------------------------
//	isInteractionWindowVisible:
// -------------------------------------------------------------------------------
- (BOOL)isInteractionWindowVisible
{
    return false; //[[_interactionWindowController window] isVisible];
}
#pragma mark -


// -------------------------------------------------------------------------------
//	refreshInteractionUIElement:sender
// -------------------------------------------------------------------------------
- (void)refreshInteractionUIElement:(id)sender
{
    [self updateUIElementInfoWithAnimation:YES];
}


// -------------------------------------------------------------------------------
//	setCurrentUIElement:uiElement
// -------------------------------------------------------------------------------
- (void)setOutputTarget:(AXUIElementRef)uiElement
{
    [_mainMenuWindowController setOutputTarget:uiElement];
}
@end

