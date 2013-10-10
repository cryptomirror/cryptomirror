#import "ReadWindowController.h"
#import "UIElementUtilities.h"
#import "AppDelegate.h"
#import "common.h"
#import "blobber.h"
#import "messages.h"
#include "nacl.h"

@implementation ReadWindowController

- (void)awakeFromNib {
    
}

- (void)windowWillClose:(NSNotification *)note {
    [NSApp performSelector:@selector(terminate:) withObject:nil afterDelay:0];
}

- (void) UpdateText:(NSString*)string
{
    [textDescription setTextColor:[NSColor whiteColor]];
    [textDescription setStringValue:string];
}

@end
