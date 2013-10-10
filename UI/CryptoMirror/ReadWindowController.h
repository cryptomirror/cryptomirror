#import <Cocoa/Cocoa.h>

@interface ReadWindowController : NSWindowController
{
    IBOutlet NSTextField *textDescription;
}

//
// Read view
//
//[[[NSApplication sharedApplication] _readWindowController] updateText: text];

- (void) UpdateText:(NSString*)string;

@end
