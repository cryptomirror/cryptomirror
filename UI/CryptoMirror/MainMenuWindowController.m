#import "MainMenuWindowController.h"
#import "UIElementUtilities.h"

@implementation MainMenuWindowController

- (void)awakeFromNib {
    
}

- (void)updateInfoForUIElement:(AXUIElementRef)uiElement {

    NSString * description = [UIElementUtilities descriptionForUIElement:uiElement attribute:@"AXValue" beingVerbose:false];
    
    if (description)
    {
        NSColor *textColor = [description isEqualToString:UIElementUtilitiesNoDescription] ? [NSColor grayColor] : [NSColor whiteColor];

        [descriptionField setTextColor:textColor];
      
        [descriptionField setStringValue:description];
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

@end
