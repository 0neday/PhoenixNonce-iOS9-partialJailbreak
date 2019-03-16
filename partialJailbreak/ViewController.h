//
//  ViewController.h
//  partialJailbreak
//
//  Created by hongs on 8/11/18.
//  Copyright © 2018 hongs. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

@property (weak, nonatomic) IBOutlet UILabel *notfiyLabel;
@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;
@property (weak, nonatomic) IBOutlet UITextView *outputView;
@property (readonly) ViewController *sharedController;

+(ViewController*)sharedController;
- (void)appendTextToOutput:(NSString*)text;

@end

