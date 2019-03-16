//
//  AppDelegate.h
//  partialJailbreak
//
//  Created by hongs on 8/11/18.
//  Copyright © 2018 hongs. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (strong, atomic) NSPipe *combinedPipe;
@property (assign) int orig_stderr;
@property (assign) int orig_stdout;

@end

