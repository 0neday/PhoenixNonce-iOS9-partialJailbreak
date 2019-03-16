//
//  ViewController.m
//  partialJailbreak
//
//  Created by hongs on 8/11/18.
//  Copyright © 2018 hongs. All rights reserved.
//

#import "ViewController.h"
#include <sys/sysctl.h>
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <mach/mach.h>
#include <sys/utsname.h>
#include <sys/time.h>

#include "jailbreak.h"

@interface ViewController ()


@end

@implementation ViewController

static ViewController *sharedController = nil;
static NSMutableString *output = nil;

#define LOG(str, args...) do { NSLog(@"[*] " str , ##args); } while(false)

double uptime(void);

- (void)viewDidLoad {
    [super viewDidLoad];
    
    sharedController = self;
    
    
    NSString *ver = [[NSProcessInfo processInfo] operatingSystemVersionString];
    struct utsname u;
    uname(&u);
    printf("-----------------------------------\n");
    LOG("Device: %s", u.machine);
    LOG("iOS Version: %@", ver);
    LOG("%s", u.version);
    
    
    //set textview
    [self.outputView setEditable:NO];
    [self.outputView setSelectable:NO];
    [self.outputView setContentInset:UIEdgeInsetsMake(-5, 1, -5, -5)];
    [self.outputView setTextAlignment:NSTextAlignmentLeft];
    self.outputView.layoutManager.allowsNonContiguousLayout = NO;
    self.outputView.scrollEnabled = YES;
    self.outputView.textContainer.lineBreakMode = NSLineBreakByWordWrapping;
    self.outputView.textContainer.lineFragmentPadding = 0;
    
    // Do any additional setup after loading the view, typically from a nib.
    //wait 90s after restart device
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        int waitTime;
        [self.jailbreakButton setEnabled:NO];
        while ((waitTime = 90 - uptime()) > 0) { 
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.jailbreakButton setTitle:[NSString stringWithFormat:@"wait: %d", waitTime] forState:UIControlStateNormal];
            });
            sleep(1);
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.jailbreakButton setTitle:@"go" forState:UIControlStateNormal];
            [self.jailbreakButton setEnabled:YES];
        });
    });
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)go:(id)sender {
    if(jailbreak() == 0){
        [self.jailbreakButton setTitle:@"Jailbreaked" forState:UIControlStateNormal];
    }
    else
        [self.notfiyLabel setText:@"Failed!"];
    [self.jailbreakButton setEnabled:NO];
}


- (void) touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    
    [self.view endEditing:YES];
}

double uptime(){
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 )
    {
        return -1.0;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);
    
    return difftime(csec, bsec);
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleDefault;
}

// This intentionally returns nil if called before it's been created by a proper init
+(ViewController *)sharedController {
    return sharedController;
}

-(void)updateOutputView {
    [self updateOutputViewFromQueue:@NO];
}

-(void)updateOutputViewFromQueue:(NSNumber*)fromQueue {
    static BOOL updateQueued = NO;
    static struct timeval last = {0,0};
    static dispatch_queue_t updateQueue;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        updateQueue = dispatch_queue_create("updateView", NULL);
    });
    
    dispatch_async(updateQueue, ^{
        struct timeval now;
        
        if (fromQueue.boolValue) {
            updateQueued = NO;
        }
        
        if (updateQueued) {
            return;
        }
        
        if (gettimeofday(&now, NULL)) {
            //LOG("gettimeofday failed");
            return;
        }
        
        uint64_t elapsed = (now.tv_sec - last.tv_sec) * 1000000 + now.tv_usec - last.tv_usec;
        // 30 FPS
        if (elapsed > 1000000/30) {
            updateQueued = NO;
            gettimeofday(&last, NULL);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.outputView.text = output;
                [self.outputView scrollRangeToVisible:NSMakeRange(self.outputView.text.length, 0)];
            });
        } else {
            NSTimeInterval waitTime = ((1000000/30) - elapsed) / 1000000.0;
            updateQueued = YES;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self performSelector:@selector(updateOutputViewFromQueue:) withObject:@YES afterDelay:waitTime];
            });
        }
    });
}

-(void)appendTextToOutput:(NSString *)text {
    if (self.outputView == nil) {
        return;
    }
    static NSRegularExpression *remove = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        remove = [NSRegularExpression regularExpressionWithPattern:@"^\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\.\\d+[-\\d\\s]+\\S+\\[\\d+:\\d+\\]\\s+"
                                                           options:NSRegularExpressionAnchorsMatchLines error:nil];
        output = [NSMutableString new];
    });
    
    text = [remove stringByReplacingMatchesInString:text options:0 range:NSMakeRange(0, text.length) withTemplate:@""];
    
    @synchronized (output) {
        [output appendString:text];
    }
    [self updateOutputView];
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithCoder:aDecoder];
        }
    }
    self = sharedController;
    return self;
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
        }
    }
    self = sharedController;
    return self;
}

- (id)init {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super init];
        }
    }
    self = sharedController;
    return self;
}

@end
