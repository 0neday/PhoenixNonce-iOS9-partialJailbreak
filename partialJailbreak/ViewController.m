//
//  ViewController.m
//  partialJailbreak
//
//  Created by hongs on 8/11/18.
//  Copyright © 2018 hongs. All rights reserved.
//

#import "ViewController.h"
#include <sys/sysctl.h>

#include "jailbreak.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UILabel *notfiyLabel;

@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;


@end

@implementation ViewController

double uptime(void);

- (void)viewDidLoad {
    [super viewDidLoad];
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
        [self.notfiyLabel setText:[NSString stringWithFormat:@"Did we mount / as read + write? %s\n", file_exist("/.bit_of_fun") ? "yes" : "no"]];
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

@end
