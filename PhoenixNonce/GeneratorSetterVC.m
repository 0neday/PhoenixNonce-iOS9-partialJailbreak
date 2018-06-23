/*
 * GeneratorSetterVC.m - UI stuff
 *
 * Copyright (c) 2017 Siguza & tihmstar
 */

#include "load_payload.h"
#import "GeneratorSetterVC.h"

@interface GeneratorSetterVC ()

@end

@implementation GeneratorSetterVC

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

-(void)failedWithError:(NSString*)error{
    self.errorLabel.hidden = NO;
    [self.errorLabel setTextColor:[UIColor redColor]];
    self.errorLabel.text = error;
}


- (IBAction)kbDoneBtnPressed:(id)sender {
    [self.textfield endEditing:YES];
}

- (IBAction)btnDumpPressed:(id)sender {
    self.errorLabel.hidden = YES;
   // bool ret = dump_apticket([[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:@"apticket.der"].UTF8String);
	
				load_payload();

        self.errorLabel.hidden = NO;
        [self.errorLabel setTextColor:[UIColor greenColor]];
        self.errorLabel.text = @"Get tfp0, root and sandbox escape";
  }

@end
