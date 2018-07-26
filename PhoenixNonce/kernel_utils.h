//
//  kernel_utils.h
//  PhoenixNonce
//
//  Created by hongs on 7/27/18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef kernel_utils_h
#define kernel_utils_h

#include <stdio.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>

vm_address_t find_kernel_base(task_t kernel_task);

#endif /* kernel_utils_h */
