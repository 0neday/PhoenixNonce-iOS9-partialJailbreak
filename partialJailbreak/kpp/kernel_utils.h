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
#include "kpp.h"

#define kread32 ReadAnywhere32
#define kwrite32 WriteAnywhere32
#define kread64 ReadAnywhere64
#define kwrite64 WriteAnywhere64
#define kread(from, to, size) copyin(to, from, size)
#define kwrite(to, from, size) copyout(to, from, size)


vm_address_t find_kernel_base(task_t kernel_task);
int patchContainermanagerd(uintptr_t kern_kauth_cred_addr, uintptr_t kern_proc_addr);

#endif /* kernel_utils_h */
