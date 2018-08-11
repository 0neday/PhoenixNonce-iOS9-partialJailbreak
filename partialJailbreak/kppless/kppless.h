//
//  kppless.h
//  PhoenixNonce
//
//  Created by hongs on 2018/6/24.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef kppless_h
#define kppless_h

#include <stdio.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include "kppless.h"



extern task_t tfp0;

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

void prepare_rwk_via_tfp0(mach_port_t port);
uint64_t ReadAnywhere64(uint64_t addr);
uint64_t WriteAnywhere64(uint64_t addr, uint64_t val);
uint32_t ReadAnywhere32(uint64_t addr);
uint64_t WriteAnywhere32(uint64_t addr, uint32_t val);
void copyin(void* to, uint64_t from, size_t size);
void copyout(uint64_t to, void* from, size_t size);

size_t kread(uint64_t where, void *p, size_t size);
size_t kwrite(uint64_t where, const void *p, size_t size);
uint32_t rk32(uint64_t kaddr);
uint64_t rk64(uint64_t kaddr);
void wk32(uint64_t kaddr, uint32_t val);
void wk64(uint64_t kaddr, uint64_t val);



//
#define kread32 ReadAnywhere32
#define kwrite32 WriteAnywhere32
#define kread64 ReadAnywhere64
#define kwrite64 WriteAnywhere64

vm_address_t find_kernel_base(task_t kernel_task);
int patchContainermanagerd(uintptr_t kern_kauth_cred_addr, uintptr_t kern_proc_addr);


#endif /* kppless_h */

