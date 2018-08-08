//
//  kernel_utils.c
//  PhoenixNonce
//
//  Created by hongs on 7/27/18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>

#include "kernel_utils.h"


// https://github.com/JonathanSeals/kernelversionhacker/blob/master/kernelversionhacker.c

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_IOS9 0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_IOS 0xffffff8000000000

#define ptrSize sizeof(uintptr_t)

vm_address_t find_kernel_base(mach_port_t kernel_task) {
    uint64_t addr = 0;
    
    struct utsname u = {0};
    uname(&u);
    uint64_t osRelease = strtol(u.release, NULL, 0);

    
    /* iOS 10 and 11 share the same default kernel slide */
    if (osRelease == 16 || osRelease == 17) {
        addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    }
    
    else if (osRelease == 15) {
        addr = KERNEL_SEARCH_ADDRESS_IOS9+MAX_KASLR_SLIDE;
    }
    
    else if (osRelease >= 18) {
        printf("This is an unknown kernel version, trying iOS 10/11 default address. If you panic, this is probably the cause\n");
        addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    }
    
    /* This function shouldn't be getting called on iOS 8 or lower */
    else return -1;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(kernel_task, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(kernel_task, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(kernel_task, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
    
    printf("ERROR: Failed to find kernel base.\n");
    exit(1);
}


uint64_t find_proc_by_name(char* name, uintptr_t kern_proc_addr) {
    uint64_t proc = kread64(kern_proc_addr + 0x08);
    
    while (proc) {
        char proc_name[40] = { 0 };
        
        kread(proc + 0x26c, proc_name, 40);
        
        if (!strcmp(name, proc_name)) {
            return proc;
        }
        
        proc = kread64(proc + 0x08);
    }
    
    return 0;
}

int patchContainermanagerd(uintptr_t kern_kauth_cred_addr, uintptr_t kern_proc_addr) {
    uint64_t cmgr = find_proc_by_name("containermanager", kern_proc_addr);
    if (cmgr == 0) {
        printf("unable to find containermanager!\n");
        return 1;
    }
    
    kwrite64(cmgr + 0x100, kern_kauth_cred_addr);
    return 0;
}
