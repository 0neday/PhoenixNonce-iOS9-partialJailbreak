//
//  kppless.c
//  PhoenixNonce
//
//  Created by hongs on 2018/6/24.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <stdio.h>

//
//  jailbreak.m
//  yalu102
//
//  Created by qwertyoruiop on 07/01/2017.
//  Copyright © 2017 kimjongcracks. All rights reserved.
//

#import <mach/mach.h>

#import <pthread.h>
#import <mach/mach.h>

#import <sys/mount.h>
#import <spawn.h>
#import <copyfile.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/utsname.h>

#import "common.h"

#define vm_address_t mach_vm_address_t

mach_port_t tfp0=0;
uint64_t slide=0;
// #define NSLog(...)
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);


void prepare_rwk_via_tfp0(mach_port_t port) {
	tfp0 = port;
}

void copyin(void* to, uint64_t from, size_t size) {
	mach_vm_size_t outsize = size;
	size_t szt = size;
	if (size > 0x1000) {
		size = 0x1000;
	}
	size_t off = 0;
	while (1) {
		mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
		szt -= size;
		off += size;
		if (szt == 0) {
			break;
		}
		size = szt;
		if (size > 0x1000) {
			size = 0x1000;
		}
		
	}
}

void copyout(uint64_t to, void* from, size_t size) {
	mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint64_t ReadAnywhere64(uint64_t addr) {
	uint64_t val = 0;
	copyin(&val, addr, 8);
	return val;
}

uint64_t WriteAnywhere64(uint64_t addr, uint64_t val) {
	copyout(addr, &val, 8);
	return val;
}

uint32_t ReadAnywhere32(uint64_t addr) {
	uint32_t val = 0;
	copyin(&val, addr, 4);
	return val;
}

uint64_t WriteAnywhere32(uint64_t addr, uint32_t val) {
	copyout(addr, &val, 4);
	return val;
}



size_t kread(uint64_t where, void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        
        if (rv || sz == 0) {
            break;
        }
        
        offset += sz;
    }
    return offset;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0,
                           where + offset,
                           (mach_vm_offset_t)p + offset,
                           (mach_msg_type_number_t)chunk);
        
        if (rv) {
            printf("[kernel] error copying buffer into region: @%p \n", (void *)(offset + where));
            break;
        }
        
        offset +=chunk;
    }
    
    return offset;
}

uint32_t rk32(uint64_t kaddr) {
    kern_return_t err;
    uint32_t val = 0;
    mach_vm_size_t outsize = 0;
    
    kern_return_t mach_vm_write(vm_map_t target_task,
                                mach_vm_address_t address,
                                vm_offset_t data,
                                mach_msg_type_number_t dataCnt);
    
    err = mach_vm_read_overwrite(tfp0,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)sizeof(uint32_t),
                                 (mach_vm_address_t)&val,
                                 &outsize);
    
    if (err != KERN_SUCCESS) {
        return 0;
    }
    
    if (outsize != sizeof(uint32_t)) {
        return 0;
    }
    
    return val;
}

uint64_t rk64(uint64_t kaddr) {
    uint64_t lower = rk32(kaddr);
    uint64_t higher = rk32(kaddr + 4);
    return ((higher << 32) | lower);
}



void wk32(uint64_t kaddr, uint32_t val) {
    if (tfp0 == MACH_PORT_NULL) {
        return;
    }
    
    kern_return_t err;
    err = mach_vm_write(tfp0,
                        (mach_vm_address_t)kaddr,
                        (vm_offset_t)&val,
                        (mach_msg_type_number_t)sizeof(uint32_t));
    
    if (err != KERN_SUCCESS) {
        return;
    }
}

void wk64(uint64_t kaddr, uint64_t val) {
    uint32_t lower = (uint32_t)(val & 0xffffffff);
    uint32_t higher = (uint32_t)(val >> 32);
    wk32(kaddr, lower);
    wk32(kaddr + 4, higher);
}





#include <stdio.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include "kppless.h"
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


