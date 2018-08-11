//
//  kpp.c
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


