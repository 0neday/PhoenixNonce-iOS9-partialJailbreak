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


int file_exist (char *filename)
{
	struct stat   buffer;
	return (stat (filename, &buffer) == 0);
}


// remount root partition r/W
int remount_rw(task_t tfp0) {

	// prepare kernel r/w
	prepare_rwk_via_tfp0(tfp0);
	uint64_t rootfs_vnode = ReadAnywhere64(OFFSET_ROOT_MOUNT_V_NODE);
	
	struct utsname uts;
	uname(&uts);
	
	vm_offset_t off = 0xd8;
	if (strstr(uts.version, "16.0.0")) {
		off = 0xd0;
	}
	
	uint64_t v_mount = ReadAnywhere64(rootfs_vnode+off);
	
	uint32_t v_flag = ReadAnywhere32(v_mount + 0x71);
	
	WriteAnywhere32(v_mount + 0x71, v_flag & (~(0x1<<6)));
	
	char* nmz = strdup("/dev/disk0s1s1");
	int lolr = mount( "hfs", "/", MNT_UPDATE, (void*)&nmz);
	NSLog(@"remounting: %d", lolr);
	
	v_mount = ReadAnywhere64(rootfs_vnode+off);
	
	WriteAnywhere32(v_mount + 0x71, v_flag);
	
	int fd = open("/.bit_of_fun", O_RDONLY);
	if (fd == -1) {
		fd = creat("/.bit_of_fun", 0644);
	} else {
		printf("File already exists!\n");
	}
	close(fd);
	
	printf("Did we mount / as read+write? %s\n", file_exist("/.bit_of_fun") ? "yes" : "no");
	
	//printf("first four values of amficache: %08x\n", rk32(find_amficache()));
	//printf("trust cache at: %016llx\n", rk64(find_trustcache()));
	return 0;
}


static int party_hard(void)
{
	int ret = 0;
	if(getuid() != 0) // Skip if we got root already
	{
		ret = -1;
		vm_address_t kbase = 0;
		task_t kernel_task = get_kernel_task(&kbase);
		LOG("kernel_task: 0x%x", kernel_task);
		printf("kernel base:  0x%lx\n",kbase);
		//remount_rw(kernel_task);
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
		NSString *kernelcache = [execpath stringByAppendingPathComponent:@"kernelcache-decrypt-6s-n71ap-9.3"];
		
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
		copyfile([kernelcache UTF8String], "/tmp/kernelcache-decrypt", 0, COPYFILE_ALL);
		
		//chmod
		chmod("/tmp/tar-sig", 0755);
		//  chmod("/bin/sh", 0755);
		chmod("/tmp/bash-arm64-sig", 0755);
		chmod("/tmp/dropbear-sig", 0755);
		

		/* untar bootstrap.tar */
		printf("untar and drop bootstrap.tar into /tmp\n");
		FILE *a = fopen([bootstrap UTF8String], "rb");
		chdir("/tmp");
		untar(a, "bootstrap");
		fclose(a);
		
		/* kpp pass and got root system partition r/w */  // do not got patch offsets for iOS9 ,just commit it
	//	int kpp_init(uint64_t kernbase, uint64_t slide);
		
		// getshell
		
	//	getshell();
		
		//backup activation file
		//copyfile("/var/containers/Data/System/49A66B5C-C909-4BEF-9475-2BDEC887307D/Library/activation_records/activation_record.plist", "/var/mobile/Media/activate", 0, COPYFILE_ALL);
	
		
	
		// test
	/*	FILE *file = fopen("/var/root/.profile", "rb");
		if (file) {
			char str[1024];
			while (fscanf(file, "%s", str)!=EOF)
				printf("%s",str);
			fclose(file);
		}*/
		

		
		//exec cmd
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
