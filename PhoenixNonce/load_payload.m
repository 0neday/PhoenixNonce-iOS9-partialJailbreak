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
#include "nvpatch.h"
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

static int party_hard(void)
{
    int ret = 0;
    if(getuid() != 0) // Skip if we got root already
    {
        ret = -1;
        vm_address_t kbase = 0;
        task_t kernel_task = get_kernel_task(&kbase);
        LOG("kernel_task: 0x%x", kernel_task);
        if(MACH_PORT_VALID(kernel_task))
        {
          //  ret = nvpatch(kernel_task, kbase, "com.apple.System.boot-nonce");
					ret = 0;
        }
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
		
		/* kpp pass and got root system partition r/w */  // do not got patch offsets for iOS9 ,just commit ir
	//	int kpp_init(uint64_t kernbase, uint64_t slide);
		
		// getshell
		
	//	getshell();
	
		// test
		FILE *file = fopen("/var/root/.profile", "rb");
		if (file) {
			char str[1024];
			while (fscanf(file, "%s", str)!=EOF)
				printf("%s",str);
			fclose(file);
		}
		

		
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
