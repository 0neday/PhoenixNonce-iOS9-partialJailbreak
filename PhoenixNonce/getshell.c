/* J. Levin has compiled a bunch of Apple opensource utilites for arm64
 * You can get them from his site here: http://newosxbook.com/tools/iOSBinaries.html
 *
 * Follow the link to "The 64-bit tgz pack"
 *
 * Unpack the tarball into a directory called iosbinpack64 and drag-and-drop
 * that directory into the directory with all the source files in in XCode
 * so that it ends up in the .app bundle
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <spawn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <CoreFoundation/CoreFoundation.h>

//#include "amfi.h"

char* bundle_path() {
  CFBundleRef mainBundle = CFBundleGetMainBundle();
  CFURLRef resourcesURL = CFBundleCopyResourcesDirectoryURL(mainBundle);
  int len = 4096;
  char* path = malloc(len);
  
  CFURLGetFileSystemRepresentation(resourcesURL, TRUE, (UInt8*)path, len);
  
  return path;
}


// prepare all the payload binaries under the iosbinpack64 directory
// and build up the PATH
char* init_env() {
  char* path = calloc(4096, 1);
  strcpy(path, "PATH=");
    
 // char* dir = bundle_path();
	char* dir = "/tmp/bins";
 // strcat(dir, "/bins");
  strcat(path, dir);
  strcat(path, ":");
  //free(dir);
    
  strcat(path, "/bin:/sbin");
 // printf("PATH = %s\n",path);

  return path;
}

void do_bind_shell(char* env, int port) {
  //char* dir = bundle_path();
	char* dir = "/tmp";
	
  char* shell_path = NULL;
  asprintf(&shell_path, "%s/bash-arm64-sig", dir);
  chmod(shell_path, 0775);
  // inject amfi
  //inject_trust(shell_path);
  
 // free(dir);
	printf("get shell_path on : %s\n",shell_path);
	
  char* argv[] = {shell_path, NULL};
  char* envp[] = {env, NULL};
  
  struct sockaddr_in sa;
  sa.sin_len = 0;
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = INADDR_ANY;
  
  int sock = socket(PF_INET, SOCK_STREAM, 0);
  bind(sock, (struct sockaddr*)&sa, sizeof(sa));
  listen(sock, 1);
  
  printf("shell listening on port %d\n", port);
  
 // for(;;) {
    int conn = accept(sock, 0, 0);
    
    posix_spawn_file_actions_t actions;
    
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, conn, 0);
    posix_spawn_file_actions_adddup2(&actions, conn, 1);
    posix_spawn_file_actions_adddup2(&actions, conn, 2);
    

    pid_t spawned_pid = 0;
    int spawn_err = posix_spawn(&spawned_pid, shell_path, &actions, NULL, argv, envp);
		
    if (spawn_err != 0){
      perror("shell spawn error");
    } else {
      printf("shell posix_spawn success!\n");
    }
    
    posix_spawn_file_actions_destroy(&actions);
    
    printf("our pid: %d\n", getpid());
    printf("spawned_pid: %d\n", spawned_pid);
    
    int wl = 0;
    while (waitpid(spawned_pid, &wl, 0) == -1 && errno == EINTR);
  // }
  
  free(shell_path);
}

void getshell() {
  char* env_path = init_env();
  printf("will launch a shell with this environment: %s\n", env_path);
  
  do_bind_shell(env_path, 4141);
  free(env_path);
}
