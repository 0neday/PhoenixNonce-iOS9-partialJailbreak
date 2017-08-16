#ifndef NVPATCH_H
#define NVPATCH_H

#include <stdio.h>
#include <mach/mach.h>

#define MAX_HEADER_SIZE 0x4000

typedef struct
{
    vm_address_t addr;
    vm_size_t len;
    char *buf;
} segment_t;

int nvpatch(task_t kernel_task, vm_address_t kbase, const char *target);

#endif
