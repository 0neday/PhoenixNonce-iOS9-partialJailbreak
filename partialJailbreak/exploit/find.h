/*
 * find.h - Minimal offsets finder
 *          Taken and modified from cl0ver
 *
 * Copyright (c) 2016-2017 Siguza
 */

#ifndef FIND_H
#define FIND_H

#include <mach/mach.h>


#define MAX_HEADER_SIZE 0x4000

typedef struct
{
	vm_address_t addr;
	vm_size_t len;
	char *buf;
} segment_t;


vm_address_t find_kernel_task(segment_t *text);

vm_address_t find_ipc_space_kernel(segment_t *text);

#endif
