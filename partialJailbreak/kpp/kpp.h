//
//  kpp.h
//  PhoenixNonce
//
//  Created by hongs on 2018/6/24.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef kpp_h
#define kpp_h

void prepare_rwk_via_tfp0(mach_port_t port);
uint64_t ReadAnywhere64(uint64_t addr);
uint64_t WriteAnywhere64(uint64_t addr, uint64_t val);
uint32_t ReadAnywhere32(uint64_t addr);
uint64_t WriteAnywhere32(uint64_t addr, uint32_t val);
void copyin(void* to, uint64_t from, size_t size);
void copyout(uint64_t to, void* from, size_t size);

#endif /* kpp_h */
