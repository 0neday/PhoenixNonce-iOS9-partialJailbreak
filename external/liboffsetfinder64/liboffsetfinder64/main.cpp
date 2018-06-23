//
//  main.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <iostream>
#include <liboffsetfinder64/liboffsetfinder64.hpp>

using namespace std;
using namespace tihmstar;
typedef uint64_t kptr_t;

int main(int argc, const char * argv[]) {
    offsetfinder64 fi(argv[1]);
    
    fi.find_kernel_pmap_nosym();
    
    [](offsetfinder64 *fi){
        kptr_t sizeof_task =                      (kptr_t)fi->find_sizeof_task();
        kptr_t task_itk_self =                    (kptr_t)fi->find_task_itk_self();
        kptr_t task_itk_registered =              (kptr_t)fi->find_task_itk_registered();
        kptr_t task_bsd_info =                    (kptr_t)fi->find_task_bsd_info();
        kptr_t proc_ucred =                       (kptr_t)fi->find_proc_ucred();
        kptr_t vm_map_hdr =                       (kptr_t)fi->find_vm_map_hdr();
        kptr_t ipc_space_is_task =                (kptr_t)fi->find_ipc_space_is_task();
        kptr_t realhost_special =                 0x10;
        kptr_t iouserclient_ipc =                 (kptr_t)fi->find_iouserclient_ipc();
        kptr_t vtab_get_retain_count =            (kptr_t)fi->find_vtab_get_retain_count();
        kptr_t vtab_get_external_trap_for_index = (kptr_t)fi->find_vtab_get_external_trap_for_index();

        kptr_t zone_map =                         (kptr_t)fi->find_zone_map();
        kptr_t kernel_map =                       (kptr_t)fi->find_kernel_map();
        kptr_t kernel_task =                      (kptr_t)fi->find_kernel_task();
        kptr_t realhost =                         (kptr_t)fi->find_realhost();

        kptr_t copyin =                           (kptr_t)fi->find_copyin();
        kptr_t copyout =                          (kptr_t)fi->find_copyout();
        kptr_t chgproccnt =                       (kptr_t)fi->find_chgproccnt();
        kptr_t kauth_cred_ref =                   (kptr_t)fi->find_kauth_cred_ref();
        kptr_t ipc_port_alloc_special =           (kptr_t)fi->find_ipc_port_alloc_special();
        kptr_t ipc_kobject_set =                  (kptr_t)fi->find_ipc_kobject_set();
        kptr_t ipc_port_make_send =               (kptr_t)fi->find_ipc_port_make_send();
        kptr_t osserializer_serialize =           (kptr_t)fi->find_osserializer_serialize();
        kptr_t rop_ldr_x0_x0_0x10 =               (kptr_t)fi->find_rop_ldr_x0_x0_0x10();


        for (kptr_t *s = &sizeof_task; s>=&rop_ldr_x0_x0_0x10; s--) {
            printf("%p\n",*s);
        }

        printf("");

    }(&fi);

    printf("/*------------------------ kernelpatches -------------------------- */\n");

    /*------------------------ kernelpatches -------------------------- */
    tihmstar::patchfinder64::patch i_can_has_debugger_patch_off = fi.find_i_can_has_debugger_patch_off();
    tihmstar::patchfinder64::patch lwvm_patch_offsets = fi.find_lwvm_patch_offsets();
    tihmstar::patchfinder64::patch remount_patch_offset = fi.find_remount_patch_offset();
    tihmstar::patchfinder64::patch proc_enforce = fi.find_proc_enforce();
    tihmstar::patchfinder64::patch amfi_patch_offsets = fi.find_amfi_patch_offsets();
    tihmstar::patchfinder64::patch cs_enforcement_disable_amfi = fi.find_cs_enforcement_disable_amfi();
    tihmstar::patchfinder64::patch amfi_substrate_patch = fi.find_amfi_substrate_patch();
    tihmstar::patchfinder64::patch sandbox_patch = fi.find_sandbox_patch();
    tihmstar::patchfinder64::patch nonce = fi.find_nonceEnabler_patch();
    
    
    auto nosuid_off = fi.find_nosuid_off();
    auto sbops = fi.find_sbops();
    
    for (tihmstar::patchfinder64::patch *s = &i_can_has_debugger_patch_off; s>=&nonce; s--) {
        printf("%p\n",s->_location);
    }
    
    for (auto s : nosuid_off) {
        printf("%p\n",s._location);
    }
    printf("%p\n",sbops);
    
    printf("/*------------------------ Util -------------------------- */\n");
    tihmstar::patchfinder64::loc_t vnode = fi.find_rootvnode();
    
    printf("%p\n",vnode);
    
    printf("");
    
    

    
    std::cout << "Done!\n";
    return 0;
}
