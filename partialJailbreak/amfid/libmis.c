//
//  libmis.c
//  partialJailbreak
//
//  Created by hongs on 2/19/19.
//  Copyright © 2019 hongs. All rights reserved.
//

#include "libmis.h"

#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>

typedef void *MISProfileRef;



typedef void (^block_handler_t)(MISProfileRef);

// From libmis.h - the missing (still partial) header



// libmis exports some 65 functions in 9.3.1. This shows a dozen.
// some are accessors. But others (notably blacklist, UPP and
// profile creation) will be included in a future version.

#define MIS_ERROR_BASE 0xe8008000

// The #1 function in the library ...
extern int MISValidateSignature (void *File, CFDictionaryRef Opts);
// which is really just a pass through to :
extern int MISValidateSignatureAndCopyInfo (CFStringRef File, CFDictionaryRef Opts, void **Info);

extern CFStringRef MISCopyErrorStringForErrorCode(int Error);

extern int MISEnumerateInstalledProvisioningProfiles (int flags,
                                                      block_handler_t);

extern CFStringRef MISProfileGetValue (MISProfileRef, CFStringRef Key);
extern CFStringRef MISProvisioningProfileGetUUID (MISProfileRef);

extern CFStringRef MISProvisioningProfileGetName (MISProfileRef);
extern int MISProvisioningProfileGetVersion (MISProfileRef);
extern CFDictionaryRef MISProvisioningProfileGetEntitlements (MISProfileRef);
extern CFStringRef MISProvisioningProfileGetTeamIdentifier (MISProfileRef);

extern CFArrayRef MISProvisioningProfileGetProvisionedDevices(MISProfileRef);
extern int MISProfileIsMutable(MISProfileRef);

extern int MISProvisioningProfileIsAppleInternalProfile(MISProfileRef);
extern int MISProvisioningProfileIsForLocalProvisioning(MISProfileRef);
extern int MISProvisioningProfileProvisionsAllDevices(MISProfileRef);
extern int MISProvisioningProfileGrantsEntitlement(MISProfileRef, CFStringRef ,void *);

// Validation options - actually CFStringRefs. but whatever

extern void *kMISValidationOptionRespectUppTrustAndAuthorization;
extern void *kMISValidationOptionValidateSignatureOnly;
extern void *kMISValidationOptionUniversalFileOffset;
extern void *kMISValidationOptionAllowAdHocSigning;
extern void *kMISValidationOptionOnlineAuthorization; // triggers online validation of cert


int libmis(char *filepath)
{
    
    void * copiedInfo =  NULL;
    CFMutableDictionaryRef optionsDict =
    CFDictionaryCreateMutable(kCFAllocatorDefault, // CFAllocatorRef allocator,
                              0,            // CFIndex capacity
                              &kCFTypeDictionaryKeyCallBacks, // const CFDictionaryKeyCallBacks *keyCallBacks,
                              &kCFTypeDictionaryValueCallBacks); // const CFDictionaryValueCallBacks *valueCallBacks );
    
    
    
    // Now, here's what AMFI really would do:
    
#ifdef IOS_9
    // In 9.x:
    CFDictionarySetValue(optionsDict,kMISValidationOptionRespectUppTrustAndAuthorization, kCFBooleanTrue);
#endif
    //  CFDictionarySetValue(optionsDict,kMISValidationOptionValidateSignatureOnly,kCFBooleanTrue);
    //  CFDictionarySetValue(optionsDict,kMISValidationOptionExpectedCDHash,CFData of CDhash here..);
    //  CFDictionarySetValue(optionsDict,kMISValidationOptionUniversalFileOffset, CFNumber...);
    
    
    // Me, I just try the ad-hoc validation, or defaults, which validates App store too.
   // CFDictionarySetValue(optionsDict,kMISValidationOptionAllowAdHocSigning, kCFBooleanTrue);
    
    
    // $%#$%$#%# CFStrings
    
    CFStringRef FileName =
    CFStringCreateWithCStringNoCopy (kCFAllocatorDefault, // CFAllocatorRef alloc,
                                     filepath, // const char *cStr,
                                     kCFStringEncodingUTF8, // CFStringEncoding encoding,
                                     kCFAllocatorDefault); // CFAllocatorRef contentsDeallocator );
    
    // Using MISValidateSignatureAndCopyInfo because on JB devices MISValidateSignature
    // is re-exported to return 0 in any case...
    // change this to MVS if you want to check if your code signature bypass works:
    
    
    /*
    int rc = MISValidateSignatureAndCopyInfo(FileName, optionsDict,NULL);
    if (rc)
    {
        fprintf(stderr,"Error %d (0x%x) - ",rc, rc);
        CFShow(MISCopyErrorStringForErrorCode(rc));
    }
    else {printf("Valid!\n"); }
    
    return (rc);
     */
    return 0;
}

