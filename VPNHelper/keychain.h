#ifndef VPNHELPER_KEYCHAIN_H
#define VPNHELPER_KEYCHAIN_H

#include "vpn.h"
#include <CoreFoundation/CoreFoundation.h>

Boolean configure_keychain(L2TPConfigRef config, CFStringRef service_id, CFStringRef shared_secret_id);

#endif
