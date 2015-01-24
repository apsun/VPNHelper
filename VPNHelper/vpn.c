#include "vpn.h"
#include "keychain.h"
#include <stdio.h>
#include <SystemConfiguration/SystemConfiguration.h>

void
print_scerror(const char *message)
{
    fprintf(stderr, "%s: %s (%d)\n", message, SCErrorString(SCError()), SCError());
}

CFStringRef
create_shared_secret_id(CFStringRef service_id)
{
    return CFStringCreateWithFormat(NULL, NULL, CFSTR("%@.SS"), service_id);
}

SCNetworkServiceRef
create_vpn_service(SCPreferencesRef preferences)
{
    SCNetworkInterfaceRef l2tp_interface = SCNetworkInterfaceCreateWithInterface(
        kSCNetworkInterfaceIPv4, kSCNetworkInterfaceTypeL2TP
    );
    
    SCNetworkInterfaceRef ppp_interface = SCNetworkInterfaceCreateWithInterface(
        l2tp_interface, kSCNetworkInterfaceTypePPP
    );
    
    SCNetworkServiceRef vpn_service = SCNetworkServiceCreate(preferences, ppp_interface);
    if (vpn_service == NULL) {
        print_scerror("Failed to create new VPN service");
    }
    
    CFRelease(ppp_interface);
    CFRelease(l2tp_interface);
    
    return vpn_service;
}

Boolean
set_service_name(SCNetworkServiceRef vpn_service, L2TPConfigRef config)
{
    CFStringRef service_name = config->service_name;
    
    if (service_name == NULL) {
        return TRUE;
    }
    
    Boolean success = SCNetworkServiceSetName(vpn_service, service_name);
    
    if (!success) {
        print_scerror("Failed to set service name");
    }
    
    return success;
}

Boolean
set_ppp_config(SCNetworkInterfaceRef vpn_interface, L2TPConfigRef config)
{
    CFStringRef server_address = config->server_address;
    CFStringRef username = config->username;
    
    if (server_address == NULL && username == NULL) {
        return TRUE;
    }
    
    const void *keys[3] = {
        kSCPropNetPPPAuthPasswordEncryption
    };
    
    const void *values[3] = {
        kSCValNetPPPAuthPasswordEncryptionKeychain
    };
    
    int index = 1;
    
    if (server_address != NULL) {
        keys[index] = kSCPropNetPPPCommRemoteAddress;
        values[index] = server_address;
        index++;
    }
    
    if (username != NULL) {
        keys[index] = kSCPropNetPPPAuthName;
        values[index] = username;
        index++;
    }
    
    CFDictionaryRef ppp_config = CFDictionaryCreate(NULL, keys, values, index, NULL, NULL);
    Boolean success = SCNetworkInterfaceSetConfiguration(vpn_interface, ppp_config);
    CFRelease(ppp_config);
    
    if (!success) {
        print_scerror("Failed to set PPP config");
    }
    
    return success;
}

Boolean
set_ipsec_config(SCNetworkInterfaceRef vpn_interface, CFStringRef shared_secret_id)
{
    const void *keys[3] = {
        kSCPropNetIPSecAuthenticationMethod,
        kSCPropNetIPSecSharedSecretEncryption,
        kSCPropNetIPSecSharedSecret
    };
    
    const void *values[3] = {
        kSCValNetIPSecAuthenticationMethodSharedSecret,
        kSCValNetIPSecSharedSecretEncryptionKeychain,
        shared_secret_id
    };
    
    CFDictionaryRef ipsec_config = CFDictionaryCreate(NULL, keys, values, 3, NULL, NULL);
    Boolean success = SCNetworkInterfaceSetExtendedConfiguration(vpn_interface, CFSTR("IPSec"), ipsec_config);
    CFRelease(ipsec_config);
    
    if (!success) {
        print_scerror("Failed to set IPSec config");
    }
    
    return success;
}

Boolean
set_ipv4_config(SCNetworkServiceRef vpn_service, L2TPConfigRef config)
{
    CFBooleanRef send_all_traffic = config->send_all_traffic;
    
    if (send_all_traffic == NULL) {
        return TRUE;
    }
    
    Boolean success = FALSE;
    
    SCNetworkProtocolRef protocol = SCNetworkServiceCopyProtocol(vpn_service, kSCNetworkProtocolTypeIPv4);
    if (protocol == NULL) {
        print_scerror("Failed to get IPv4 protocol");
        goto exit;
    }
    
    const void *keys[2] = {
        kSCPropNetIPv4ConfigMethod,
        kSCPropNetOverridePrimary
    };
    
    const void *values[2] = {
        kSCValNetIPv4ConfigMethodPPP,
        send_all_traffic
    };
    
    CFDictionaryRef ipv4_config = CFDictionaryCreate(NULL, keys, values, 2, NULL, NULL);
    
    if (!SCNetworkProtocolSetConfiguration(protocol, ipv4_config)) {
        print_scerror("Failed to set IPv4 config");
        goto release_ipv4_config;
    }
    
    success = TRUE;
    
release_ipv4_config:
    CFRelease(ipv4_config);
exit:
    return success;
}

Boolean
configure_new_vpn_service(SCPreferencesRef preferences, SCNetworkServiceRef vpn_service)
{
    if (!SCNetworkServiceEstablishDefaultConfiguration(vpn_service)) {
        print_scerror("Failed to establish default connection");
        return FALSE;
    }
    
    SCNetworkSetRef current_services = SCNetworkSetCopyCurrent(preferences);
    if (current_services == NULL) {
        print_scerror("Failed to get current network service set");
        return FALSE;
    }
    
    if (!SCNetworkSetAddService(current_services, vpn_service)) {
        print_scerror("Failed to add VPN service");
        return FALSE;
    }

    return TRUE;
}

Boolean
create_vpn(CFStringRef *service_id, L2TPConfigRef config)
{
    Boolean success = FALSE;
    
    SCPreferencesRef preferences = SCPreferencesCreate(NULL, CFSTR("VPNHelper"), NULL);
    
    if (!SCPreferencesLock(preferences, TRUE)) {
        print_scerror("Failed to obtain preferences lock");
        goto release_prefs;
    }
    
    SCNetworkServiceRef vpn_service;
    CFStringRef vpn_service_id;
    if (service_id != NULL && *service_id != NULL) {
        vpn_service_id = *service_id;
        vpn_service = SCNetworkServiceCopy(preferences, vpn_service_id);
        
    } else {
        vpn_service = create_vpn_service(preferences);
        vpn_service_id = SCNetworkServiceGetServiceID(vpn_service);
    }
    
    if (vpn_service == NULL) {
        print_scerror("Failed to get VPN service");
        goto release_prefs;
    }
    
    if (!set_service_name(vpn_service, config)) {
        goto release_service;
    }
    
    SCNetworkInterfaceRef vpn_interface = SCNetworkServiceGetInterface(vpn_service);
    if (vpn_interface == NULL) {
        print_scerror("Failed to get VPN interface");
        goto release_service;
    }
    
    if (!set_ppp_config(vpn_interface, config)) {
        goto release_shared_secret_id;
    }
    
    CFStringRef vpn_shared_secret_id = create_shared_secret_id(vpn_service_id);
    
    if (!set_ipsec_config(vpn_interface, vpn_shared_secret_id)) {
        goto release_shared_secret_id;
    }
    
    if (!configure_new_vpn_service(preferences, vpn_service)) {
        goto release_shared_secret_id;
    }
    
    if (!set_ipv4_config(vpn_service, config)) {
        goto release_shared_secret_id;
    }
    
    if (!configure_keychain(config, vpn_service_id, vpn_shared_secret_id)) {
        goto release_shared_secret_id;
    }
    
    if (!SCPreferencesCommitChanges(preferences)) {
        print_scerror("Failed to commit changes");
        goto release_shared_secret_id;
    }
    
    if (!SCPreferencesApplyChanges(preferences)) {
        print_scerror("Failed to apply changes");
        goto release_shared_secret_id;
    }
    
    if (service_id != NULL && *service_id == NULL) {
        *service_id = CFRetain(vpn_service_id);
    }
    success = TRUE;
    
release_shared_secret_id:
    CFRelease(vpn_shared_secret_id);
release_service:
    CFRelease(vpn_service);
unlock_prefs:
    assert(SCPreferencesUnlock(preferences));
release_prefs:
    CFRelease(preferences);
exit:
    return success;
}

Boolean
delete_vpn(CFStringRef service_id)
{
    // TODO: Add something here!
    
    return FALSE;
}
