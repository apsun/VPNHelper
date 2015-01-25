#include "keychain.h"
#include <stdio.h>
#include <Security/Security.h>

void
print_osstatus(const char *message, OSStatus status)
{
    fprintf(stderr, "%s: %d\n", message, status);
}

char *
copy_utf8_chars(CFStringRef str)
{
    if (str == NULL) {
        return NULL;
    }
    CFIndex utf16_length = CFStringGetLength(str);
    CFIndex max_utf8_length = CFStringGetMaximumSizeForEncoding(utf16_length, kCFStringEncodingUTF8) + 1;
    char *buffer = malloc(max_utf8_length);
    assert(CFStringGetCString(str, buffer, max_utf8_length, kCFStringEncodingUTF8));
    return buffer;
}

SecTrustedApplicationRef
create_trusted_app(const char *path)
{
    SecTrustedApplicationRef app;
    OSStatus result = SecTrustedApplicationCreateFromPath(path, &app);
    assert(result == errSecSuccess);
    return app;
}

CFArrayRef
get_trusted_app_list()
{
    static CFArrayRef trusted_apps;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const void *trusted_apps_raw[7] = {
            create_trusted_app("/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper"),
            create_trusted_app("/System/Library/PreferencePanes/Network.prefPane/Contents/XPCServices/com.apple.preference.network.remoteservice.xpc"),
            create_trusted_app("/usr/sbin/pppd"),
            create_trusted_app("/usr/sbin/racoon"),
            create_trusted_app("/usr/libexec/nehelper"),
            create_trusted_app("/usr/libexec/nesessionmanager"),
            create_trusted_app("/usr/libexec/neagent")
        };
        trusted_apps = CFArrayCreate(NULL, trusted_apps_raw, 7, NULL);
    });
    return trusted_apps;
}

Boolean
delete_keychain_key(SecKeychainRef keychain, char *service)
{
    OSStatus status;

    while (TRUE) {
        SecKeychainItemRef item;
        status = SecKeychainFindGenericPassword(
            keychain,
            (UInt32)strlen(service),
            service,
            0,
            NULL,
            NULL,
            NULL,
            &item
        );

        if (status == errSecItemNotFound) {
            return TRUE;
        }

        if (status != errSecSuccess) {
            print_osstatus("Failed to get existing keychain entry", status);
            return FALSE;
        }

        status = SecKeychainItemDelete(item);
        CFRelease(item);

        if (status != errSecSuccess) {
            print_osstatus("Failed to delete existing keychain entry", status);
            return FALSE;
        }
    }
}

Boolean
configure_keychain_key(SecKeychainRef keychain, SecAccessRef access, SecKeychainAttributeList attributes, char *service, char *password)
{
    if (!delete_keychain_key(keychain, service)) {
        return FALSE;
    }
    
    OSStatus status = SecKeychainItemCreateFromContent(
        kSecGenericPasswordItemClass,
        &attributes,
        password == NULL ? 0 : (UInt32)strlen(password),
        password,
        keychain,
        access,
        NULL
    );
    
    if (status != errSecSuccess) {
        print_osstatus("Failed to create new keychain entry", status);
    }
    
    return status == errSecSuccess;
}

Boolean
configure_keychain_vpn_password(SecKeychainRef keychain, SecAccessRef access, L2TPConfigRef config, CFStringRef service_id)
{
    CFStringRef service_name = config->service_name;
    CFStringRef username = config->username;
    CFStringRef password = config->password;
    
    if (service_name == NULL && username == NULL && password == NULL) {
        return TRUE;
    }
    
    char *str_description = "VPN Password";
    char *str_service = copy_utf8_chars(service_id);
    
    char *str_label = copy_utf8_chars(service_name);
    char *str_account = copy_utf8_chars(username);
    char *str_value = copy_utf8_chars(password);

    SecKeychainAttribute attributes[4] = {
        {kSecServiceItemAttr,     (UInt32)strlen(str_service),     str_service},
        {kSecDescriptionItemAttr, (UInt32)strlen(str_description), str_description}
    };
    
    int index = 2;
    
    if (str_label != NULL) {
        attributes[index++] = (SecKeychainAttribute){kSecLabelItemAttr, (UInt32)strlen(str_label), str_label};
    }
    
    if (str_account != NULL) {
        attributes[index++] = (SecKeychainAttribute){kSecAccountItemAttr, (UInt32)strlen(str_account), str_account};
    }
    
    SecKeychainAttributeList attribute_list = {index, attributes};
    
    Boolean success = configure_keychain_key(keychain, access, attribute_list, str_service, str_value);
    
free_strings:
    if (str_label != NULL) {
        free(str_label);
    }
    if (str_account != NULL) {
        free(str_account);
    }
    free(str_service);
    free(str_value);
exit:
    return success;
}

Boolean
configure_keychain_shared_secret(SecKeychainRef keychain, SecAccessRef access, L2TPConfigRef config, CFStringRef shared_secret_id)
{
    CFStringRef service_name = config->service_name;
    CFStringRef shared_secret = config->shared_secret;
    
    if (service_name == NULL && shared_secret == NULL) {
        return TRUE;
    }
    
    char *str_description = "IPSec Shared Secret";
    char *str_service = copy_utf8_chars(shared_secret_id);
    
    char *str_label = copy_utf8_chars(service_name);
    char *str_value = copy_utf8_chars(shared_secret);
    
    SecKeychainAttribute attributes[3] = {
        {kSecServiceItemAttr,     (UInt32)strlen(str_service),     str_service},
        {kSecDescriptionItemAttr, (UInt32)strlen(str_description), str_description}
    };
    
    int index = 2;
    
    if (str_label != NULL) {
        attributes[index++] = (SecKeychainAttribute){kSecLabelItemAttr, (UInt32)strlen(str_label), str_label};
    }
    
    SecKeychainAttributeList attribute_list = {index, attributes};
    
    Boolean success = configure_keychain_key(keychain, access, attribute_list, str_service, str_value);
    
free_strings:
    if (str_label != NULL) {
        free(str_label);
    }
    free(str_service);
    free(str_value);
exit:
    return success;
}

Boolean
configure_keychain(L2TPConfigRef config, CFStringRef service_id, CFStringRef shared_secret_id)
{
    Boolean success = FALSE;
    OSStatus status;
    
    SecKeychainRef keychain;
    status = SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &keychain);
    if (status != errSecSuccess) {
        print_osstatus("Failed to open system keychain", status);
        goto exit;
    }
    
    SecAccessRef access;
    status = SecAccessCreate(CFSTR("VPNHelper"), get_trusted_app_list(), &access);
    if (status != errSecSuccess) {
        print_osstatus("Failed to obtain keychain access", status);
        goto release_keychain;
    }
    
    if (!configure_keychain_vpn_password(keychain, access, config, service_id)) {
        goto release_access;
    }
    
    if (!configure_keychain_shared_secret(keychain, access, config, shared_secret_id)) {
        goto release_access;
    }
    
    success = TRUE;
    
release_access:
    CFRelease(access);
release_keychain:
    CFRelease(keychain);
exit:
    return success;
}
