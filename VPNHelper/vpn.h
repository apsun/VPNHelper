#ifndef VPNHELPER_VPN_H
#define VPNHELPER_VPN_H

#include <CoreFoundation/CoreFoundation.h>

typedef struct {
    /* The name of the VPN connection. */
    CFStringRef service_name;
    
    /* The address of the VPN server. */
    CFStringRef server_address;
    
    /* The username used to log into the VPN. */
    CFStringRef username;
    
    /* The password used to log into the VPN. */
    CFStringRef password;
    
    /* The shared secret used to log into the VPN. */
    CFStringRef shared_secret;
    
    /* Whether to send all traffic through the VPN connection. */
    CFBooleanRef send_all_traffic;
} L2TPConfig;

typedef const L2TPConfig *L2TPConfigRef;

/* Creates a new VPN connection, or modifies an existing one.
 * @param service_id A pointer to a string containing the service ID of the
 *     VPN connection. If this or the value it points to is NULL, a new
 *     VPN connection will be created, and this will point to the service
 *     ID of the connection when the function returns (if the pointer
 *     itself is not NULL). Otherwise, the function will modify an existing
 *     connection with the specified service ID.
 * @param config The VPN connection configuration. If creating a new connection, 
 *     all members must have values; otherwise, only those with values will 
 *     be updated.
 * @result TRUE if the operation is successful; FALSE otherwise.
 */
Boolean create_vpn(CFStringRef *service_id, L2TPConfigRef config);

/* Deletes an existing VPN connection.
 * @param service_id The service ID of the VPN connection.
 * @result TRUE if the operation is successful; FALSE otherwise.
 */
Boolean delete_vpn(CFStringRef service_id);

#endif
