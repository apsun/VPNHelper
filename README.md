# AutoVPN
A command line tool to manage L2TP VPN connections in Mac OS X.

# Requirements
A computer running OS X 10.5 through 10.10.

# Usage

### Creating a new connection
```
vpnhelper create -n "VPN Name" -a "vpn.server.com" -u "Username" -p "Password" -s "Shared Secret"
```

### Modifying an existing connection
```
vpnhelper edit -i "Service ID" [-n "VPN Name"] [-a "vpn.server.com"] [-u "Username"] [-p "Password"] [-s "Shared Secret"]
```

# Todo
- Add support for deleting VPN connections
- Add support for connecting/disconnecting to a VPN
