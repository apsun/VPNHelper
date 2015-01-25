# VPNHelper
A command line tool (written entirely in C) to manage L2TP VPN connections in Mac OS X.

Works using the [SystemConfiguration framework](https://developer.apple.com/library/mac/documentation/Networking/Reference/SCNetworkConfiguration/index.html).

## Requirements
- A computer running OS X 10.10 Yosemite
- Administrator privileges (run the program with `sudo`)

This program was developed and tested on 10.10, though in theory it should work on 10.5 or above.

## Usage

### Creating a new connection
```
sudo vpnhelper create -n "VPN Name" -a "vpn.server.com" -u "Username" -p "Password" -s "Shared Secret"
```

### Modifying an existing connection
```
sudo vpnhelper edit -i "Service ID" [-n "VPN Name"] [-a "vpn.server.com"] [-u "Username"] [-p "Password"] [-s "Shared Secret"]
```

## Todo
- Add support for deleting VPN connections
- Add support for connecting/disconnecting to a VPN
- Add support for printing existing VPN connection info