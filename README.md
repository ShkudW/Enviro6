# Enviro6 -  IPv6 DHCP & DNS Server Configuration Tool and Sniffing Tool


This tool is designed to automatically set up and configure a Linux-based server (e.g., Kali Linux) as an IPv6 DHCP, DNS, and Router Advertisement Daemon (RADVD) server. The script facilitates the deployment of a fully functional IPv6 environment, where the server can act as the default gateway, DNS server, and DHCPv6 server for the network clients.


## Features - Enviro6.py

- **RA Spoofing**: Spoof Router Advertisements to hijack the default gateway of IPv6 devices.
- **NDP Spoofing**: Spoof Neighbor Discovery Protocol messages to associate an IP address with a fake MAC address.
- **RA Flood**: Flood the network with Router Advertisements to disrupt or take over the network.
- **Sniffing**: Capture and display Link-Local, ULA, and Global IPv6 addresses associated with MAC addresses in real-time.


## Features - Enviro6-DHCP-DNS-Server.py
- **DHCPv6 Server**: Turns your machine into a DHCPv6 server that distributes ULA addresses to all the stations that request to receive IPv6 articles automatically.
- **DNSv6 Server**: Turns your machine into a DNSv6 server , With the option to add a domain name that will be translated in the AAAA and A record to the IP address of your machine.

## Requirements


Installed Services: isc-dhcp-server, dnsmasq, radvd.
```bash
sudo apt-get install isc-dhcp-server
sudo apt-get install dnsmasq
sudo apt-get install radvd
sudo apt-get install netplan
```

Install the required Python packages by running:
```bash
pip install -r requirements.txt
```

## Usage - Enviro6-DHCP-DNS-Server.py:
-iface: The network interface to use (e.g., eth0).
-dns -domain DOMAIN.co.il: The domain name that will be translated into the ULA address and the IPv6 address of your machine.
-restore: Return the state of all configuration on the machine to their original state, before the start of the attack.


## Usage - Enviro6.py
```
python3 Enviro6.py -I <interface> [options]
```

Options:
* -I, --interface: The network interface to use (e.g., eth0).
* --ra-spoof: Run an RA Spoofing attack.
* --ndp-spoof: Run an NDP Spoofing attack. Requires --target-ipv6 and --fake-mac.
* --ra-flood: Run an RA Flood attack.
* --sniff: Sniff the network and display IPv6 addresses associated with MAC addresses in real-time.
* --target-ipv6: The target IPv6 address for NDP Spoofing.
* --fake-mac: The fake MAC address to use for NDP Spoofing.


## Example Commands - Enviro6-DHCP-DNS-Server.py:

Open DHCPv6 and DNSv6 Server:
```
python3 Enviro6-DHCP-DNS-Server.py -iface eth0 -dns -domain godfather.local
```

## Example Commands - Enviro6.py:

RA Spoofing:
```
python3 Enviro6.py -I eth0 --ra-spoof

```
NDP Spoofing:
```
python3 enviro6.py -I eth0 --ndp-spoof --target-ipv6 fe80::f524:c89b:11bb:d7be --fake-mac 11:22:33:44:55:66

```
RA Flood
```
python3 enviro6.py -I eth0 --ra-flood
```
Sniffing
```
python3 enviro6.py -I eth0 --sniff
```


## Monitoring Traffic with TCPDump
```
sudo tcpdump -i eth0 ip6
```


## PoC - Enviro6-DHCP-DNS-Server.py:
Start DHCP and DNS version 6 Servers:
![image](https://github.com/user-attachments/assets/24cdbed0-340d-44a2-ae23-e22fe707cb31)


The Victim (Windows 10 Machine, BefireThe Attack and After):
![image](https://github.com/user-attachments/assets/ed9288f4-05ac-438b-9c6d-8d597aebbda5)


The Victim's DNS Server:

![image](https://github.com/user-attachments/assets/38f5e133-d930-488d-bde9-7504c7563d32)


Stop The attack and Restore all the configuration on kali machine:

![image](https://github.com/user-attachments/assets/9b4a1f50-26b3-4183-989b-3d3ad3b78837)


# Enjoy!

