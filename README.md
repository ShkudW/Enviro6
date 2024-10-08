# Enviro6 -  IPv6 DHCP & DNS Server Configuration Tool and Sniffing Tool


This tool is designed to automatically set up and configure a Linux-based server (e.g., Kali Linux) as an IPv6 DHCP, DNS, and Router Advertisement Daemon (RADVD) server. The script facilitates the deployment of a fully functional IPv6 environment, where the server can act as the default gateway, DNS server, and DHCPv6 server for the network clients.

## Key Features

- **DHCPv6**: Automatically set up a DHCPv6 server with a unique ULA (Unique Local Address) to assign IPv6 addresses to devices on the network.
- **DNS**: Configure a DNS server that maps domains to IPv6 and IPv4 addresses as specified by the user.
- **Router Advertisement (RA)**: Broadcast router advertisements in the network to inform devices about router addresses and other configurations.
- **Sniffing**: Monitor and listen to Neighbor Discovery Protocol (NDP) activity in the network.
- **Restore**: Restore network settings to their previous state before any changes were made by the tool.

## Installation

The tool is Python-based and requires a few dependencies to be installed on a Kali Linux environment.

1. Clone the repository:
    ```bash
    git clone https://github.com/ShkudW/Enviro6.git
    cd Enviro6
    ```

2. Install the necessary dependencies:
    ```bash
    sudo apt-get update
    sudo apt-get install isc-dhcp-server dnsmasq radvd python3-pip
    pip3 install colorama
    ```

### Examples

- **Setting up DHCPv6 and DNSv6**:
    ```bash
    python3 Enviro6.py -iface <eth0> -dns -domain <example.co.il>
    ```

- **Sniffing NDP traffic**:
    ```bash
    python3 Enviro6.py -iface <eth0> -sniff
    ```

- **Restoring configurations**:
    ```bash
    python3 Enviro6.py -restore
    ```

## PoC:

Starting DHCP and DNS Servers:

![image](https://github.com/user-attachments/assets/077d080a-a7eb-4abd-92e4-a07c0b784fd3)


The Victim (Windows 10 Machine, Before The Attack and After):
![image](https://github.com/user-attachments/assets/ed9288f4-05ac-438b-9c6d-8d597aebbda5)


The Victim's DNS Server:

![image](https://github.com/user-attachments/assets/38f5e133-d930-488d-bde9-7504c7563d32)


Stop The attack and Restore all the configuration on kali machine:

![image](https://github.com/user-attachments/assets/72ed76a9-709b-4721-97dc-885711f2a936)


Sniffing function:

![image](https://github.com/user-attachments/assets/e037883e-c98a-46aa-8f6c-206c5a8cf739)


# Enjoy!

