![image](https://github.com/user-attachments/assets/fe18cfca-b39b-43dc-a1e7-c9b74d51ea40)

# brief:

The tool was tested in lab environments as well as in production testing environments. 
However, it seemed that its operation did not perform consistently and satisfactorily across all environments. Therefore, I took the time to research more about IPv6 addresses, rewrite the tool, and modify its functionality. 


As with everything, IPv6 addresses were created out of necessity, specifically due to the increasing shortage of IPv4 addresses. In one of the lectures I attended, there was a discussion about the incredible number of IPv6 addresses, with a phrase that stuck with me:
"If we take all the IPv4 addresses in the world, we could fill an entire truck, but if we take all the IPv6 addresses in the world, we could fill the sun..."

So, IPv6 addresses are 128 bits long, and I’ll elaborate here on three types of IPv6 addresses:

*Link-Local Address:
These addresses are used for communication within a local network only and can be assigned to devices even without a DHCPv6 server in the network. You can recognize the address by the prefix fe80::. There are two ways to generate these addresses:

 - Method A: Derived from the device’s MAC address, 48 bits are expanded to 64 bits by adding fe80, adding "FFFE", and flipping the 7th bit.
 - Method B: Random Generation: To enhance security and prevent network neighbors from guessing the LLA, the device generates a random address each time it connects to the network
.
Therefore, in most cases, the LLA will be consistent if it's based on the MAC address, but in operating systems like Windows 10 or macOS, the LLA is used in a random and dynamic manner.

*Global IPv6 Address:
A global address is usually assigned to network devices by the ISP, allowing access to the device from anywhere on the internet. The address is chosen from a range defined by IANA (2000::/3), and it is unique globally. The address is assigned to the router in the local network, and it distributes the prefix to devices in the network that also want global IPv6 addresses.

*Unique Local Address (ULA):
ULA is similar to private addresses in IPv4 (e.g., 10.x.x.x, 172.16.x.x, or 192.168.x.x). They are intended for use within private networks and start with the prefix fc00::/7. These addresses are not meant to be routed to the public internet.

How a Device Receives an IPv6 Address (Global or Local):
This process is quite similar to the "DORA" process in IPv4. This process also consists of 4 stages:

a) The client sends a Solicit message to all servers in the network to request an IP address.

b) The server responds with an Advertise message offering an IPv6 address.

C) The client sends a Request message requesting the offered address.

D) The server responds with a Reply message confirming the allocation of the address.


The main focus of the tool:
Identifying Link-Local Addresses by listening for Solicit requests. 
In these requests, the client sends its Link-Local Address along with its MAC address.
Another method of identification is by sending NDP (Neighbor Discovery Protocol) messages. 
This protocol is mainly used for exchanging information about addresses within the local network space, allowing devices to discover the Link-Local Addresses of other devices on the network.
Additionally, the tool can also function as a DHCPv6 server, so it knows which ULA addresses it has assigned and to whom.

I encountered many environments with network isolation policies, where the policy was, to my delight, only applied to IPv4 addresses, and IPv6 addresses were not managed at all. Therefore, I created a separate and efficient communication network that operates alongside the IPv4 addresses of the network.


# Enviro6

Enviro6 is a smart script designed for discovering and managing IPv6 addresses within networks. The tool enables device detection through DHCPv6 and NDP scanning, allowing users to bypass IPv4 isolation restrictions and communicate with other devices using IPv6. It features a colorful, dynamic interface for easy visualization of discovered information.

The primary purpose of this tool is to enable Penetration Testers to access devices on the network over IPv6. The tool aims to bypass network restrictions that are typically enforced on IPv4.

## Features

Enviro6 performs two main functions:

1. **Neighbor Discovery:** Discover devices in the network that hold IPv6 addresses:
   - Discovery of Link-Local Addresses
   - Discovery of Global IPv6 Addresses
   - Discovery of Local IPv6 Addresses

2. **DHCPv6 Server:** Acts as a DHCPv6 server, distributing IPv6 addresses to all devices in the network.


## Installation

To use Enviro6, you'll need Python 3.x installed on your system. Follow these steps to set up the environment:

1. Clone the repository:

   ```bash
   git clone https://github.com/ShkudW/Enviro6.git
   cd Enviro6

## Usage
```
python3 Enviro6.py -I <network_interface> 
```

```
python3 Enviro6.py -I <network_interface> -DHCPv6
```

