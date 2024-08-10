![image](https://github.com/user-attachments/assets/fe18cfca-b39b-43dc-a1e7-c9b74d51ea40)


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
python3 Enviro6.py -I <network_interface> -timeout <seconds>
```

```
python3 Enviro6.py -I <network_interface> -DHCPv6
```

