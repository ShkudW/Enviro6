# Enviro6

Enviro6 is a penetration testing tool for network environments. It allows you to check host names, discover DHCP servers, perform DHCP starvation attacks, and assign IPv6 addresses to hosts.

## Features

- **Host Checker**: Check all host names in the environment.
- **DHCP Server Discovery**: Check for DHCP servers in the environment.
- **DHCP Starvation Attack**: Perform a DHCP starvation attack.
- **IPv6 Address Assignment**: Assign IPv6 addresses to hosts and display them.

## Usage

### Basic Usage

```bash
python Enviro6.py -ip_range <IP_RANGE> -iface <INTERFACE> <OPTIONS>
