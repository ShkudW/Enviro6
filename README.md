# Enviro6 - IPv6 Attack and Sniffing Tool

Enviro6 is a Python-based tool designed for performing various IPv6 network attacks and sniffing operations. The tool allows you to conduct RA Spoofing, NDP Spoofing, and RA Flood attacks, as well as sniff network traffic to gather information about connected devices. 

## Features

- **RA Spoofing**: Spoof Router Advertisements to hijack the default gateway of IPv6 devices.
- **NDP Spoofing**: Spoof Neighbor Discovery Protocol messages to associate an IP address with a fake MAC address.
- **RA Flood**: Flood the network with Router Advertisements to disrupt or take over the network.
- **Sniffing**: Capture and display Link-Local, ULA, and Global IPv6 addresses associated with MAC addresses in real-time.

## Requirements

Install the required Python packages by running:

```bash
pip install -r requirements.txt
```

## Usage
```
python3 Enviro6.py -I <interface> [options]

```
Options:
-I, --interface: The network interface to use (e.g., eth0).
--ra-spoof: Run an RA Spoofing attack.
--ndp-spoof: Run an NDP Spoofing attack. Requires --target-ipv6 and --fake-mac.
--ra-flood: Run an RA Flood attack.
--sniff: Sniff the network and display IPv6 addresses associated with MAC addresses in real-time.
--target-ipv6: The target IPv6 address for NDP Spoofing.
--fake-mac: The fake MAC address to use for NDP Spoofing.

## Example Commands

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

## Disclaimer
This tool is intended for educational purposes only and should only be used in environments where you have explicit permission to perform testing. Unauthorized use of this tool in a production network or without permission is illegal and unethical.

## PoC
RA-Spoof Attack:

Windows 10:
IPv4 - 192.168.74.2
IPv6 Link-Local-Address - fe80::f524:c89b:11bb:d7be

![image](https://github.com/user-attachments/assets/11771e50-72f9-429a-ad83-ee18512446d9)

Statring RA-Spoof attack:
![image](https://github.com/user-attachments/assets/2d6bcabd-e8f9-4ee2-8c9b-f19aa39548eb)


The Windows 10 after the attack:
![image](https://github.com/user-attachments/assets/16700b82-b8a1-4fb3-9e9e-8bcf40f595c5)
 * The Default-Gateway is the Kali now.

NDP-spoof Attack:

![image](https://github.com/user-attachments/assets/65e25f6d-9fcc-40dc-ae9a-35d5f98d0b2d)

* put the Link-Local-Address that you want to spoof, and the MAc-Address of yours machine
The Windows 10 after attack:
![image](https://github.com/user-attachments/assets/e1d24cee-c4e4-4cdf-a705-87d1ff5e53a6)

# Enjoy!

