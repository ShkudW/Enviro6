import argparse
import time
import threading
import sys
from tqdm import tqdm
from tabulate import tabulate
from scapy.all import sniff, sendp, IPv6, Ether, UDP, DHCP6_Solicit, DHCP6_Advertise, DHCP6_Reply, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6OptServerId, ICMPv6ND_NS, ICMPv6ND_NA, conf
from colorama import Fore, Style, init


init(autoreset=True)


conf.verb = 0


banner = f"""
{Fore.CYAN}  ______            _             __  
 |  ____|          (_)           / /  
 | |__   _ ____   ___ _ __ ___  / /_  
 |  __| | '_ \ \ / / | '__/ _ \| '_ \ 
 | |____| | | \ V /| | | | (_) | (_) |
 |______|_| |_|\_/ |_|_|  \___/ \___/ 
{Fore.GREEN}By @ShkudW
{Fore.YELLOW}https://github.com/ShkudW
{Style.RESET_ALL}
"""


device_info = {}
dhcp_assigned_devices = {}  # Table to store devices that received an internal IPv6 address


def handle_dhcpv6(packet):
    global dhcp_assigned_devices  # Ensure access to global variable
    if DHCP6_Solicit in packet:
        mac_address = packet[Ether].src
        client_id = packet[DHCP6OptClientId].duid

        
        ipv6_internal = f"fd00::{len(dhcp_assigned_devices) + 1}"
        dhcp_assigned_devices[mac_address] = ipv6_internal

        
        advertise = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                    IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src) / \
                    UDP(sport=547, dport=546) / \
                    DHCP6_Advertise(trid=packet[DHCP6_Solicit].trid) / \
                    DHCP6OptServerId(duid=b"00:01:00:01:23:45:67:89:ab:cd:ef:01:23:45") / \
                    DHCP6OptClientId(duid=client_id) / \
                    DHCP6OptIA_NA(iaid=0, T1=0, T2=0, addr=ipv6_internal)

        sendp(advertise, iface=packet.sniffed_on)

        time.sleep(1)

        
        reply = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src) / \
                UDP(sport=547, dport=546) / \
                DHCP6_Reply(trid=packet[DHCP6_Solicit].trid) / \
                DHCP6OptServerId(duid=b"00:01:00:01:23:45:67:89:ab:cd:ef:01:23:45") / \
                DHCP6OptClientId(duid=client_id) / \
                DHCP6OptIA_NA(iaid=0, T1=0, T2=0, addr=ipv6_internal)

        sendp(reply, iface=packet.sniffed_on)

# Function to handle Solicit and NDP packets
def handle_packet(packet):
    global device_info  # Ensure access to global variable
    mac_address = packet[Ether].src
    ipv6_address = packet[IPv6].src

    if ipv6_address == "::":
        return  # Skip invalid addresses

    if mac_address not in device_info:
        device_info[mac_address] = {
            "link_local": None,
            "global": None,
            "internal": None
        }

    if ipv6_address.startswith("fe80::"):  # Link-Local
        device_info[mac_address]["link_local"] = ipv6_address
    elif ipv6_address.startswith("fd00::") or ipv6_address.startswith("fc00::"):  # פנימית (ULA)
        device_info[mac_address]["internal"] = ipv6_address
    else:  # גלובלית
        device_info[mac_address]["global"] = ipv6_address


def print_device_table(dhcpv6_mode=False):
    headers = [Fore.CYAN + "No.", "MAC Address", "IPv6 Address" + Style.RESET_ALL]
    table = []

    if dhcpv6_mode:
        for i, (mac, ipv6_internal) in enumerate(dhcp_assigned_devices.items(), start=1):
            table.append([Fore.YELLOW + str(i), Fore.GREEN + mac, Fore.RED + ipv6_internal + Style.RESET_ALL])
    else:
        for i, (mac, info) in enumerate(device_info.items(), start=1):
            link_local = Fore.BLUE + info["link_local"] if info["link_local"] else ""
            global_ip = Fore.MAGENTA + info["global"] if info["global"] else ""
            internal_ip = Fore.RED + info["internal"] if info["internal"] else ""
            table.append([Fore.YELLOW + str(i), Fore.GREEN + mac, link_local, global_ip, internal_ip + Style.RESET_ALL])

        headers = [Fore.CYAN + "No.", "MAC Address", "Link-Local Address", "Global Address", "Internal Address" + Style.RESET_ALL]

    print("\n" + Fore.CYAN + "Device IPv6 Address Table" + Style.RESET_ALL)
    print(Fore.YELLOW + "------------------------------------------------" + Style.RESET_ALL)
    print(tabulate(table, headers, tablefmt="fancy_grid", stralign="center", numalign="center"))

# Function to send Multicast NDP requests to all devices on the network
def send_multicast_ndp_request(interface):
    multicast_address = "ff02::1"  # Multicast address for all devices
    ns_packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6ND_NS(tgt=multicast_address)
    sendp(ns_packet, iface=interface)

# Function to sniff for Solicit packets with timeout
def sniff_solicit(interface, timeout):
    sniff(prn=handle_packet, filter="ip6 and udp port 546", iface=interface, timeout=timeout)

# Function to sniff for NDP packets with timeout
def sniff_ndp(interface, timeout):
    sniff(prn=handle_packet, filter="icmp6 and (ip6[40] == 135 or ip6[40] == 136)", iface=interface, timeout=timeout)

# Function to send proactive NDP requests
def send_ndp_requests(interface):
    for i in range(1, 255):
        multicast_address = f"ff02::1:ff00:{i:02x}"  # NDP multicast address
        ns_packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6ND_NS(tgt=multicast_address)
        sendp(ns_packet, iface=interface)
        time.sleep(0.1)  # Delay between requests to avoid flooding the network


def main():
    global device_info  # Ensure access to global variable
    parser = argparse.ArgumentParser(description="DHCPv6 Server and NDP Sniffer")
    parser.add_argument("-I", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-DHCPv6", action="store_true", help="Run as DHCPv6 server")
    parser.add_argument("-timeout", type=int, default=60, help="Time in seconds to run the script (default is 60 seconds)")
    args = parser.parse_args()

    print(banner)  # Display banner only after argument parsing is successful

    if args.DHCPv6:
        dhcp_thread = threading.Thread(target=sniff, args=(handle_dhcpv6,), kwargs={"filter": "udp and (port 546 or port 547)", "iface": args.interface, "timeout": args.timeout})
        dhcp_thread.start()

    sniff_solicit_thread = threading.Thread(target=sniff_solicit, args=(args.interface, args.timeout))
    sniff_ndp_thread = threading.Thread(target=sniff_ndp, args=(args.interface, args.timeout))
    proactive_ndp_thread = threading.Thread(target=send_ndp_requests, args=(args.interface,))

    sniff_solicit_thread.start()
    sniff_ndp_thread.start()
    proactive_ndp_thread.start()

    start_time = time.time()
    
    with tqdm(total=args.timeout, desc=f"{Fore.CYAN}Scanning Progress", bar_format=f"{Fore.YELLOW}{{l_bar}}{Fore.GREEN}{{bar}}{Fore.CYAN}| {{n_fmt}}/{{total_fmt}} devices detected{Style.RESET_ALL}", ncols=100, leave=True) as pbar:
        while time.time() - start_time < args.timeout:
            send_multicast_ndp_request(args.interface)
            time.sleep(1)  # Update progress every second for a more dynamic feel
            pbar.set_postfix({"Devices found": len(device_info)})
            pbar.update(1)

    
    sniff_solicit_thread.join()
    sniff_ndp_thread.join()
    proactive_ndp_thread.join()
    if args.DHCPv6:
        dhcp_thread.join()

    
    print_device_table(dhcpv6_mode=args.DHCPv6)
    print("\n" + Fore.GREEN + "Script completed based on the timeout value." + Style.RESET_ALL)
    sys.exit(0)  # Ensure the script exits cleanly

if __name__ == "__main__":
    main()
