import argparse
import time
import threading
import sys
import logging
from tqdm import tqdm
from tabulate import tabulate
from scapy.all import sniff, sendp, IPv6, Ether, UDP, DHCP6_Solicit, DHCP6_Advertise, DHCP6_Reply, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6OptServerId, ICMPv6ND_NS, ICMPv6EchoRequest, conf
from colorama import Fore, Style, init


init(autoreset=True)


conf.verb = 0


logging.basicConfig(filename='enviro6.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')


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
    global dhcp_assigned_devices
    logging.debug("Handling DHCPv6 packet.")
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
        time.sleep(0.5)  # Reduced sleep time for faster response

        reply = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src) / \
                UDP(sport=547, dport=546) / \
                DHCP6_Reply(trid=packet[DHCP6_Solicit].trid) / \
                DHCP6OptServerId(duid=b"00:01:00:01:23:45:67:89:ab:cd:ef:01:23:45") / \
                DHCP6OptIA_NA(iaid=0, T1=0, T2=0, addr=ipv6_internal)

        sendp(reply, iface=packet.sniffed_on)

def handle_packet(packet):
    global device_info
    if IPv6 in packet:
        mac_address = packet[Ether].src
        ipv6_address = packet[IPv6].src

        logging.debug(f"Handling packet from MAC {mac_address}, IPv6: {ipv6_address}")

        if ipv6_address == "::":
            return

        if mac_address not in device_info:
            device_info[mac_address] = {
                "link_local": None,
                "global": None,
                "internal": None
            }

        if ipv6_address.startswith("fe80::"):
            device_info[mac_address]["link_local"] = ipv6_address
        elif ipv6_address.startswith("fc00::") or ipv6_address.startswith("fd00::"):
            device_info[mac_address]["internal"] = ipv6_address
        elif ipv6_address.startswith("2") or ipv6_address.startswith("3"):
            device_info[mac_address]["global"] = ipv6_address

def sniff_solicit(interface):
    logging.debug("Starting sniff_solicit.")
    sniff(prn=handle_packet, filter="ip6 and udp port 546", iface=interface)
    logging.debug("Finished sniff_solicit.")

def sniff_ndp(interface):
    logging.debug("Starting sniff_ndp.")
    sniff(prn=handle_packet, filter="icmp6 and (ip6[40] == 135 or ip6[40] == 136)", iface=interface)
    logging.debug("Finished sniff_ndp.")

def sniff_mdns(interface):
    logging.debug("Starting sniff_mdns.")
    sniff(prn=handle_packet, filter="udp port 5353", iface=interface)
    logging.debug("Finished sniff_mdns.")

def sniff_llmnr(interface):
    logging.debug("Starting sniff_llmnr.")
    sniff(prn=handle_packet, filter="udp port 5355", iface=interface)
    logging.debug("Finished sniff_llmnr.")

def sniff_ssdp(interface):
    logging.debug("Starting sniff_ssdp.")
    sniff(prn=handle_packet, filter="udp port 1900", iface=interface)
    logging.debug("Finished sniff_ssdp.")

def send_ndp_requests(interface):
    logging.debug("Starting send_ndp_requests.")
    for i in range(1, 65535):
        multicast_address = f"ff02::1:ff00:{i:04x}"
        ns_packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6ND_NS(tgt=multicast_address)
        sendp(ns_packet, iface=interface)
        time.sleep(0.005)  
    logging.debug("Finished send_ndp_requests.")

def print_device_table(dhcpv6_mode=False):
    headers = [Fore.CYAN + "No.", "MAC Address", "IPv6 Address" + Style.RESET_ALL]
    table = []

    if dhcpv6_mode:
        for i, (mac, ipv6_internal) in enumerate(dhcp_assigned_devices.items(), start=1):
            table.append([Fore.YELLOW + str(i), Fore.GREEN + mac, Fore.RED + ipv6_internal + Style.RESET_ALL])
    else:
        for i, (mac, info) in enumerate(device_info.items(), start=1):
            link_local = Fore.BLUE + (info["link_local"] or "") + Style.RESET_ALL
            global_ip = Fore.MAGENTA + (info["global"] or "") + Style.RESET_ALL
            internal_ip = Fore.RED + (info["internal"] or "") + Style.RESET_ALL
            table.append([Fore.YELLOW + str(i), Fore.GREEN + mac, link_local, global_ip, internal_ip])

        headers = [Fore.CYAN + "No.", "MAC Address", "Link-Local Address", "Global Address", "Internal Address" + Style.RESET_ALL]

    print("\n" + Fore.CYAN + "Device IPv6 Address Table" + Style.RESET_ALL)
    print(Fore.YELLOW + "------------------------------------------------" + Style.RESET_ALL)
    print(tabulate(table, headers, tablefmt="fancy_grid", stralign="center", numalign="center"))

def send_multicast_ndp_request(interface):
    logging.debug("Starting send_multicast_ndp_request.")
    multicast_address = "ff02::1"
    ns_packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6ND_NS(tgt=multicast_address)
    sendp(ns_packet, iface=interface)
    logging.debug("Finished send_multicast_ndp_request.")

def send_icmpv6_echo_request(interface):
    logging.debug("Starting send_icmpv6_echo_request.")
    for i in range(1, 65535):
        multicast_address = f"ff02::1:ff00:{i:04x}"
        echo_request = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6EchoRequest()
        sendp(echo_request, iface=interface)
        time.sleep(0.01)  # Reduced sleep time for faster response
    logging.debug("Finished send_icmpv6_echo_request.")

def main():
    global device_info
    parser = argparse.ArgumentParser(description="DHCPv6 Server and NDP Sniffer")
    parser.add_argument("-I", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-DHCPv6", action="store_true", help="Run as DHCPv6 server")
    args = parser.parse_args()

    print(banner)

    stop_event = threading.Event()

    sniff_solicit_thread = threading.Thread(target=sniff_solicit, args=(args.interface,))
    sniff_ndp_thread = threading.Thread(target=sniff_ndp, args=(args.interface,))
    proactive_ndp_thread = threading.Thread(target=send_ndp_requests, args=(args.interface,))
    icmpv6_ping_thread = threading.Thread(target=send_icmpv6_echo_request, args=(args.interface,))
    mdns_thread = threading.Thread(target=sniff_mdns, args=(args.interface,))
    llmnr_thread = threading.Thread(target=sniff_llmnr, args=(args.interface,))
    ssdp_thread = threading.Thread(target=sniff_ssdp, args=(args.interface,))

    threads = [
        sniff_solicit_thread, sniff_ndp_thread, proactive_ndp_thread,
        icmpv6_ping_thread, mdns_thread, llmnr_thread, ssdp_thread
    ]

    if args.DHCPv6:
        dhcp_thread = threading.Thread(target=sniff, args=(handle_dhcpv6,), kwargs={"filter": "udp and (port 546 or port 547)", "iface": args.interface})
        dhcp_thread.start()
        threads.append(dhcp_thread)

    for thread in threads:
        thread.start()

    start_time = time.time()

    estimated_time = 120  # Basic estimation logic
    with tqdm(total=100, desc=f"{Fore.CYAN}Scanning Progress", bar_format=f"{Fore.YELLOW}{{l_bar}}{Fore.GREEN}{{bar}}{Fore.CYAN}| 100% complete{Style.RESET_ALL}", ncols=100, leave=True) as pbar:
        while time.time() - start_time < estimated_time:
            time.sleep(estimated_time / 100)
            pbar.update(1)

    for thread in threads:
        thread.join(timeout=5)  
        if thread.is_alive():
            logging.warning(f"Thread {thread.name} did not finish in time.")

    print_device_table(dhcpv6_mode=args.DHCPv6)
    print("\n" + Fore.GREEN + "Script completed based on the estimated runtime." + Style.RESET_ALL)
    logging.debug("Script finished successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()
