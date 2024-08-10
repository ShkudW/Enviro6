import argparse
import time
import threading
import sys
import logging
from tqdm import tqdm
from tabulate import tabulate
from scapy.all import sniff, sendp, IPv6, Ether, UDP, DHCP6_Solicit, DHCP6_Advertise, DHCP6_Reply, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6OptServerId, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6EchoRequest, DNSQR, DNS, conf
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Disable Scapy's verbose output to prevent "Sent 1 packets." messages
conf.verb = 0

# Configure logging
logging.basicConfig(filename='enviro6.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Banner to display
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

# Table to store mappings between MAC addresses and IPv6 addresses
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
        time.sleep(1)

        reply = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src) / \
                UDP(sport=547, dport=546) / \
                DHCP6_Reply(trid=packet[DHCP6_Solicit].trid) / \
                DHCP6OptServerId(duid=b"00:01:00:01:23:45:67:89:ab:cd:ef:01:23:45") / \
                DHCP6OptIA_NA(iaid=0, T1=0, T2=0, addr=ipv6_internal)

        sendp(reply, iface=packet.sniffed_on)

def handle_packet(packet):
    global device_info
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
    elif ipv6_address.startswith("fd00::") or ipv6_address.startswith("fc00::"):
        device_info[mac_address]["internal"] = ipv6_address
    else:
        device_info[mac_address]["global"] = ipv6_address

def sniff_solicit(interface, stop_event):
    logging.debug("Starting sniff_solicit.")
    sniff(prn=handle_packet, filter="ip6 and udp port 546", iface=interface, stop_filter=lambda x: stop_event.is_set())
    logging.debug("Finished sniff_solicit.")

def sniff_ndp(interface, stop_event):
    logging.debug("Starting sniff_ndp.")
    sniff(prn=handle_packet, filter="icmp6 and (ip6[40] == 135 or ip6[40] == 136)", iface=interface, stop_filter=lambda x: stop_event.is_set())
    logging.debug("Finished sniff_ndp.")

def send_ndp_requests(interface, stop_event):
    logging.debug("Starting send_ndp_requests.")
    for i in range(1, 255):
        if stop_event.is_set():
            break
        multicast_address = f"ff02::1:ff00:{i:02x}"
        ns_packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6ND_NS(tgt=multicast_address)
        sendp(ns_packet, iface=interface)
        time.sleep(0.05)
    logging.debug("Finished send_ndp_requests.")

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

def send_multicast_ndp_request(interface, retries=3, stop_event=None):
    logging.debug("Starting send_multicast_ndp_request.")
    multicast_address = "ff02::1"
    ns_packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6ND_NS(tgt=multicast_address)
    for _ in range(retries):
        if stop_event and stop_event.is_set():
            break
        sendp(ns_packet, iface=interface)
        time.sleep(0.2)
    logging.debug("Finished send_multicast_ndp_request.")

def send_icmpv6_echo_request(interface, retries=3, stop_event=None):
    logging.debug("Starting send_icmpv6_echo_request.")
    for i in range(1, 255):
        if stop_event and stop_event.is_set():
            break
        multicast_address = f"ff02::1:ff00:{i:02x}"
        echo_request = Ether(dst="33:33:00:00:00:01") / IPv6(dst=multicast_address) / ICMPv6EchoRequest()
        for _ in range(retries):
            if stop_event and stop_event.is_set():
                break
            sendp(echo_request, iface=interface)
            time.sleep(0.2)
    logging.debug("Finished send_icmpv6_echo_request.")

def sniff_mdns(interface, stop_event):
    logging.debug("Starting sniff_mdns.")
    def handle_mdns_packet(packet):
        if packet.haslayer(DNSQR) and packet[DNS].qd.qname.decode().endswith(".local."):
            mac_address = packet[Ether].src
            ipv6_address = packet[IPv6].src if IPv6 in packet else "N/A"
            logging.info(f"[mDNS] Detected: MAC {mac_address} -> IPv6 {ipv6_address} -> Name: {packet[DNS].qd.qname.decode()}")
            if mac_address not in device_info:
                device_info[mac_address] = {"link_local": None, "global": None, "internal": None}
            if ipv6_address != "N/A":
                device_info[mac_address]["link_local"] = ipv6_address

    sniff(prn=handle_mdns_packet, filter="udp port 5353", iface=interface, store=0, stop_filter=lambda x: stop_event.is_set())
    logging.debug("Finished sniff_mdns.")

def sniff_llmnr(interface, stop_event):
    logging.debug("Starting sniff_llmnr.")
    def handle_llmnr_packet(packet):
        if packet.haslayer(DNSQR):
            mac_address = packet[Ether].src
            ipv6_address = packet[IPv6].src if IPv6 in packet else "N/A"
            logging.info(f"[LLMNR] Detected: MAC {mac_address} -> IPv6 {ipv6_address} -> Name: {packet[DNS].qd.qname.decode()}")
            if mac_address not in device_info:
                device_info[mac_address] = {"link_local": None, "global": None, "internal": None}
            if ipv6_address != "N/A":
                device_info[mac_address]["link_local"] = ipv6_address

    sniff(prn=handle_llmnr_packet, filter="udp port 5355", iface=interface, store=0, stop_filter=lambda x: stop_event.is_set())
    logging.debug("Finished sniff_llmnr.")

def sniff_ssdp(interface, stop_event):
    logging.debug("Starting sniff_ssdp.")
    def handle_ssdp_packet(packet):
        if packet.haslayer(UDP) and packet[UDP].sport == 1900:
            mac_address = packet[Ether].src
            ipv6_address = packet[IPv6].src if IPv6 in packet else "N/A"
            logging.info(f"[SSDP] Detected: MAC {mac_address} -> IPv6 {ipv6_address} -> SSDP Service")
            if mac_address not in device_info:
                device_info[mac_address] = {"link_local": None, "global": None, "internal": None}
            if ipv6_address != "N/A":
                device_info[mac_address]["link_local"] = ipv6_address

    sniff(prn=handle_ssdp_packet, filter="udp port 1900", iface=interface, store=0, stop_filter=lambda x: stop_event.is_set())
    logging.debug("Finished sniff_ssdp.")

def main():
    global device_info
    parser = argparse.ArgumentParser(description="DHCPv6 Server and NDP Sniffer")
    parser.add_argument("-I", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-DHCPv6", action="store_true", help="Run as DHCPv6 server")
    parser.add_argument("-timeout", type=int, default=120, help="Time in seconds to run the script (default is 120 seconds)")
    parser.add_argument("-retries", type=int, default=3, help="Number of retries for sending requests (default is 3)")
    args = parser.parse_args()

    print(banner)

    stop_event = threading.Event()

    sniff_solicit_thread = threading.Thread(target=sniff_solicit, args=(args.interface, stop_event))
    sniff_ndp_thread = threading.Thread(target=sniff_ndp, args=(args.interface, stop_event))
    proactive_ndp_thread = threading.Thread(target=send_ndp_requests, args=(args.interface, stop_event))
    icmpv6_ping_thread = threading.Thread(target=send_icmpv6_echo_request, args=(args.interface, args.retries, stop_event))
    mdns_thread = threading.Thread(target=sniff_mdns, args=(args.interface, stop_event))
    llmnr_thread = threading.Thread(target=sniff_llmnr, args=(args.interface, stop_event))
    ssdp_thread = threading.Thread(target=sniff_ssdp, args=(args.interface, stop_event))

    threads = [
        sniff_solicit_thread, sniff_ndp_thread, proactive_ndp_thread,
        icmpv6_ping_thread, mdns_thread, llmnr_thread, ssdp_thread
    ]

    if args.DHCPv6:
        dhcp_thread = threading.Thread(target=sniff, args=(handle_dhcpv6,), kwargs={"filter": "udp and (port 546 or port 547)", "iface": args.interface, "timeout": args.timeout})
        dhcp_thread.start()
        threads.append(dhcp_thread)

    for thread in threads:
        thread.start()

    start_time = time.time()
    
    with tqdm(total=100, desc=f"{Fore.CYAN}Scanning Progress", bar_format=f"{Fore.YELLOW}{{l_bar}}{Fore.GREEN}{{bar}}{Fore.CYAN}| {{n_fmt}}% complete{Style.RESET_ALL}", ncols=100, leave=True) as pbar:
        while time.time() - start_time < args.timeout:
            time.sleep(args.timeout / 100)
            pbar.update(1)

    logging.debug("Waiting for threads to finish...")
    
    stop_event.set()  # Signal all threads to stop

    for thread in threads:
        thread.join(timeout=5)  # Join threads with a short timeout to avoid deadlocks
        if thread.is_alive():
            logging.warning(f"Thread {thread.name} did not finish in time.")

    print_device_table(dhcpv6_mode=args.DHCPv6)
    print("\n" + Fore.GREEN + "Script completed based on the timeout value." + Style.RESET_ALL)
    logging.debug("Script finished successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()